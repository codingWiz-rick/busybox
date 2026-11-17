/* vi: set sw=4 ts=4: */
/*
 * sepolicy - SELinux policy inspection and live rule injection tool
 *
 * Copyright (C) 2026 Antigravity (Google DeepMind)
 * Based on Android SELinux policy injection architecture by Joshua Brindle / topjohnwu
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config SEPOLICY
//config:	bool "sepolicy (Android SELinux policy injector & inspector)"
//config:	default y
//config:	help
//config:	  sepolicy allows inspecting, modifying, and live-injecting SELinux
//config:	  policy rules (allow, auditallow, dontaudit, permissive, enforce)
//config:	  directly into the running Linux kernel or on-disk policy files.

//applet:IF_SEPOLICY(APPLET(sepolicy, BB_DIR_USR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SEPOLICY) += sepolicy.o

//usage:#define sepolicy_trivial_usage
//usage:	"[-l] [-s FILE] [-t FILE] [-d] [COMMAND [ARGS...]]"
//usage:#define sepolicy_full_usage "\n\n"
//usage:       "SELinux policy inspection and live rule injection tool\n"
//usage:     "\nOptions:"
//usage:     "\n	-l, --live	Live kernel injection (read /sys/fs/selinux/policy, write /sys/fs/selinux/load)"
//usage:     "\n	-s FILE		Source policy file (default: /sys/fs/selinux/policy)"
//usage:     "\n	-t FILE		Target policy output file (default: /sys/fs/selinux/load with -l)"
//usage:     "\n	-d, --dump	Dump policy statistics (version, types, classes, permissive domains)"
//usage:     "\n"
//usage:     "\nCommands:"
//usage:     "\n	allow <source> <target> <class> <perms...>"
//usage:     "\n	auditallow <source> <target> <class> <perms...>"
//usage:     "\n	dontaudit <source> <target> <class> <perms...>"
//usage:     "\n	permissive <type...>"
//usage:     "\n	enforce <type...>"
//usage:     "\n	typeattribute <type> <attribute>"

#include "libbb.h"
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/hashtab.h>

#define KERNEL_POLICY_PATH "/sys/fs/selinux/policy"
#define KERNEL_LOAD_PATH   "/sys/fs/selinux/load"

/* Helper: Load binary policy into policydb_t */
static int load_policydb(const char *filename, policydb_t *db)
{
	policy_file_t pf;
	FILE *fp;
	int ret;

	fp = fopen(filename, "re");
	if (!fp)
		return -1;

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = fp;

	if (policydb_init(db) < 0) {
		fclose(fp);
		return -1;
	}

	ret = policydb_read(db, &pf, 0);
	fclose(fp);

	return ret;
}

/* Helper: Save binary policy from policydb_t to file or kernel */
static int save_policydb(const char *filename, policydb_t *db)
{
	policy_file_t pf;
	char *buf;
	size_t len;
	int fd;
	ssize_t written;

	/* 1. Calculate required length in memory */
	policy_file_init(&pf);
	pf.type = PF_LEN;
	if (policydb_write(db, &pf) < 0 || pf.len == 0)
		return -1;

	len = pf.len;
	buf = xmalloc(len);

	/* 2. Serialize full policy into contiguous RAM buffer */
	policy_file_init(&pf);
	pf.type = PF_USE_MEMORY;
	pf.data = buf;
	pf.len = len;
	pf.size = len;

	if (policydb_write(db, &pf) < 0) {
		free(buf);
		return -1;
	}

	/* 3. Atomic single-buffer write (strictly required by kernel /sys/fs/selinux/load) */
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		free(buf);
		return -1;
	}

	written = write(fd, buf, len);
	close(fd);
	free(buf);

	return (written == (ssize_t)len) ? 0 : -1;
}

/* Add an Access Vector rule (allow, auditallow, dontaudit) */
static int inject_av_rule(policydb_t *db, uint16_t effect,
			  const char *src_name, const char *tgt_name,
			  const char *cls_name, char **perms, int perm_count)
{
	type_datum_t *src, *tgt;
	class_datum_t *cls;
	avtab_key_t key;
	avtab_ptr_t node;
	uint32_t perm_mask = 0;
	int i;

	src = (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)src_name);
	if (!src) {
		bb_error_msg("source type '%s' does not exist", src_name);
		return -1;
	}

	tgt = (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)tgt_name);
	if (!tgt) {
		bb_error_msg("target type '%s' does not exist", tgt_name);
		return -1;
	}

	cls = (class_datum_t *)hashtab_search(db->p_classes.table, (hashtab_key_t)cls_name);
	if (!cls) {
		bb_error_msg("class '%s' does not exist", cls_name);
		return -1;
	}

	for (i = 0; i < perm_count; i++) {
		char *pstr = perms[i];
		char *tok;

		/* Support comma-separated permissions (e.g. read,write) */
		while ((tok = strsep(&pstr, ",")) != NULL) {
			perm_datum_t *perm;

			if (*tok == '\0')
				continue;

			if (strcmp(tok, "*") == 0) {
				perm_mask = ~0U;
				break;
			}

			perm = (perm_datum_t *)hashtab_search(cls->permissions.table, (hashtab_key_t)tok);
			if (!perm && cls->comdatum)
				perm = (perm_datum_t *)hashtab_search(cls->comdatum->permissions.table, (hashtab_key_t)tok);

			if (!perm) {
				bb_error_msg("permission '%s' does not exist in class '%s'", tok, cls_name);
				return -1;
			}

			perm_mask |= (1U << (perm->s.value - 1));
		}
	}

	if (perm_mask == 0) {
		bb_error_msg("no valid permissions specified for class '%s'", cls_name);
		return -1;
	}

	memset(&key, 0, sizeof(key));
	key.source_type = src->s.value;
	key.target_type = tgt->s.value;
	key.target_class = cls->s.value;
	key.specified = effect;

	node = avtab_search_node(&db->te_avtab, &key);
	if (node) {
		if (effect == AVTAB_AUDITDENY)
			node->datum.data &= ~perm_mask;
		else
			node->datum.data |= perm_mask;
	} else {
		avtab_datum_t datum;
		memset(&datum, 0, sizeof(datum));
		datum.data = (effect == AVTAB_AUDITDENY) ? ~perm_mask : perm_mask;
		datum.xperms = NULL;
		if (!avtab_insert_nonunique(&db->te_avtab, &key, &datum)) {
			bb_error_msg("failed to insert avtab rule");
			return -1;
		}
	}

	return 0;
}

/* Set domain permissive or enforcing state */
static int set_domain_state(policydb_t *db, const char *type_name, int permissive)
{
	type_datum_t *type;

	type = (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)type_name);
	if (!type) {
		bb_error_msg("type '%s' does not exist", type_name);
		return -1;
	}

	if (ebitmap_set_bit(&db->permissive_map, type->s.value, permissive) < 0) {
		bb_error_msg("failed to set permissive map bit for '%s'", type_name);
		return -1;
	}

	return 0;
}

/* Assign type to attribute */
static int inject_typeattribute(policydb_t *db, const char *type_name, const char *attr_name)
{
	type_datum_t *type, *attr;

	type = (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)type_name);
	if (!type) {
		bb_error_msg("type '%s' does not exist", type_name);
		return -1;
	}

	attr = (type_datum_t *)hashtab_search(db->p_types.table, (hashtab_key_t)attr_name);
	if (!attr) {
		bb_error_msg("attribute '%s' does not exist", attr_name);
		return -1;
	}

	if (ebitmap_set_bit(&db->type_attr_map[type->s.value - 1], attr->s.value - 1, 1) < 0 ||
	    ebitmap_set_bit(&db->attr_type_map[attr->s.value - 1], type->s.value - 1, 1) < 0) {
		bb_error_msg("failed to map type '%s' to attribute '%s'", type_name, attr_name);
		return -1;
	}

	return 0;
}

/* Parse and execute a single rule tokens array */
static int execute_rule_tokens(policydb_t *db, char **argv, int argc)
{
	const char *verb;

	if (argc <= 0)
		return 0;

	verb = argv[0];

	if (strcmp(verb, "allow") == 0) {
		if (argc < 5) {
			bb_error_msg("allow requires <src> <tgt> <class> <perms...>");
			return -1;
		}
		return inject_av_rule(db, AVTAB_ALLOWED, argv[1], argv[2], argv[3], &argv[4], argc - 4);
	}

	if (strcmp(verb, "auditallow") == 0) {
		if (argc < 5) {
			bb_error_msg("auditallow requires <src> <tgt> <class> <perms...>");
			return -1;
		}
		return inject_av_rule(db, AVTAB_AUDITALLOW, argv[1], argv[2], argv[3], &argv[4], argc - 4);
	}

	if (strcmp(verb, "dontaudit") == 0) {
		if (argc < 5) {
			bb_error_msg("dontaudit requires <src> <tgt> <class> <perms...>");
			return -1;
		}
		return inject_av_rule(db, AVTAB_AUDITDENY, argv[1], argv[2], argv[3], &argv[4], argc - 4);
	}

	if (strcmp(verb, "permissive") == 0) {
		int i, err = 0;
		if (argc < 2) {
			bb_error_msg("permissive requires at least one <type>");
			return -1;
		}
		for (i = 1; i < argc; i++) {
			if (set_domain_state(db, argv[i], 1) < 0)
				err = -1;
		}
		return err;
	}

	if (strcmp(verb, "enforce") == 0) {
		int i, err = 0;
		if (argc < 2) {
			bb_error_msg("enforce requires at least one <type>");
			return -1;
		}
		for (i = 1; i < argc; i++) {
			if (set_domain_state(db, argv[i], 0) < 0)
				err = -1;
		}
		return err;
	}

	if (strcmp(verb, "typeattribute") == 0) {
		if (argc != 3) {
			bb_error_msg("typeattribute requires <type> <attribute>");
			return -1;
		}
		return inject_typeattribute(db, argv[1], argv[2]);
	}

	bb_error_msg("unknown sepolicy rule verb: '%s'", verb);
	return -1;
}

/* Parse a string line into space-separated tokens */
static int execute_rule_line(policydb_t *db, char *line)
{
	char *tokens[32];
	int count = 0;
	char *p = line;
	char *tok;

	/* Trim leading whitespace */
	while (*p == ' ' || *p == '\t')
		p++;

	if (*p == '#' || *p == '\0' || *p == '\n')
		return 0;

	while ((tok = strsep(&p, " \t\r\n")) != NULL) {
		if (*tok == '\0')
			continue;
		if (count < 32)
			tokens[count++] = tok;
	}

	return execute_rule_tokens(db, tokens, count);
}

/* Dump statistics and permissive domains */
static int dump_policy_info(policydb_t *db)
{
	unsigned int i;
	int permissive_count = 0;

	printf("====================================================================\n");
	printf("SELinux Policy Information\n");
	printf("--------------------------------------------------------------------\n");
	printf("Policy Version:       %u\n", db->policyvers);
	printf("Target Platform:      %s\n", db->target_platform == SEPOL_TARGET_SELINUX ? "SELinux" : "Xen");
	printf("MLS Enabled:          %s\n", (db->mls) ? "yes" : "no");
	printf("Total Types:          %u\n", db->p_types.nprim);
	printf("Total Classes:        %u\n", db->p_classes.nprim);
	printf("Total Roles:          %u\n", db->p_roles.nprim);
	printf("Total Users:          %u\n", db->p_users.nprim);
	printf("Total AV Rules:       %u\n", db->te_avtab.nel);
	printf("--------------------------------------------------------------------\n");
	printf("Permissive Domains:\n");

	for (i = 0; i < db->p_types.nprim; i++) {
		if (ebitmap_get_bit(&db->permissive_map, i + 1)) {
			printf("  [Permissive] %s\n", db->p_type_val_to_name[i]);
			permissive_count++;
		}
	}

	if (permissive_count == 0)
		printf("  (none - all domains enforcing)\n");
	else
		printf("Total Permissive:     %d\n", permissive_count);

	printf("====================================================================\n");
	return 0;
}

int sepolicy_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int sepolicy_main(int argc, char **argv)
{
	const char *source_path = KERNEL_POLICY_PATH;
	const char *target_path = NULL;
	int opt_live = 0;
	int opt_dump = 0;
	policydb_t db;
	int modified = 0;
	int ret = EXIT_SUCCESS;

	/* Parse flags manually to support rule commands seamlessly */
	while (argc > 1 && argv[1][0] == '-') {
		if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--live") == 0) {
			opt_live = 1;
			argv++;
			argc--;
		} else if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--dump") == 0) {
			opt_dump = 1;
			argv++;
			argc--;
		} else if ((strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--source") == 0) && argc > 2) {
			source_path = argv[2];
			argv += 2;
			argc -= 2;
		} else if ((strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--target") == 0) && argc > 2) {
			target_path = argv[2];
			argv += 2;
			argc -= 2;
		} else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
			bb_show_usage();
		} else {
			break;
		}
	}

	/* Fall back search for source policy if default not found */
	if (access(source_path, R_OK) != 0) {
		if (access("/sepolicy", R_OK) == 0)
			source_path = "/sepolicy";
		else if (access("/sys/fs/selinux/policy", R_OK) == 0)
			source_path = "/sys/fs/selinux/policy";
	}

	if (load_policydb(source_path, &db) < 0)
		bb_error_msg_and_die("failed to load policy from '%s'", source_path);

	if (opt_dump) {
		dump_policy_info(&db);
		policydb_destroy(&db);
		return EXIT_SUCCESS;
	}

	/* Set target path */
	if (!target_path) {
		if (opt_live)
			target_path = KERNEL_LOAD_PATH;
		else
			target_path = source_path;
	}

	/* Parse rules from command line */
	if (argc > 1) {
		/* If single quoted argument containing spaces or semicolons, split it */
		if (argc == 2 && (strchr(argv[1], ' ') || strchr(argv[1], ';'))) {
			char *copy = xstrdup(argv[1]);
			char *line;
			char *p = copy;
			while ((line = strsep(&p, ";\n")) != NULL) {
				if (execute_rule_line(&db, line) == 0)
					modified++;
				else
					ret = EXIT_FAILURE;
			}
			free(copy);
		} else {
			if (execute_rule_tokens(&db, &argv[1], argc - 1) == 0)
				modified++;
			else
				ret = EXIT_FAILURE;
		}
	} else if (!isatty(STDIN_FILENO)) {
		/* Read rule statements from stdin */
		char *line;
		while ((line = xmalloc_fgetline(stdin)) != NULL) {
			if (execute_rule_line(&db, line) == 0)
				modified++;
			else
				ret = EXIT_FAILURE;
			free(line);
		}
	} else {
		bb_show_usage();
	}

	/* If rules were modified, write out to target */
	if (modified > 0 && ret == EXIT_SUCCESS) {
		if (save_policydb(target_path, &db) < 0)
			bb_error_msg_and_die("failed to save policy to '%s'", target_path);

		if (opt_live)
			printf("[+] Successfully injected %d rule(s) live into kernel (%s)\n", modified, target_path);
		else
			printf("[+] Successfully saved %d rule(s) to %s\n", modified, target_path);
	}

	policydb_destroy(&db);
	return ret;
}
