/* vi: set sw=4 ts=4: */
/*
 * Native libc-independent getprop applet for Android
 *
 * Traverses Android's /dev/__properties__/ memory-mapped trie structures directly.
 * Compatible with Android 8.0 through 16, with property_info fallback for
 * non-root permission restrictions (mode 711).
 *
 * Licensed under GPLv2 or later.
 */

//config:config GETPROP
//config:	bool "getprop (Android system property reader)"
//config:	default y
//config:	help
//config:	  Reads Android system properties from /dev/__properties__/.

//applet:IF_GETPROP(APPLET(getprop, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_GETPROP) += getprop.o

//usage:#define getprop_trivial_usage
//usage:       "[-Z] [NAME [DEFAULT]]"
//usage:#define getprop_full_usage "\n\n"
//usage:       "Get an Android system property, or list all properties.\n"
//usage:     "\n	-Z	Show property SELinux security contexts instead of values"

#include "libbb.h"
#include "bb_android.h"
#include <sys/mman.h>
#include <dirent.h>

/* Internal property entry for sorting / storage */
struct prop_entry {
	char *name;
	char *value;
	char *context;
};

struct prop_collector {
	const char *target_key;
	char *found_value;
	struct prop_entry *entries;
	size_t count;
	size_t capacity;
	const char *current_context;
	bool show_context;
};

static void read_property_value(const char *area_base, size_t area_size,
                                const struct prop_info *pi, char *val_buf, size_t val_buf_sz)
{
	uint32_t serial;
	size_t len;
	int tries = 10;

	val_buf[0] = '\0';
	do {
		serial = *(const volatile uint32_t *)&pi->serial;
	} while ((serial & 1) && --tries > 0);

	if (serial & PROP_FLAG_LONG) {
		/* Long property: offset is relative to pi */
		const char *long_val = (const char *)pi + pi->long_property.offset;
		if (long_val >= area_base && long_val < area_base + area_size) {
			size_t max_avail = (area_base + area_size) - long_val;
			size_t copy_len = strnlen(long_val, max_avail);
			if (copy_len >= val_buf_sz)
				copy_len = val_buf_sz - 1;
			memcpy(val_buf, long_val, copy_len);
			val_buf[copy_len] = '\0';
			return;
		}
	}

	/* Short inline property */
	len = (serial >> 24) & 0xff;
	if (len > 0) {
		if (len >= val_buf_sz)
			len = val_buf_sz - 1;
		if (len > sizeof(pi->value))
			len = sizeof(pi->value);
		memcpy(val_buf, pi->value, len);
		val_buf[len] = '\0';
	} else {
		/* Fallback for legacy Android where length wasn't in serial */
		size_t copy_len = strnlen(pi->value, sizeof(pi->value));
		if (copy_len >= val_buf_sz)
			copy_len = val_buf_sz - 1;
		memcpy(val_buf, pi->value, copy_len);
		val_buf[copy_len] = '\0';
	}
}

static void walk_trie_node(const char *data_base, size_t data_size,
                           const char *area_base, size_t area_size,
                           uint32_t node_off, const char *prefix,
                           struct prop_collector *col)
{
	const struct prop_trie_node *node;
	char cur_path[512];

	if (node_off + sizeof(struct prop_trie_node) > data_size)
		return;

	node = (const struct prop_trie_node *)(data_base + node_off);

	/* 1. Traverse left sibling BST */
	if (node->left && node->left + sizeof(struct prop_trie_node) <= data_size)
		walk_trie_node(data_base, data_size, area_base, area_size, node->left, prefix, col);

	/* Construct current path */
	if (node->namelen > 0 && node_off + sizeof(struct prop_trie_node) + node->namelen <= data_size) {
		if (prefix && prefix[0] != '\0') {
			snprintf(cur_path, sizeof(cur_path), "%s.%-.*s", prefix, (int)node->namelen, node->name);
		} else {
			snprintf(cur_path, sizeof(cur_path), "%-.*s", (int)node->namelen, node->name);
		}
	} else {
		cur_path[0] = '\0';
	}

	/* 2. Check if this node terminates a property */
	if (node->prop && node->prop + sizeof(struct prop_info) <= data_size) {
		const struct prop_info *pi = (const struct prop_info *)(data_base + node->prop);
		/* pi->name holds canonical full property name */
		const char *pname = (pi->name[0] != '\0') ? pi->name : cur_path;
		char val[1024];

		read_property_value(area_base, area_size, pi, val, sizeof(val));

		if (pname && pname[0] != '\0') {
			if (col->target_key) {
				if (strcmp(pname, col->target_key) == 0) {
					if (!col->found_value)
						col->found_value = xstrdup(val);
					return;
				}
			} else {
				/* Collect for listing */
				if (col->count >= col->capacity) {
					col->capacity = (col->capacity == 0) ? 256 : col->capacity * 2;
					col->entries = xrealloc(col->entries, col->capacity * sizeof(col->entries[0]));
				}
				col->entries[col->count].name = xstrdup(pname);
				col->entries[col->count].value = xstrdup(val);
				col->entries[col->count].context = col->current_context ? xstrdup(col->current_context) : NULL;
				col->count++;
			}
		}
	}

	if (col->target_key && col->found_value)
		return;

	/* 3. Traverse children sub-trie */
	if (node->children && node->children + sizeof(struct prop_trie_node) <= data_size)
		walk_trie_node(data_base, data_size, area_base, area_size, node->children, cur_path, col);

	if (col->target_key && col->found_value)
		return;

	/* 4. Traverse right sibling BST */
	if (node->right && node->right + sizeof(struct prop_trie_node) <= data_size)
		walk_trie_node(data_base, data_size, area_base, area_size, node->right, prefix, col);
}

static void parse_prop_file(const char *filepath, const char *context_name, struct prop_collector *col)
{
	int fd;
	struct stat st;
	char *map;

	fd = open(filepath, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	if (fstat(fd, &st) < 0 || st.st_size < PROP_AREA_HEADER_SIZE + (off_t)sizeof(struct prop_trie_node)) {
		close(fd);
		return;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (map == MAP_FAILED)
		return;

	col->current_context = context_name;

	/*
	 * Android prop_area layout:
	 * - Bytes 0..127: prop_area header (bytes_used, serial, magic, version, reserved)
	 * - Bytes 128..st.st_size: data_ payload
	 * Root prop_trie_node is at data_ + 0 (file offset 128)
	 */
	walk_trie_node(map + PROP_AREA_HEADER_SIZE,
	               (size_t)st.st_size - PROP_AREA_HEADER_SIZE,
	               map, (size_t)st.st_size,
	               0, "", col);

	munmap(map, st.st_size);
}

static void parse_property_info_contexts(const char *prop_dir, struct prop_collector *col)
{
	char pinfo_path[PATH_MAX];
	int fd;
	struct stat st;
	char *map;
	const struct property_info_area_header *hdr;
	uint32_t num_contexts;
	const uint32_t *offsets;
	uint32_t i;

	snprintf(pinfo_path, sizeof(pinfo_path), "%s/property_info", prop_dir);
	fd = open(pinfo_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(struct property_info_area_header)) {
		close(fd);
		return;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (map == MAP_FAILED)
		return;

	hdr = (const struct property_info_area_header *)map;
	if (hdr->contexts_offset + 4 <= (size_t)st.st_size) {
		num_contexts = *(const uint32_t *)(map + hdr->contexts_offset);
		offsets = (const uint32_t *)(map + hdr->contexts_offset + 4);

		if (hdr->contexts_offset + 4 + (size_t)num_contexts * sizeof(uint32_t) <= (size_t)st.st_size) {
			for (i = 0; i < num_contexts; i++) {
				uint32_t ctx_off = offsets[i];
				if (ctx_off < (size_t)st.st_size) {
					const char *ctx_name = map + ctx_off;
					char fpath[PATH_MAX];

					if (strnlen(ctx_name, (size_t)st.st_size - ctx_off) < (size_t)st.st_size - ctx_off) {
						snprintf(fpath, sizeof(fpath), "%s/%s", prop_dir, ctx_name);
						parse_prop_file(fpath, ctx_name, col);
						if (col->target_key && col->found_value)
							break;
					}
				}
			}
		}
	}

	munmap(map, st.st_size);
}

static int prop_cmp(const void *a, const void *b)
{
	const struct prop_entry *ea = (const struct prop_entry *)a;
	const struct prop_entry *eb = (const struct prop_entry *)b;
	return strcmp(ea->name, eb->name);
}

int getprop_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int getprop_main(int argc, char **argv)
{
	struct prop_collector col;
	const char *prop_dir = ANDROID_PROP_DIR;
	const char *target = NULL;
	const char *def_val = "";
	DIR *dir;
	struct dirent *de;
	size_t i;
	bool show_context = false;
	int opt;

	memset(&col, 0, sizeof(col));

	while ((opt = getopt(argc, argv, "ZT")) != -1) {
		switch (opt) {
		case 'Z':
		case 'T':
			show_context = true;
			break;
		default:
			bb_show_usage();
		}
	}

	if (optind < argc) {
		target = argv[optind++];
		if (optind < argc)
			def_val = argv[optind++];
	}

	col.target_key = target;
	col.show_context = show_context;

	dir = opendir(prop_dir);
	if (dir) {
		while ((de = readdir(dir)) != NULL) {
			char fpath[PATH_MAX];
			if (de->d_name[0] == '.')
				continue;
			if (strcmp(de->d_name, "properties_serial") == 0 ||
			    strcmp(de->d_name, "property_info") == 0)
				continue;

			snprintf(fpath, sizeof(fpath), "%s/%s", prop_dir, de->d_name);
			parse_prop_file(fpath, de->d_name, &col);

			if (target && col.found_value)
				break;
		}
		closedir(dir);
	} else {
		/* Non-root or opendir denied (mode 711): discover context files from property_info */
		parse_property_info_contexts(prop_dir, &col);

		/* Legacy single-file Android fallback (/dev/__properties__) */
		if (col.count == 0 && (!target || !col.found_value)) {
			struct stat st;
			if (stat(prop_dir, &st) == 0 && S_ISREG(st.st_mode))
				parse_prop_file(prop_dir, "u:object_r:default_prop:s0", &col);
		}
	}

	if (target) {
		if (col.found_value && col.found_value[0] != '\0') {
			puts(col.found_value);
			free(col.found_value);
			return EXIT_SUCCESS;
		}
		if (def_val && def_val[0] != '\0') {
			puts(def_val);
			return EXIT_SUCCESS;
		}
		/* Empty string if not found, standard Android behavior */
		putchar('\n');
		return EXIT_SUCCESS;
	}

	/* Listing all properties: sort alphabetically and print */
	if (col.count > 1)
		qsort(col.entries, col.count, sizeof(struct prop_entry), prop_cmp);

	{
		const char *prev_name = "";
		for (i = 0; i < col.count; i++) {
			if (strcmp(col.entries[i].name, prev_name) == 0)
				continue; /* eliminate duplicates across contexts */

			prev_name = col.entries[i].name;

			if (show_context && col.entries[i].context) {
				printf("[%s]: [%s]\n", col.entries[i].name, col.entries[i].context);
			} else {
				printf("[%s]: [%s]\n", col.entries[i].name, col.entries[i].value);
			}
		}
	}

	for (i = 0; i < col.count; i++) {
		free(col.entries[i].name);
		free(col.entries[i].value);
		free(col.entries[i].context);
	}
	free(col.entries);

	return EXIT_SUCCESS;
}
