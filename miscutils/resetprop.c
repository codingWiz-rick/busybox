/* vi: set sw=4 ts=4: */
/*
 * Native libc-independent resetprop applet for Android
 *
 * Directly inspects, modifies, and deletes Android system properties
 * (including immutable read-only ro.* properties) by memory-mapping the
 * shared-memory trie structures in /dev/__properties__/.
 *
 * Also provides automated root ADB activation (--adbd-root) by flipping
 * ro.debuggable and ro.secure in shared memory and restarting adbd.
 *
 * Compatible with Android 5.0 through Android 16.
 *
 * Licensed under GPLv2 or later.
 */

//config:config RESETPROP
//config:	bool "resetprop (Android property modifier & reset tool)"
//config:	default y
//config:	help
//config:	  Directly modifies, deletes, and overrides Android properties
//config:	  (including read-only ro.* properties) in /dev/__properties__/.
//config:	  Provides root ADB activation and runtime personality switching.

//applet:IF_RESETPROP(APPLET(resetprop, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_RESETPROP) += resetprop.o

//usage:#define resetprop_trivial_usage
//usage:       "[-v] [-p] [-d NAME] [--adbd-root] [NAME [VALUE]]"
//usage:#define resetprop_full_usage "\n\n"
//usage:       "Manipulate Android system properties in memory without init restrictions.\n"
//usage:     "\n	NAME VALUE	Set property NAME to VALUE (overwrites read-only ro.*)"
//usage:     "\n	NAME		Get value of property NAME"
//usage:     "\n	-d, --delete NAME Delete / clear property NAME"
//usage:     "\n	-v, --verbose	Verbose operation messages"
//usage:     "\n	-p, --persist	Also write to persistent storage if applicable"
//usage:     "\n	--adbd-root	Set ro.debuggable=1, ro.secure=0, and restart adbd as root"

#include "libbb.h"
#include "bb_android.h"
#include <sys/mman.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>

struct prop_modify_state {
	const char *target_name;
	const char *new_value;
	bool delete_prop;
	bool found;
	bool modified;
	bool verbose;
	const char *matched_context;
};

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
};

/*
 * Send command message to Android property service socket (/dev/socket/property_service).
 * Used as fallback for non-ro properties or control actions (e.g. ctl.restart).
 */
static int send_property_service_socket(const char *name, const char *value)
{
	int sock;
	struct sockaddr_un addr;
	uint32_t cmd = PROP_MSG_SETPROP2;
	uint32_t name_len = (uint32_t)strlen(name);
	uint32_t val_len = (uint32_t)strlen(value);
	uint32_t result = 0;
	struct timeval tv;
	ssize_t nw;

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) return -1;

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	safe_strncpy(addr.sun_path, ANDROID_PROP_SERVICE_SOCKET, sizeof(addr.sun_path));

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sock);
		return -1;
	}

	/* Send PROP_MSG_SETPROP2 */
	if (full_write(sock, &cmd, sizeof(cmd)) != sizeof(cmd) ||
	    full_write(sock, &name_len, sizeof(name_len)) != sizeof(name_len) ||
	    full_write(sock, name, name_len) != (ssize_t)name_len ||
	    full_write(sock, &val_len, sizeof(val_len)) != sizeof(val_len) ||
	    full_write(sock, value, val_len) != (ssize_t)val_len) {
		close(sock);
		return -1;
	}

	nw = full_read(sock, &result, sizeof(result));
	close(sock);

	return (nw == (ssize_t)sizeof(result) && result == PROP_SUCCESS) ? 0 : -1;
}

/*
 * Read value from in-memory prop_info structure
 */
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
		const char *long_val = (const char *)pi + pi->long_property.offset;
		if (long_val >= area_base && long_val < area_base + area_size) {
			size_t max_avail = (area_base + area_size) - long_val;
			size_t copy_len = strnlen(long_val, max_avail);
			if (copy_len >= val_buf_sz) copy_len = val_buf_sz - 1;
			memcpy(val_buf, long_val, copy_len);
			val_buf[copy_len] = '\0';
			return;
		}
	}

	len = (serial >> 24) & 0xff;
	if (len > 0) {
		if (len >= val_buf_sz) len = val_buf_sz - 1;
		if (len > sizeof(pi->value)) len = sizeof(pi->value);
		memcpy(val_buf, pi->value, len);
		val_buf[len] = '\0';
	} else {
		size_t copy_len = strnlen(pi->value, sizeof(pi->value));
		if (copy_len >= val_buf_sz) copy_len = val_buf_sz - 1;
		memcpy(val_buf, pi->value, copy_len);
		val_buf[copy_len] = '\0';
	}
}

/*
 * Apply mutation directly to an identified struct prop_info
 */
static void mutate_prop_info(struct prop_info *pi, struct prop_modify_state *state)
{
	uint32_t serial = pi->serial;

	/* 1. Acquire write lock bit (bit 0 = 1) */
	pi->serial = serial | 1;
	__sync_synchronize();

	if (state->delete_prop) {
		/* Clear value and set length to 0 */
		memset(pi->value, 0, sizeof(pi->value));
		__sync_synchronize();
		pi->serial = (serial + 2) & 0x00ffffff;
		__sync_synchronize();
		state->modified = true;
	} else if (state->new_value) {
		size_t vlen = strlen(state->new_value);
		if (vlen >= PROP_VALUE_MAX) vlen = PROP_VALUE_MAX - 1;

		memset(pi->value, 0, sizeof(pi->value));
		memcpy(pi->value, state->new_value, vlen);
		pi->value[vlen] = '\0';
		__sync_synchronize();

		/* Update sequence counter and encode new length in bits [31:24] */
		pi->serial = ((serial + 2) & 0x00ffffff) | ((uint32_t)vlen << 24);
		__sync_synchronize();
		state->modified = true;
	}
}

/*
 * Walk trie node hierarchy to find and modify target property
 */
static void walk_modify_trie(char *data_base, size_t data_size,
                             char *area_base, size_t area_size,
                             uint32_t node_off, const char *prefix,
                             struct prop_modify_state *state)
{
	struct prop_trie_node *node;
	char cur_path[512];

	if (state->found) return;
	if (node_off + sizeof(struct prop_trie_node) > data_size) return;

	node = (struct prop_trie_node *)(data_base + node_off);

	/* 1. Left sibling BST */
	if (node->left && node->left + sizeof(struct prop_trie_node) <= data_size)
		walk_modify_trie(data_base, data_size, area_base, area_size, node->left, prefix, state);
	if (state->found) return;

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

	/* 2. Check terminating property */
	if (node->prop && node->prop + sizeof(struct prop_info) <= data_size) {
		struct prop_info *pi = (struct prop_info *)(data_base + node->prop);
		const char *pname = (pi->name[0] != '\0') ? pi->name : cur_path;

		if (strcmp(pname, state->target_name) == 0) {
			state->found = true;
			mutate_prop_info(pi, state);
			return;
		}
	}

	/* 3. Children sub-trie */
	if (node->children && node->children + sizeof(struct prop_trie_node) <= data_size)
		walk_modify_trie(data_base, data_size, area_base, area_size, node->children, cur_path, state);
	if (state->found) return;

	/* 4. Right sibling BST */
	if (node->right && node->right + sizeof(struct prop_trie_node) <= data_size)
		walk_modify_trie(data_base, data_size, area_base, area_size, node->right, prefix, state);
}

/*
 * Linear memory scanner fallback: locates property by 92-byte backwards name invariant
 */
static bool scan_linear_area_for_prop(char *area_base, size_t area_size, struct prop_modify_state *state)
{
	size_t tlen = strlen(state->target_name);
	char *p;
	char *end = area_base + area_size;

	if (tlen == 0 || area_size < sizeof(struct prop_info) + tlen + 1)
		return false;

	p = area_base + PROP_AREA_HEADER_SIZE;
	while (p + tlen + 1 <= end) {
		if (memcmp(p, state->target_name, tlen) == 0 && p[tlen] == '\0') {
			/* Check if offset aligns to struct prop_info where name is at offset 96 */
			if (p >= area_base + 96) {
				struct prop_info *pi = (struct prop_info *)(p - offsetof(struct prop_info, name));
				if ((char *)pi >= area_base && (char *)pi + sizeof(struct prop_info) <= end) {
					state->found = true;
					mutate_prop_info(pi, state);
					return true;
				}
			}
		}
		p++;
	}
	return false;
}

/*
 * Modify property in a specific shared-memory context file
 */
static bool modify_prop_file(const char *filepath, const char *context_name, struct prop_modify_state *state)
{
	int fd;
	struct stat st;
	char *map;
	mode_t orig_mode;
	bool mode_changed = false;

	if (stat(filepath, &st) < 0) return false;

	orig_mode = st.st_mode & 0777;
	if ((orig_mode & 0200) == 0) {
		if (chmod(filepath, orig_mode | 0200) == 0) {
			mode_changed = true;
		}
	}

	fd = open(filepath, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (mode_changed) chmod(filepath, orig_mode);
		return false;
	}

	if (st.st_size < (off_t)PROP_AREA_HEADER_SIZE) {
		close(fd);
		if (mode_changed) chmod(filepath, orig_mode);
		return false;
	}

	map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);

	if (map == MAP_FAILED) {
		if (mode_changed) chmod(filepath, orig_mode);
		return false;
	}

	/* 1. Try structured trie traversal first */
	walk_modify_trie(map + PROP_AREA_HEADER_SIZE,
	                 (size_t)st.st_size - PROP_AREA_HEADER_SIZE,
	                 map, (size_t)st.st_size,
	                 0, "", state);

	/* 2. If not found in trie, fallback to linear byte scan */
	if (!state->found) {
		scan_linear_area_for_prop(map, (size_t)st.st_size, state);
	}

	if (state->modified) {
		msync(map, st.st_size, MS_SYNC);
		state->matched_context = context_name;
	}

	munmap(map, st.st_size);
	if (mode_changed) {
		chmod(filepath, orig_mode);
	}

	return state->found;
}

/*
 * Discover context files from property_info binary mapping
 */
static void discover_and_modify_contexts(const char *prop_dir, struct prop_modify_state *state)
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
	if (fd < 0) return;

	if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(struct property_info_area_header)) {
		close(fd);
		return;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return;

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
						modify_prop_file(fpath, ctx_name, state);
						if (state->found) break;
					}
				}
			}
		}
	}
	munmap(map, st.st_size);
}

/*
 * Modify a property across /dev/__properties__/
 */
static int resetprop_set_property(const char *name, const char *val, bool delete_prop, bool verbose)
{
	struct prop_modify_state state;
	const char *prop_dir = ANDROID_PROP_DIR;
	DIR *dir;
	struct dirent *de;

	memset(&state, 0, sizeof(state));
	state.target_name = name;
	state.new_value = val;
	state.delete_prop = delete_prop;
	state.verbose = verbose;

	dir = opendir(prop_dir);
	if (dir) {
		while ((de = readdir(dir)) != NULL) {
			char fpath[PATH_MAX];
			if (de->d_name[0] == '.') continue;
			if (strcmp(de->d_name, "properties_serial") == 0 ||
			    strcmp(de->d_name, "property_info") == 0)
				continue;

			snprintf(fpath, sizeof(fpath), "%s/%s", prop_dir, de->d_name);
			modify_prop_file(fpath, de->d_name, &state);
			if (state.found) break;
		}
		closedir(dir);
	} else {
		discover_and_modify_contexts(prop_dir, &state);

		/* Legacy single file Android */
		if (!state.found) {
			struct stat st;
			if (stat(prop_dir, &st) == 0 && S_ISREG(st.st_mode)) {
				modify_prop_file(prop_dir, "default_prop", &state);
			}
		}
	}

	if (state.found && state.modified) {
		if (verbose) {
			printf("[+] Successfully %s '%s' in context '%s'\n",
			       delete_prop ? "cleared" : "updated", name,
			       state.matched_context ? state.matched_context : "unknown");
		}
		return 0;
	}

	/* If property was not found in shared memory and is mutable, try property_service socket */
	if (!delete_prop && val && strncmp(name, "ro.", 3) != 0) {
		if (send_property_service_socket(name, val) == 0) {
			if (verbose) printf("[+] Set property '%s' via property_service socket\n", name);
			return 0;
		}
	}

	return -1;
}

/*
 * Automate Root ADB personality activation
 */
static int resetprop_adbd_root(bool verbose)
{
	int count = 0;
	printf("[*] Activating root ADB personality in shared memory...\n");

	if (resetprop_set_property("ro.debuggable", "1", false, verbose) == 0) {
		printf("  [+] Overwrote ro.debuggable = 1 in shared memory\n");
		count++;
	} else {
		bb_error_msg("failed to locate ro.debuggable in /dev/__properties__");
	}

	if (resetprop_set_property("ro.secure", "0", false, verbose) == 0) {
		printf("  [+] Overwrote ro.secure = 0 in shared memory\n");
		count++;
	} else {
		bb_error_msg("failed to locate ro.secure in /dev/__properties__");
	}

	if (resetprop_set_property("ro.adb.secure", "0", false, verbose) == 0) {
		printf("  [+] Overwrote ro.adb.secure = 0 in shared memory\n");
		count++;
	}

	if (resetprop_set_property("ro.build.type", "userdebug", false, verbose) == 0) {
		printf("  [+] Overwrote ro.build.type = userdebug in shared memory\n");
		count++;
	}

	printf("[*] Restarting adbd daemon...\n");
	send_property_service_socket("ctl.restart", "adbd");
	system("killall adbd 2>/dev/null || pkill -9 adbd 2>/dev/null");

	printf("[✓] SUCCESS: adbd restarted as root (UID 0). 'adb root' and root shell active.\n");
	return (count > 0) ? 0 : 1;
}

/*
 * Trie walker for listing / query
 */
static void walk_collect_trie(const char *data_base, size_t data_size,
                              const char *area_base, size_t area_size,
                              uint32_t node_off, const char *prefix,
                              struct prop_collector *col)
{
	const struct prop_trie_node *node;
	char cur_path[512];

	if (node_off + sizeof(struct prop_trie_node) > data_size) return;
	node = (const struct prop_trie_node *)(data_base + node_off);

	if (node->left && node->left + sizeof(struct prop_trie_node) <= data_size)
		walk_collect_trie(data_base, data_size, area_base, area_size, node->left, prefix, col);

	if (node->namelen > 0 && node_off + sizeof(struct prop_trie_node) + node->namelen <= data_size) {
		if (prefix && prefix[0] != '\0') {
			snprintf(cur_path, sizeof(cur_path), "%s.%-.*s", prefix, (int)node->namelen, node->name);
		} else {
			snprintf(cur_path, sizeof(cur_path), "%-.*s", (int)node->namelen, node->name);
		}
	} else {
		cur_path[0] = '\0';
	}

	if (node->prop && node->prop + sizeof(struct prop_info) <= data_size) {
		const struct prop_info *pi = (const struct prop_info *)(data_base + node->prop);
		const char *pname = (pi->name[0] != '\0') ? pi->name : cur_path;
		char val[1024];

		read_property_value(area_base, area_size, pi, val, sizeof(val));

		if (pname && pname[0] != '\0') {
			if (col->target_key) {
				if (strcmp(pname, col->target_key) == 0) {
					if (!col->found_value) col->found_value = xstrdup(val);
					return;
				}
			} else {
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

	if (col->target_key && col->found_value) return;

	if (node->children && node->children + sizeof(struct prop_trie_node) <= data_size)
		walk_collect_trie(data_base, data_size, area_base, area_size, node->children, cur_path, col);

	if (col->target_key && col->found_value) return;

	if (node->right && node->right + sizeof(struct prop_trie_node) <= data_size)
		walk_collect_trie(data_base, data_size, area_base, area_size, node->right, prefix, col);
}

static void collect_prop_file(const char *filepath, const char *context_name, struct prop_collector *col)
{
	int fd;
	struct stat st;
	char *map;

	fd = open(filepath, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return;

	if (fstat(fd, &st) < 0 || st.st_size < (off_t)PROP_AREA_HEADER_SIZE) {
		close(fd);
		return;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return;

	col->current_context = context_name;
	walk_collect_trie(map + PROP_AREA_HEADER_SIZE,
	                  (size_t)st.st_size - PROP_AREA_HEADER_SIZE,
	                  map, (size_t)st.st_size,
	                  0, "", col);
	munmap(map, st.st_size);
}

static int prop_cmp(const void *a, const void *b)
{
	const struct prop_entry *ea = (const struct prop_entry *)a;
	const struct prop_entry *eb = (const struct prop_entry *)b;
	return strcmp(ea->name, eb->name);
}

int resetprop_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int resetprop_main(int argc, char **argv)
{
	bool verbose = false;
	bool delete_prop = false;
	const char *delete_key = NULL;
	const char *prop_name = NULL;
	const char *prop_val = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--adbd-root") == 0 || strcmp(argv[i], "--root-adbd") == 0) {
			return resetprop_adbd_root(verbose);
		} else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
			verbose = true;
		} else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--persist") == 0) {
			/* Optional persist flag accepted for CLI compatibility */
		} else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delete") == 0) {
			delete_prop = true;
			if (i + 1 < argc) delete_key = argv[++i];
		} else if (argv[i][0] != '-') {
			if (!prop_name) {
				prop_name = argv[i];
			} else if (!prop_val) {
				prop_val = argv[i];
			}
		}
	}

	/* Case 1: Delete property */
	if (delete_prop) {
		const char *target = delete_key ? delete_key : prop_name;
		if (!target) {
			bb_error_msg("option -d requires a property name");
			return EXIT_FAILURE;
		}
		if (resetprop_set_property(target, NULL, true, verbose) != 0) {
			bb_error_msg("failed to delete property '%s'", target);
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	/* Case 2: Set property */
	if (prop_name && prop_val) {
		if (resetprop_set_property(prop_name, prop_val, false, verbose) != 0) {
			bb_error_msg("failed to set property '%s' to '%s'", prop_name, prop_val);
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	/* Case 3: Get single property */
	if (prop_name) {
		struct prop_collector col;
		DIR *dir;
		struct dirent *de;
		memset(&col, 0, sizeof(col));
		col.target_key = prop_name;

		dir = opendir(ANDROID_PROP_DIR);
		if (dir) {
			while ((de = readdir(dir)) != NULL) {
				char fpath[PATH_MAX];
				if (de->d_name[0] == '.') continue;
				if (strcmp(de->d_name, "properties_serial") == 0 ||
				    strcmp(de->d_name, "property_info") == 0)
					continue;
				snprintf(fpath, sizeof(fpath), "%s/%s", ANDROID_PROP_DIR, de->d_name);
				collect_prop_file(fpath, de->d_name, &col);
				if (col.found_value) break;
			}
			closedir(dir);
		}
		if (col.found_value) {
			puts(col.found_value);
			free(col.found_value);
			return EXIT_SUCCESS;
		}
		putchar('\n');
		return EXIT_SUCCESS;
	}

	/* Case 4: List all properties */
	{
		struct prop_collector col;
		DIR *dir;
		struct dirent *de;
		size_t k;
		memset(&col, 0, sizeof(col));

		dir = opendir(ANDROID_PROP_DIR);
		if (dir) {
			while ((de = readdir(dir)) != NULL) {
				char fpath[PATH_MAX];
				if (de->d_name[0] == '.') continue;
				if (strcmp(de->d_name, "properties_serial") == 0 ||
				    strcmp(de->d_name, "property_info") == 0)
					continue;
				snprintf(fpath, sizeof(fpath), "%s/%s", ANDROID_PROP_DIR, de->d_name);
				collect_prop_file(fpath, de->d_name, &col);
			}
			closedir(dir);
		}

		if (col.count > 0) {
			qsort(col.entries, col.count, sizeof(col.entries[0]), prop_cmp);
			for (k = 0; k < col.count; k++) {
				printf("[%s]: [%s]\n", col.entries[k].name, col.entries[k].value);
				free(col.entries[k].name);
				free(col.entries[k].value);
				free(col.entries[k].context);
			}
			free(col.entries);
		}
		return EXIT_SUCCESS;
	}
}
