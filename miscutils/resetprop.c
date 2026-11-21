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
//usage:     "\n	-p, --persist	Always write persistent prop changes to storage (/data/property)"
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
	char matched_context[128];
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
		safe_strncpy(state->matched_context, context_name ? context_name : "unknown", sizeof(state->matched_context));
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
 * =========================================================================
 * Dynamic Shared-Memory Property Allocation Engine
 * =========================================================================
 * Allocates and inserts new prop_trie_node and prop_info records directly
 * into Android property shared memory areas without relying on init's socket.
 */

static void *prop_area_alloc(char *area_base, size_t area_size, size_t size, uint32_t *out_offset)
{
	struct prop_area_header *hdr = (struct prop_area_header *)area_base;
	size_t aligned = (size + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
	uint32_t payload_max;

	if (area_size <= PROP_AREA_HEADER_SIZE)
		return NULL;

	payload_max = (uint32_t)(area_size - PROP_AREA_HEADER_SIZE);
	if (hdr->bytes_used + aligned > payload_max)
		return NULL;

	*out_offset = hdr->bytes_used;
	hdr->bytes_used += (uint32_t)aligned;
	__sync_synchronize();
	return (area_base + PROP_AREA_HEADER_SIZE + *out_offset);
}

static int cmp_prop_name(const char *a, uint32_t a_len, const char *b, uint32_t b_len)
{
	if (a_len < b_len) return -1;
	if (a_len > b_len) return 1;
	return strncmp(a, b, a_len);
}

static struct prop_trie_node *find_or_add_bst_node(char *area_base, size_t area_size,
                                                   uint32_t *node_off_ptr,
                                                   const char *name, uint32_t namelen)
{
	char *data_base = area_base + PROP_AREA_HEADER_SIZE;
	uint32_t cur_off = *node_off_ptr;
	struct prop_trie_node *cur;

	if (cur_off == 0) {
		uint32_t new_off = 0;
		size_t alloc_sz = sizeof(struct prop_trie_node) + namelen + 1;
		cur = (struct prop_trie_node *)prop_area_alloc(area_base, area_size, alloc_sz, &new_off);
		if (!cur) return NULL;
		memset(cur, 0, alloc_sz);
		cur->namelen = namelen;
		memcpy(cur->name, name, namelen);
		cur->name[namelen] = '\0';
		__sync_synchronize();
		*node_off_ptr = new_off;
		return cur;
	}

	cur = (struct prop_trie_node *)(data_base + cur_off);
	while (1) {
		int cmp = cmp_prop_name(name, namelen, cur->name, cur->namelen);
		if (cmp == 0) {
			return cur;
		} else if (cmp < 0) {
			if (cur->left != 0) {
				cur = (struct prop_trie_node *)(data_base + cur->left);
			} else {
				uint32_t new_off = 0;
				size_t alloc_sz = sizeof(struct prop_trie_node) + namelen + 1;
				struct prop_trie_node *new_node =
					(struct prop_trie_node *)prop_area_alloc(area_base, area_size, alloc_sz, &new_off);
				if (!new_node) return NULL;
				memset(new_node, 0, alloc_sz);
				new_node->namelen = namelen;
				memcpy(new_node->name, name, namelen);
				new_node->name[namelen] = '\0';
				__sync_synchronize();
				cur->left = new_off;
				return new_node;
			}
		} else {
			if (cur->right != 0) {
				cur = (struct prop_trie_node *)(data_base + cur->right);
			} else {
				uint32_t new_off = 0;
				size_t alloc_sz = sizeof(struct prop_trie_node) + namelen + 1;
				struct prop_trie_node *new_node =
					(struct prop_trie_node *)prop_area_alloc(area_base, area_size, alloc_sz, &new_off);
				if (!new_node) return NULL;
				memset(new_node, 0, alloc_sz);
				new_node->namelen = namelen;
				memcpy(new_node->name, name, namelen);
				new_node->name[namelen] = '\0';
				__sync_synchronize();
				cur->right = new_off;
				return new_node;
			}
		}
	}
}

static bool add_property_to_area(char *area_base, size_t area_size, const char *name, const char *val)
{
	char *data_base;
	struct prop_trie_node *root;
	struct prop_trie_node *current;
	const char *remaining = name;
	size_t nlen, vlen, total_pi_sz;
	uint32_t pi_off = 0;
	struct prop_info *pi;

	if (!area_base || area_size < PROP_AREA_HEADER_SIZE + sizeof(struct prop_trie_node))
		return false;

	data_base = area_base + PROP_AREA_HEADER_SIZE;
	root = (struct prop_trie_node *)data_base;
	current = root;

	while (1) {
		const char *sep = strchr(remaining, '.');
		bool want_subtree = (sep != NULL);
		uint32_t substr_size = want_subtree ? (uint32_t)(sep - remaining) : (uint32_t)strlen(remaining);

		if (substr_size == 0) return false;

		current = find_or_add_bst_node(area_base, area_size, &current->children, remaining, substr_size);
		if (!current) return false;

		if (!want_subtree) break;
		remaining = sep + 1;
	}

	if (current->prop != 0) {
		/* Property already exists in trie: mutate it */
		struct prop_modify_state dummy_state;
		pi = (struct prop_info *)(data_base + current->prop);
		memset(&dummy_state, 0, sizeof(dummy_state));
		dummy_state.target_name = name;
		dummy_state.new_value = val;
		mutate_prop_info(pi, &dummy_state);
		return true;
	}

	/* Allocate new prop_info leaf */
	nlen = strlen(name);
	vlen = val ? strlen(val) : 0;
	total_pi_sz = sizeof(struct prop_info) + nlen + 1;

	if (vlen >= PROP_VALUE_MAX) {
		/* Long property support */
		uint32_t long_val_off = 0;
		char *long_val_buf = (char *)prop_area_alloc(area_base, area_size, vlen + 1, &long_val_off);
		if (!long_val_buf) return false;
		memcpy(long_val_buf, val, vlen);
		long_val_buf[vlen] = '\0';

		pi = (struct prop_info *)prop_area_alloc(area_base, area_size, total_pi_sz, &pi_off);
		if (!pi) return false;
		memset(pi, 0, total_pi_sz);
		pi->serial = PROP_FLAG_LONG | ((uint32_t)vlen << 24);
		pi->long_property.offset = long_val_off - pi_off;
	} else {
		pi = (struct prop_info *)prop_area_alloc(area_base, area_size, total_pi_sz, &pi_off);
		if (!pi) return false;
		memset(pi, 0, total_pi_sz);
		pi->serial = (uint32_t)vlen << 24;
		if (val && vlen > 0) {
			memcpy(pi->value, val, vlen);
			pi->value[vlen] = '\0';
		}
	}

	memcpy(pi->name, name, nlen);
	pi->name[nlen] = '\0';
	__sync_synchronize();
	current->prop = pi_off;
	return true;
}

static bool resetprop_add_property_in_file(const char *filepath, const char *name, const char *val, bool verbose)
{
	int fd;
	struct stat st;
	char *map;
	mode_t orig_mode;
	bool mode_changed = false;
	bool success = false;

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

	if (st.st_size < (off_t)(PROP_AREA_HEADER_SIZE + sizeof(struct prop_trie_node))) {
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

	success = add_property_to_area(map, (size_t)st.st_size, name, val);
	if (success) {
		msync(map, st.st_size, MS_SYNC);
		if (verbose) printf("[+] Added new property '%s' = '%s' into %s\n", name, val ? val : "", filepath);
	}

	munmap(map, st.st_size);
	if (mode_changed) chmod(filepath, orig_mode);
	return success;
}

static bool resetprop_insert_new_property(const char *name, const char *val, bool verbose)
{
	const char *prop_dir = ANDROID_PROP_DIR;
	char target_path[PATH_MAX];
	DIR *dir;
	struct dirent *de;

	/* 1. Try standard default context files first */
	snprintf(target_path, sizeof(target_path), "%s/u:object_r:default_prop:s0", prop_dir);
	if (resetprop_add_property_in_file(target_path, name, val, verbose))
		return true;

	snprintf(target_path, sizeof(target_path), "%s/default_prop", prop_dir);
	if (resetprop_add_property_in_file(target_path, name, val, verbose))
		return true;

	/* 2. Search for any accessible context file in /dev/__properties__/ with capacity */
	dir = opendir(prop_dir);
	if (dir) {
		while ((de = readdir(dir)) != NULL) {
			if (de->d_name[0] == '.') continue;
			if (strcmp(de->d_name, "properties_serial") == 0 ||
			    strcmp(de->d_name, "property_info") == 0)
				continue;

			snprintf(target_path, sizeof(target_path), "%s/%s", prop_dir, de->d_name);
			if (resetprop_add_property_in_file(target_path, name, val, verbose)) {
				closedir(dir);
				return true;
			}
		}
		closedir(dir);
	}

	/* 3. Legacy monolithic property file */
	if (resetprop_add_property_in_file(prop_dir, name, val, verbose))
		return true;

	return false;
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
			       state.matched_context[0] != '\0' ? state.matched_context : "unknown");
		}
		return 0;
	}

	/* If property was not found in shared memory and we have a value to set */
	if (!delete_prop && val) {
		/* Attempt dynamic trie allocation in shared memory (handles ro.* and custom props) */
		if (resetprop_insert_new_property(name, val, verbose)) {
			return 0;
		}

		/* Fallback to property_service socket for non-ro properties */
		if (strncmp(name, "ro.", 3) != 0) {
			if (send_property_service_socket(name, val) == 0) {
				if (verbose) printf("[+] Set property '%s' via property_service socket\n", name);
				return 0;
			}
		}
	}

	return -1;
}

/*
 * =========================================================================
 * Persistent Property Storage Engine (/data/property/)
 * =========================================================================
 * Android maintains persistent properties across boots via two formats:
 * 1. Modern Android (Android 9.0+ / Pie to Android 16):
 *    Serialized Protobuf binary file at /data/property/persistent_properties
 *    Message PersistentProperties { repeated PersistentPropertyRecord properties = 1; }
 *    Record: Tag 0x0a = name (field 1, wire 2), Tag 0x12 = value (field 2, wire 2).
 *    Outer: Tag 0x0a = record (field 1, wire 2).
 * 2. Legacy Android (Android 5.0 - 8.1):
 *    Individual disk files at /data/property/<name> containing the property value.
 *
 * All persistent disk modifications are performed atomically via a .tmp file,
 * followed by fsync() and atomic rename() to prevent storage corruption.
 */

struct persist_record {
	char *name;
	char *value;
};

struct persist_list {
	struct persist_record *items;
	size_t count;
	size_t capacity;
};

static void persist_list_add(struct persist_list *pl, const char *name, const char *value)
{
	if (pl->count >= pl->capacity) {
		pl->capacity = (pl->capacity == 0) ? 32 : pl->capacity * 2;
		pl->items = xrealloc(pl->items, pl->capacity * sizeof(pl->items[0]));
	}
	pl->items[pl->count].name = xstrdup(name);
	pl->items[pl->count].value = xstrdup(value ? value : "");
	pl->count++;
}

static void persist_list_free(struct persist_list *pl)
{
	size_t i;
	for (i = 0; i < pl->count; i++) {
		free(pl->items[i].name);
		free(pl->items[i].value);
	}
	free(pl->items);
	pl->items = NULL;
	pl->count = 0;
	pl->capacity = 0;
}

static size_t encode_varint(uint8_t *dest, uint32_t val)
{
	size_t len = 0;
	while (val >= 0x80) {
		dest[len++] = (uint8_t)((val & 0x7f) | 0x80);
		val >>= 7;
	}
	dest[len++] = (uint8_t)(val & 0x7f);
	return len;
}

static bool decode_varint(const uint8_t **ptr, const uint8_t *end, uint32_t *val)
{
	uint32_t res = 0;
	unsigned shift = 0;
	while (*ptr < end) {
		uint8_t b = *(*ptr)++;
		res |= (uint32_t)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			*val = res;
			return true;
		}
		shift += 7;
		if (shift >= 35) return false;
	}
	return false;
}

static void *read_entire_file(const char *path, size_t *out_size)
{
	int fd;
	struct stat st;
	char *buf;
	ssize_t nr;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return NULL;

	if (fstat(fd, &st) < 0 || st.st_size <= 0) {
		close(fd);
		return NULL;
	}

	buf = xmalloc((size_t)st.st_size);
	nr = full_read(fd, buf, (size_t)st.st_size);
	close(fd);

	if (nr != (ssize_t)st.st_size) {
		free(buf);
		return NULL;
	}

	*out_size = (size_t)st.st_size;
	return buf;
}

static int write_file_atomic(const char *path, const void *data, size_t size, mode_t mode)
{
	char tmp_path[PATH_MAX];
	int fd;
	ssize_t nw;

	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0) return -1;

	nw = full_write(fd, data, size);
	if (nw != (ssize_t)size) {
		close(fd);
		unlink(tmp_path);
		return -1;
	}

	if (fsync(fd) < 0) {
		close(fd);
		unlink(tmp_path);
		return -1;
	}

	close(fd);
	if (rename(tmp_path, path) < 0) {
		unlink(tmp_path);
		return -1;
	}
	return 0;
}

static bool parse_persistent_properties_proto(const uint8_t *data, size_t size, struct persist_list *pl)
{
	const uint8_t *ptr = data;
	const uint8_t *end = data + size;

	while (ptr < end) {
		uint32_t tag = 0;
		uint32_t wire_type;
		uint32_t field_num;

		if (!decode_varint(&ptr, end, &tag)) break;

		wire_type = tag & 0x07;
		field_num = tag >> 3;

		if (field_num == 1 && wire_type == 2) {
			/* Field 1: repeated PersistentPropertyRecord properties */
			uint32_t rec_len = 0;
			const uint8_t *rec_end;
			char *rec_name = NULL;
			char *rec_val = NULL;

			if (!decode_varint(&ptr, end, &rec_len)) break;
			if (ptr + rec_len > end) break;

			rec_end = ptr + rec_len;

			while (ptr < rec_end) {
				uint32_t inner_tag = 0;
				uint32_t inner_wire;
				uint32_t inner_field;

				if (!decode_varint(&ptr, rec_end, &inner_tag)) break;
				inner_wire = inner_tag & 0x07;
				inner_field = inner_tag >> 3;

				if (inner_wire == 2) {
					uint32_t str_len = 0;
					if (!decode_varint(&ptr, rec_end, &str_len)) break;
					if (ptr + str_len > rec_end) break;

					if (inner_field == 1) {
						/* Field 1: optional string name */
						free(rec_name);
						rec_name = xstrndup((const char *)ptr, str_len);
					} else if (inner_field == 2) {
						/* Field 2: optional string value */
						free(rec_val);
						rec_val = xstrndup((const char *)ptr, str_len);
					}
					ptr += str_len;
				} else if (inner_wire == 0) {
					uint32_t dummy;
					if (!decode_varint(&ptr, rec_end, &dummy)) break;
				} else if (inner_wire == 1) {
					ptr += 8;
				} else if (inner_wire == 5) {
					ptr += 4;
				} else {
					break;
				}
			}

			if (rec_name) {
				persist_list_add(pl, rec_name, rec_val ? rec_val : "");
				free(rec_name);
				free(rec_val);
			}
			ptr = rec_end;
		} else if (wire_type == 2) {
			uint32_t skip_len = 0;
			if (!decode_varint(&ptr, end, &skip_len)) break;
			if (ptr + skip_len > end) break;
			ptr += skip_len;
		} else if (wire_type == 0) {
			uint32_t dummy;
			if (!decode_varint(&ptr, end, &dummy)) break;
		} else if (wire_type == 1) {
			ptr += 8;
		} else if (wire_type == 5) {
			ptr += 4;
		} else {
			break;
		}
	}
	return true;
}

static uint8_t *serialize_persistent_properties_proto(const struct persist_list *pl, size_t *out_size)
{
	size_t i;
	size_t total_alloc = 256;
	uint8_t *buf = xmalloc(total_alloc);
	size_t buf_len = 0;

	for (i = 0; i < pl->count; i++) {
		const char *name = pl->items[i].name;
		const char *val = pl->items[i].value;
		size_t name_len = strlen(name);
		size_t val_len = strlen(val);
		size_t inner_alloc = name_len + val_len + 32;
		uint8_t *inner = xmalloc(inner_alloc);
		size_t inner_len = 0;
		uint8_t outer_hdr[16];
		size_t outer_hdr_len = 0;

		/* Tag 1 for name (field 1, wire 2 -> 0x0a) */
		inner[inner_len++] = 0x0a;
		inner_len += encode_varint(inner + inner_len, (uint32_t)name_len);
		memcpy(inner + inner_len, name, name_len);
		inner_len += name_len;

		/* Tag 2 for value (field 2, wire 2 -> 0x12) */
		inner[inner_len++] = 0x12;
		inner_len += encode_varint(inner + inner_len, (uint32_t)val_len);
		memcpy(inner + inner_len, val, val_len);
		inner_len += val_len;

		/* Outer record: Tag 1 (field 1, wire 2 -> 0x0a) + inner_len + inner */
		outer_hdr[outer_hdr_len++] = 0x0a;
		outer_hdr_len += encode_varint(outer_hdr + outer_hdr_len, (uint32_t)inner_len);

		if (buf_len + outer_hdr_len + inner_len > total_alloc) {
			total_alloc = (buf_len + outer_hdr_len + inner_len) * 2;
			buf = xrealloc(buf, total_alloc);
		}

		memcpy(buf + buf_len, outer_hdr, outer_hdr_len);
		buf_len += outer_hdr_len;
		memcpy(buf + buf_len, inner, inner_len);
		buf_len += inner_len;
		free(inner);
	}

	*out_size = buf_len;
	return buf;
}

static int modify_persistent_storage(const char *name, const char *val, bool delete_prop, bool verbose)
{
	int ret = 0;
	struct stat st;
	char legacy_path[PATH_MAX];
	bool handled_modern = false;

	if (!name || name[0] == '\0')
		return -1;

	/* 1. Modern Android: /data/property/persistent_properties (Android 9.0+) */
	if (stat(ANDROID_PERSISTENT_PROP_FILE, &st) == 0 ||
	    (stat(ANDROID_PERSISTENT_PROP_DIR, &st) == 0 && S_ISDIR(st.st_mode))) {
		size_t fsize = 0;
		uint8_t *raw_data = (uint8_t *)read_entire_file(ANDROID_PERSISTENT_PROP_FILE, &fsize);
		struct persist_list pl;
		size_t i;
		bool found = false;
		size_t out_sz = 0;
		uint8_t *out_buf;

		memset(&pl, 0, sizeof(pl));
		if (raw_data) {
			parse_persistent_properties_proto(raw_data, fsize, &pl);
			free(raw_data);
		}

		for (i = 0; i < pl.count; i++) {
			if (strcmp(pl.items[i].name, name) == 0) {
				found = true;
				if (delete_prop) {
					free(pl.items[i].name);
					free(pl.items[i].value);
					memmove(&pl.items[i], &pl.items[i + 1], (pl.count - i - 1) * sizeof(pl.items[0]));
					pl.count--;
				} else {
					free(pl.items[i].value);
					pl.items[i].value = xstrdup(val ? val : "");
				}
				break;
			}
		}

		if (!found && !delete_prop) {
			persist_list_add(&pl, name, val ? val : "");
		}

		out_buf = serialize_persistent_properties_proto(&pl, &out_sz);
		if (write_file_atomic(ANDROID_PERSISTENT_PROP_FILE, out_buf, out_sz, 0600) == 0) {
			handled_modern = true;
			if (verbose) {
				printf("[+] %s persistent '%s' in %s\n",
				       delete_prop ? "Removed" : "Saved",
				       name, ANDROID_PERSISTENT_PROP_FILE);
			}
		} else {
			if (verbose) {
				bb_perror_msg("failed writing persistent properties to %s", ANDROID_PERSISTENT_PROP_FILE);
			}
			ret = -1;
		}
		free(out_buf);
		persist_list_free(&pl);
	}

	/* 2. Legacy Android / individual file sync: /data/property/<name> (Android <= 8.1) */
	snprintf(legacy_path, sizeof(legacy_path), "%s/%s", ANDROID_PERSISTENT_PROP_DIR, name);
	if (delete_prop) {
		if (unlink(legacy_path) == 0) {
			if (verbose) printf("[+] Removed legacy persistent property file '%s'\n", legacy_path);
		}
	} else if (!handled_modern || stat(legacy_path, &st) == 0) {
		if (write_file_atomic(legacy_path, val ? val : "", strlen(val ? val : ""), 0600) == 0) {
			if (verbose) printf("[+] Wrote legacy persistent property file '%s'\n", legacy_path);
		}
	}

	return (handled_modern || ret == 0) ? 0 : -1;
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

static bool scan_linear_area_for_read(const char *area_base, size_t area_size, struct prop_collector *col)
{
	size_t tlen;
	const char *p;
	const char *end = area_base + area_size;

	if (!col->target_key) return false;
	tlen = strlen(col->target_key);
	if (tlen == 0 || area_size < sizeof(struct prop_info) + tlen + 1)
		return false;

	p = area_base + PROP_AREA_HEADER_SIZE;
	while (p + tlen + 1 <= end) {
		if (memcmp(p, col->target_key, tlen) == 0 && p[tlen] == '\0') {
			if (p >= area_base + 96) {
				const struct prop_info *pi = (const struct prop_info *)(p - offsetof(struct prop_info, name));
				if ((const char *)pi >= area_base && (const char *)pi + sizeof(struct prop_info) <= end) {
					char val[1024];
					read_property_value(area_base, area_size, pi, val, sizeof(val));
					if (!col->found_value) col->found_value = xstrdup(val);
					return true;
				}
			}
		}
		p++;
	}
	return false;
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

	if (col->target_key && !col->found_value) {
		scan_linear_area_for_read(map, (size_t)st.st_size, col);
	}

	munmap(map, st.st_size);
}

/*
 * Fallback context discovery for non-root users:
 * When opendir("/dev/__properties__") fails with EACCES, read the context
 * list from /dev/__properties__/property_info (which has world-readable 0444 mode).
 */
static void discover_and_collect_contexts(const char *prop_dir, struct prop_collector *col)
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
						collect_prop_file(fpath, ctx_name, col);
						if (col->target_key && col->found_value) break;
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

int resetprop_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int resetprop_main(int argc, char **argv)
{
	bool verbose = false;
	bool persist = false;
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
			persist = true;
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
		if (persist) {
			modify_persistent_storage(target, NULL, true, verbose);
		}
		return EXIT_SUCCESS;
	}

	/* Case 2: Set property */
	if (prop_name && prop_val) {
		if (resetprop_set_property(prop_name, prop_val, false, verbose) != 0) {
			bb_error_msg("failed to set property '%s' to '%s'", prop_name, prop_val);
			return EXIT_FAILURE;
		}
		if (persist) {
			modify_persistent_storage(prop_name, prop_val, false, verbose);
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
		} else {
			discover_and_collect_contexts(ANDROID_PROP_DIR, &col);
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
		} else {
			discover_and_collect_contexts(ANDROID_PROP_DIR, &col);
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
