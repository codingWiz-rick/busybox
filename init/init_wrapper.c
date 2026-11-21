/* vi: set sw=4 ts=4: */
/*
 * Universal Android First-Stage Init Wrapper & Module Loader Applet
 *
 * Runs as PID 1 (/init) in Android boot ramdisk.
 *
 * Features:
 * 1. Hardware Volume-Down Fail-Safe (KEY_VOLUMEDOWN = 114) for emergency safe mode.
 * 2. Dynamic, configuration-driven module loading from modules.load (zero hardcoded names).
 * 3. Kernel cmdline integration for module parameters (<mod>.<param>=<val>) and safe mode switches.
 * 4. Dual-syscall execution: sys_finit_module() (273) with fallback to sys_init_module() (105).
 * 5. Pristine VFS handoff via umount2(..., MNT_DETACH) before chainloading /init.real or /system/bin/init.
 *
 * Licensed under GPLv2 or later.
 */

//config:config INIT_WRAPPER
//config:	bool "init_wrapper (Android first-stage PID 1 loader)"
//config:	default y
//config:	help
//config:	Universal first-stage init wrapper for Android boot ramdisks.
//config:	Executes as PID 1, mounts early pseudo-filesystems, loads kernel
//config:	modules from modules.load, and chainloads Android init.

//config:config INIT_WRAPPER_AS_INIT
//config:	bool "Alias 'init' applet to init_wrapper (Android first-stage PID 1)"
//config:	default y
//config:	depends on INIT_WRAPPER && !INIT
//config:	help
//config:	Allows BusyBox to act directly as PID 1 /init in Android ramdisks.
//config:	When the kernel executes /init -> /sbin/busybox, BusyBox dispatches
//config:	init_wrapper_main without requiring traditional /etc/inittab.

//applet:IF_INIT_WRAPPER(APPLET(init_wrapper, BB_DIR_SBIN, BB_SUID_DROP))
//applet:IF_INIT_WRAPPER(APPLET_ODDNAME(early_init, init_wrapper, BB_DIR_SBIN, BB_SUID_DROP, init_wrapper))
//applet:IF_INIT_WRAPPER(APPLET_ODDNAME(init_wrap, init_wrapper, BB_DIR_SBIN, BB_SUID_DROP, init_wrapper))
//applet:IF_INIT_WRAPPER_AS_INIT(APPLET_ODDNAME(init, init_wrapper, BB_DIR_SBIN, BB_SUID_DROP, init_wrapper))

//kbuild:lib-$(CONFIG_INIT_WRAPPER) += init_wrapper.o

//usage:#define init_wrapper_trivial_usage
//usage:       "[ARGS]..."
//usage:#define init_wrapper_full_usage "\n\n"
//usage:       "Universal Android first-stage PID 1 init wrapper and early kernel module loader\n"

#ifdef BB_VER
#include "libbb.h"
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef MAIN_EXTERNALLY_VISIBLE
#define MAIN_EXTERNALLY_VISIBLE
#endif
#ifndef UNUSED_PARAM
#define UNUSED_PARAM __attribute__((__unused__))
#endif
static inline ssize_t full_write(int fd, const void *buf, size_t len)
{
	const char *p = (const char *)buf;
	size_t rem = len;
	while (rem > 0) {
		ssize_t w = write(fd, p, rem);
		if (w < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (w == 0) break;
		p += w;
		rem -= (size_t)w;
	}
	return (ssize_t)(len - rem);
}
#endif
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <limits.h>
#include <linux/input.h>

#ifndef SYS_finit_module
#define SYS_finit_module 273
#endif

#ifndef SYS_init_module
#define SYS_init_module 105
#endif

#ifndef KEY_VOLUMEDOWN
#define KEY_VOLUMEDOWN 114
#endif

#ifndef KEY_MAX
#define KEY_MAX 0x2ff
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef __NR_memfd_create
# if defined(__aarch64__)
#  define __NR_memfd_create 279
# elif defined(__x86_64__)
#  define __NR_memfd_create 319
# elif defined(__arm__)
#  define __NR_memfd_create 385
# endif
#endif

#define TAG "<6>early-init: "
#define TAG_ERR "<3>early-init: [ERROR] "
#define TAG_WARN "<4>early-init: [WARN] "

#define DEFAULT_REAL_INIT "/init.real"
#define FALLBACK_SYSTEM_INIT "/system/bin/init"
#define FALLBACK_ORIG_INIT "/init_original"

static const char * const search_dirs[] = {
	"/lib/modules",
	"/system/lib/modules",
	"/vendor/lib/modules",
	"/early_modules",
	"/modules",
	"/",
	NULL
};

static const char * const modules_load_configs[] = {
	"/lib/modules/modules.load",
	"/system/lib/modules/modules.load",
	"/vendor/lib/modules/modules.load",
	"/etc/modules.load",
	"/modules.load",
	NULL
};

static int create_memfd(const char *name)
{
	int fd = -1;
#if defined(SYS_memfd_create)
	fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);
#elif defined(__NR_memfd_create)
	fd = syscall(__NR_memfd_create, name, MFD_CLOEXEC);
#endif
	if (fd < 0) {
#ifdef O_TMPFILE
		fd = open("/dev/shm", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
		if (fd < 0)
			fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
#endif
	}
	return fd;
}

static void kmsg_puts(const char *level, const char *msg)
{
	int fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
		fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	}
	if (fd >= 0) {
		char buf[512];
		int len = snprintf(buf, sizeof(buf), "%s%s\n", level, msg);
		if (len > 0) {
			full_write(fd, buf, (size_t)len);
		}
		close(fd);
	}
}

static void mount_early_vfs(void)
{
	mkdir("/dev", 0755);
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);

	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0 && errno != EBUSY) {
		kmsg_puts(TAG_WARN, "Failed to mount /proc");
	}

	if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0 && errno != EBUSY) {
		kmsg_puts(TAG_WARN, "Failed to mount /sys");
	}
}

static void unmount_early_vfs(void)
{
	umount2("/sys", MNT_DETACH);
	umount2("/proc", MNT_DETACH);
}

static void populate_input_nodes(void)
{
	DIR *dir;
	struct dirent *de;

	mkdir("/dev/input", 0755);
	dir = opendir("/sys/class/input");
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		char dev_path[512];
		char node_path[512];
		char buf[32];
		int fd;
		ssize_t n;
		int major = 0, minor = 0;

		if (strncmp(de->d_name, "event", 5) != 0)
			continue;

		snprintf(dev_path, sizeof(dev_path), "/sys/class/input/%s/dev", de->d_name);
		fd = open(dev_path, O_RDONLY);
		if (fd < 0)
			continue;

		memset(buf, 0, sizeof(buf));
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;

		if (sscanf(buf, "%d:%d", &major, &minor) == 2) {
			snprintf(node_path, sizeof(node_path), "/dev/input/%s", de->d_name);
			mknod(node_path, S_IFCHR | 0660, makedev(major, minor));
		}
	}
	closedir(dir);
}

static bool is_volume_down_held(void)
{
	DIR *dir;
	struct dirent *de;
	bool held = false;

	populate_input_nodes();
	dir = opendir("/dev/input");
	if (!dir)
		return false;

	while ((de = readdir(dir)) != NULL) {
		char node_path[512];
		int fd;
		uint8_t key_bits[(KEY_MAX + 7) / 8];
		uint8_t key_state[(KEY_MAX + 7) / 8];
		int byte_idx;
		int bit_idx;

		if (strncmp(de->d_name, "event", 5) != 0)
			continue;

		snprintf(node_path, sizeof(node_path), "/dev/input/%s", de->d_name);
		fd = open(node_path, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;

		memset(key_bits, 0, sizeof(key_bits));
		if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits) >= 0) {
			byte_idx = KEY_VOLUMEDOWN / 8;
			bit_idx = KEY_VOLUMEDOWN % 8;
			if (byte_idx < (int)sizeof(key_bits) && (key_bits[byte_idx] & (1 << bit_idx))) {
				memset(key_state, 0, sizeof(key_state));
				if (ioctl(fd, EVIOCGKEY(sizeof(key_state)), key_state) >= 0) {
					if (key_state[byte_idx] & (1 << bit_idx)) {
						held = true;
						close(fd);
						break;
					}
				}
			}
		}
		close(fd);
	}
	closedir(dir);
	return held;
}

static void read_proc_cmdline(char *buf, size_t max_len)
{
	int fd;
	buf[0] = '\0';
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, buf, max_len - 1);
		if (n > 0) {
			buf[n] = '\0';
			if (n > 0 && buf[n - 1] == '\n')
				buf[n - 1] = '\0';
		}
		close(fd);
	}
}

static bool cmdline_has_flag(const char *cmdline, const char *flag)
{
	const char *p;
	size_t flen;

	if (!cmdline || !flag)
		return false;

	p = cmdline;
	flen = strlen(flag);

	while ((p = strstr(p, flag)) != NULL) {
		bool left_ok = (p == cmdline || *(p - 1) == ' ');
		bool right_ok = (*(p + flen) == '\0' || *(p + flen) == ' ' || *(p + flen) == '\n');
		if (left_ok && right_ok)
			return true;
		p += flen;
	}
	return false;
}

static bool cmdline_get_val(const char *cmdline, const char *key, char *out, size_t out_sz)
{
	char pattern[128];
	size_t plen;
	const char *p;

	if (!cmdline || !key || !out || out_sz == 0)
		return false;
	out[0] = '\0';

	snprintf(pattern, sizeof(pattern), "%s=", key);
	plen = strlen(pattern);
	p = cmdline;

	while ((p = strstr(p, pattern)) != NULL) {
		if (p == cmdline || *(p - 1) == ' ') {
			const char *val_start = p + plen;
			size_t idx = 0;
			while (*val_start != '\0' && *val_start != ' ' && *val_start != '\n' && idx + 1 < out_sz) {
				out[idx++] = *val_start++;
			}
			out[idx] = '\0';
			return true;
		}
		p += plen;
	}
	return false;
}

static void extract_module_params(const char *cmdline, const char *mod_stem, char *out, size_t out_sz)
{
	char prefix[128];
	size_t pre_len;
	size_t out_pos = 0;
	const char *p;

	out[0] = '\0';
	if (!cmdline || !mod_stem)
		return;

	snprintf(prefix, sizeof(prefix), "%s.", mod_stem);
	pre_len = strlen(prefix);
	p = cmdline;

	while (*p != '\0') {
		const char *token_start;
		size_t token_len;

		while (*p == ' ') p++;
		if (*p == '\0') break;

		token_start = p;
		while (*p != '\0' && *p != ' ' && *p != '\n') p++;
		token_len = p - token_start;

		if (token_len > pre_len && strncmp(token_start, prefix, pre_len) == 0) {
			const char *param_pair = token_start + pre_len;
			size_t pair_len = token_len - pre_len;
			size_t to_copy;

			if (out_pos > 0 && out_pos + 1 < out_sz) {
				out[out_pos++] = ' ';
			}
			to_copy = (out_pos + pair_len < out_sz) ? pair_len : (out_sz - out_pos - 1);
			memcpy(out + out_pos, param_pair, to_copy);
			out_pos += to_copy;
			out[out_pos] = '\0';
		}
	}
}

static void get_module_stem(const char *path, char *stem, size_t stem_sz)
{
	const char *slash = strrchr(path, '/');
	const char *base = slash ? (slash + 1) : path;
	char *dot;

	snprintf(stem, stem_sz, "%s", base);
	dot = strstr(stem, ".ko");
	if (dot)
		*dot = '\0';
}

static int load_single_module(const char *mod_path, const char *params)
{
	int fd;
	const char *mod_params;
	long ret = -1;
	char msg[256];
	char magic[6];
	char stem[64];
	ssize_t nmagic;
	bool is_compressed = false;
	const char *fmt_name = "Compressed";
	size_t decomp_sz = 0;
	void *decomp_buf = NULL;
	int mfd = -1;

	mod_params = params ? params : "";

	fd = open(mod_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(msg, sizeof(msg), "Failed to open module '%s': %s", mod_path, strerror(errno));
		kmsg_puts(TAG_WARN, msg);
		return -1;
	}

	memset(magic, 0, sizeof(magic));
	nmagic = read(fd, magic, sizeof(magic));
	close(fd);

	if (nmagic >= 2) {
		/* Gzip magic: 1f 8b */
		if ((uint8_t)magic[0] == 0x1f && (uint8_t)magic[1] == 0x8b) {
			is_compressed = true;
			fmt_name = "Gzip";
		}
		/* XZ magic: fd 37 7a 58 5a 00 */
		else if (nmagic >= 6 && (uint8_t)magic[0] == 0xfd && magic[1] == '7' &&
		         magic[2] == 'z' && magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00) {
			is_compressed = true;
			fmt_name = "XZ";
		}
		/* Bzip2 magic: 'B' 'Z' */
		else if (magic[0] == 'B' && magic[1] == 'Z') {
			is_compressed = true;
			fmt_name = "Bzip2";
		}
	}

	if (is_compressed) {
		snprintf(msg, sizeof(msg), "Found %s module '%s', decompressing into RAM...", fmt_name, mod_path);
		kmsg_puts(TAG, msg);

		decomp_buf = xmalloc_open_zipped_read_close(mod_path, &decomp_sz);

		if (!decomp_buf || decomp_sz == 0) {
			snprintf(msg, sizeof(msg), "Failed to decompress module '%s' (errno=%d: %s)",
				mod_path, errno, strerror(errno));
			kmsg_puts(TAG_ERR, msg);
			free(decomp_buf);
			return -1;
		}

		/* Verify valid ELF header before kernel injection */
		if (decomp_sz >= 4) {
			const unsigned char *elf = (const unsigned char *)decomp_buf;
			if (elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
				snprintf(msg, sizeof(msg), "Decompressed module '%s' is not a valid ELF binary (magic: %02x %02x %02x %02x)",
					mod_path, elf[0], elf[1], elf[2], elf[3]);
				kmsg_puts(TAG_ERR, msg);
				free(decomp_buf);
				return -1;
			}
		}

		snprintf(msg, sizeof(msg), "Decompressed '%s' (%zu bytes in RAM, valid ELF). Loading via in-memory memfd...",
			mod_path, decomp_sz);
		kmsg_puts(TAG, msg);

		/* Fast path: stream into anonymous in-memory memfd for sys_finit_module */
		get_module_stem(mod_path, stem, sizeof(stem));
		mfd = create_memfd(stem);
		if (mfd >= 0) {
			full_write(mfd, decomp_buf, decomp_sz);
			lseek(mfd, 0, SEEK_SET);
			ret = syscall(SYS_finit_module, mfd, mod_params, 0);
			close(mfd);
		}

		/* Direct in-memory buffer fallback: sys_init_module */
		if (ret != 0 && (errno == ENOSYS || mfd < 0)) {
			ret = syscall(SYS_init_module, decomp_buf, (unsigned long)decomp_sz, mod_params);
		}

		free(decomp_buf);
	} else {
		/* Plain uncompressed ELF .ko */
		snprintf(msg, sizeof(msg), "Loading uncompressed module '%s' via finit_module...", mod_path);
		kmsg_puts(TAG, msg);

		fd = open(mod_path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			snprintf(msg, sizeof(msg), "Failed to reopen module '%s': %s", mod_path, strerror(errno));
			kmsg_puts(TAG_WARN, msg);
			return -1;
		}

		ret = syscall(SYS_finit_module, fd, mod_params, 0);

		if (ret != 0 && errno == ENOSYS) {
			struct stat st;
			if (fstat(fd, &st) == 0 && st.st_size > 0) {
				void *buf = malloc((size_t)st.st_size);
				if (buf) {
					if (read(fd, buf, (size_t)st.st_size) == st.st_size) {
						ret = syscall(SYS_init_module, buf, (unsigned long)st.st_size, mod_params);
					}
					free(buf);
				}
			}
		}
		close(fd);
	}

	if (ret == 0 || errno == EEXIST) {
		snprintf(msg, sizeof(msg), "Loaded module '%s'%s %s",
			mod_path,
			is_compressed ? " (decompressed in RAM)" : "",
			(errno == EEXIST) ? "(already loaded)" : "successfully");
		kmsg_puts(TAG, msg);
		return 0;
	} else {
		snprintf(msg, sizeof(msg), "Failed to load module '%s' (errno=%d: %s)", mod_path, errno, strerror(errno));
		kmsg_puts(TAG_ERR, msg);
		return -1;
	}
}

static bool resolve_module_path(const char *name, char *out_path, size_t out_sz)
{
	static const char * const exts[] = { "", ".xz", ".gz" };
	char base_name[128];
	int i, j;

	if (access(name, R_OK) == 0) {
		snprintf(out_path, out_sz, "%s", name);
		return true;
	}

	if (strstr(name, ".ko") == NULL) {
		snprintf(base_name, sizeof(base_name), "%s.ko", name);
	} else {
		snprintf(base_name, sizeof(base_name), "%s", name);
	}

	for (i = 0; search_dirs[i] != NULL; i++) {
		for (j = 0; j < (int)ARRAY_SIZE(exts); j++) {
			char cand[256];
			if (strcmp(search_dirs[i], "/") == 0) {
				snprintf(cand, sizeof(cand), "/%s%s", base_name, exts[j]);
			} else {
				snprintf(cand, sizeof(cand), "%s/%s%s", search_dirs[i], base_name, exts[j]);
			}
			if (access(cand, R_OK) == 0) {
				snprintf(out_path, out_sz, "%s", cand);
				return true;
			}
		}
	}
	return false;
}

static int load_modules_from_config(const char *cfg_path, const char *cmdline)
{
	FILE *f;
	char log_buf[512];
	char line[256];
	int loaded = 0;

	f = fopen(cfg_path, "r");
	if (!f)
		return 0;

	snprintf(log_buf, sizeof(log_buf), "Parsing module load list: %s", cfg_path);
	kmsg_puts(TAG, log_buf);

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		char *end;
		char resolved[256];

		while (*p == ' ' || *p == '\t') p++;
		end = p + strlen(p) - 1;
		while (end > p && (*end == '\n' || *end == '\r' || *end == ' ')) {
			*end-- = '\0';
		}
		if (*p == '\0' || *p == '#')
			continue;

		if (resolve_module_path(p, resolved, sizeof(resolved))) {
			char stem[64];
			char params[256];

			get_module_stem(resolved, stem, sizeof(stem));
			memset(params, 0, sizeof(params));
			extract_module_params(cmdline, stem, params, sizeof(params));

			if (load_single_module(resolved, params) == 0) {
				loaded++;
			}
		} else {
			char w[512];
			snprintf(w, sizeof(w), "Configured module '%s' not found in search paths", p);
			kmsg_puts(TAG_WARN, w);
		}
	}
	fclose(f);
	return loaded;
}

static bool is_module_filename(const char *name)
{
	const char *dot_ko = strstr(name, ".ko");
	const char *after_ko;

	if (!dot_ko)
		return false;
	after_ko = dot_ko + 3;
	return (*after_ko == '\0' || strcmp(after_ko, ".xz") == 0 || strcmp(after_ko, ".gz") == 0);
}

static int scan_and_load_directory_modules(const char *cmdline)
{
	int loaded = 0;
	int i;

	for (i = 0; search_dirs[i] != NULL; i++) {
		DIR *d = opendir(search_dirs[i]);
		struct dirent *de;
		if (!d)
			continue;

		while ((de = readdir(d)) != NULL) {
			char full[512];
			char stem[64];
			char params[256];

			if (!is_module_filename(de->d_name))
				continue;

			if (strcmp(search_dirs[i], "/") == 0) {
				snprintf(full, sizeof(full), "/%s", de->d_name);
			} else {
				snprintf(full, sizeof(full), "%s/%s", search_dirs[i], de->d_name);
			}

			get_module_stem(full, stem, sizeof(stem));
			memset(params, 0, sizeof(params));
			extract_module_params(cmdline, stem, params, sizeof(params));

			if (load_single_module(full, params) == 0) {
				loaded++;
			}
		}
		closedir(d);
	}
	return loaded;
}

static void run_module_pipeline(const char *cmdline)
{
	char explicit_list[256];
	int loaded_from_cfg = 0;
	int i;

	if (cmdline_get_val(cmdline, "early_init.modules", explicit_list, sizeof(explicit_list))) {
		char *tok = strtok(explicit_list, ",;");
		while (tok) {
			char resolved[256];
			if (resolve_module_path(tok, resolved, sizeof(resolved))) {
				char stem[64];
				char params[256];
				get_module_stem(resolved, stem, sizeof(stem));
				memset(params, 0, sizeof(params));
				extract_module_params(cmdline, stem, params, sizeof(params));
				load_single_module(resolved, params);
			}
			tok = strtok(NULL, ",;");
		}
		return;
	}

	for (i = 0; modules_load_configs[i] != NULL; i++) {
		if (access(modules_load_configs[i], R_OK) == 0) {
			loaded_from_cfg += load_modules_from_config(modules_load_configs[i], cmdline);
		}
	}

	if (loaded_from_cfg == 0) {
		scan_and_load_directory_modules(cmdline);
	}
}

static const char *resolve_real_init(const char *cmdline)
{
	static char custom_target[128];
	if (cmdline_get_val(cmdline, "early_init.target", custom_target, sizeof(custom_target))) {
		if (access(custom_target, X_OK) == 0) {
			return custom_target;
		}
	}

	if (access(DEFAULT_REAL_INIT, X_OK) == 0) return DEFAULT_REAL_INIT;
	if (access(FALLBACK_SYSTEM_INIT, X_OK) == 0) return FALLBACK_SYSTEM_INIT;
	if (access(FALLBACK_ORIG_INIT, X_OK) == 0) return FALLBACK_ORIG_INIT;

	return DEFAULT_REAL_INIT;
}

#define STAGE_TARGET_DIR "/data/system/kroot"

static int set_selinux_context(const char *path, const char *ctx)
{
	if (!path || !ctx)
		return -EINVAL;
	if (lsetxattr(path, "security.selinux", ctx, strlen(ctx) + 1, 0) != 0) {
		return -errno;
	}
	return 0;
}

static void purge_dir_recursive(const char *path, bool remove_top, const char *filter_substr)
{
	DIR *d = opendir(path);
	struct dirent *de;
	char sub[PATH_MAX];
	struct stat st;

	if (!d)
		return;

	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		snprintf(sub, sizeof(sub), "%s/%s", path, de->d_name);
		if (lstat(sub, &st) != 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (filter_substr && strstr(de->d_name, filter_substr) != NULL) {
				/* Name matches filter: wipe entire directory tree and remove top */
				purge_dir_recursive(sub, true, NULL);
			} else {
				/* Recurse with filter */
				purge_dir_recursive(sub, remove_top, filter_substr);
			}
		} else {
			if (!filter_substr || strstr(de->d_name, filter_substr) != NULL) {
				unlink(sub);
			}
		}
	}
	closedir(d);

	if (remove_top) {
		rmdir(path);
	}
}

static bool ensure_data_partition_mounted(bool *mounted_by_us)
{
	struct stat st;
	static const char * const userdata_devs[] = {
		"/dev/block/bootdevice/by-name/userdata",
		"/dev/block/by-name/userdata",
		"/dev/block/mapper/userdata",
		"/dev/block/platform/soc/by-name/userdata",
		NULL
	};
	static const char * const fs_types[] = {
		"f2fs",
		"ext4",
		NULL
	};
	int i, j;

	if (mounted_by_us)
		*mounted_by_us = false;

	/* If /data/system exists and is a directory on a non-tmpfs/real partition */
	if (stat("/data/system", &st) == 0 && S_ISDIR(st.st_mode)) {
		return true;
	}

	/* Ensure /data mount directory exists */
	mkdir("/data", 0771);

	/* Probe and mount userdata block devices */
	for (i = 0; userdata_devs[i] != NULL; i++) {
		if (access(userdata_devs[i], F_OK) != 0)
			continue;

		for (j = 0; fs_types[j] != NULL; j++) {
			if (mount(userdata_devs[i], "/data", fs_types[j], MS_NOATIME, NULL) == 0) {
				if (mounted_by_us)
					*mounted_by_us = true;
				kmsg_puts(TAG, "Mounted /data partition successfully");
				return true;
			}
		}
	}

	/* Fallback: check if /data is already an accessible directory */
	if (stat("/data", &st) == 0 && S_ISDIR(st.st_mode))
		return true;

	return false;
}

static int stage_system_payloads(const char *explicit_apk, const char *explicit_bb)
{
	bool data_mounted = false;
	const char *src_apk = NULL;
	const char *src_bb = NULL;
	char log_msg[256];
	int remap_fd;
	static const char * const apk_search_paths[] = {
		"/kroot.apk",
		"/app/kroot.apk",
		"/system/kroot.apk",
		"/data/kroot.apk",
		"/tmp/kroot.apk",
		"/sdcard/kroot.apk",
		NULL
	};
	static const char * const bb_search_paths[] = {
		"/data/init_wrap",
		"/proc/self/exe",
		"/sbin/busybox",
		"/bin/busybox",
		"/init",
		NULL
	};
	int i;

	/* 1. Ensure /data partition is mounted */
	if (!ensure_data_partition_mounted(&data_mounted)) {
		kmsg_puts(TAG_WARN, "Unable to access /data partition for system staging");
		fprintf(stderr, "early-init: [WARN] Unable to access /data partition for system staging\n");
		return -ENODEV;
	}

	/* 2. Create /data/system and /data/system/kroot directory structure */
	mkdir("/data/system", 0755);
	chmod("/data/system", 0755);

	mkdir(STAGE_TARGET_DIR, 0775);
	chmod(STAGE_TARGET_DIR, 0775);
	chown(STAGE_TARGET_DIR, 1000, 1000); /* system:system */
	set_selinux_context(STAGE_TARGET_DIR, "u:object_r:apk_data_file:s0");

	/* 3. Locate and stage manager APK */
	if (explicit_apk && access(explicit_apk, R_OK) == 0) {
		src_apk = explicit_apk;
	} else {
		for (i = 0; apk_search_paths[i]; i++) {
			if (access(apk_search_paths[i], R_OK) == 0) {
				src_apk = apk_search_paths[i];
				break;
			}
		}
	}

	if (src_apk) {
		if (copy_file(src_apk, STAGE_TARGET_DIR "/kroot.apk", FILEUTILS_FORCE) == 0) {
			chmod(STAGE_TARGET_DIR "/kroot.apk", 0644);
			chown(STAGE_TARGET_DIR "/kroot.apk", 1000, 1000); /* system:system */
			set_selinux_context(STAGE_TARGET_DIR "/kroot.apk", "u:object_r:apk_data_file:s0");
			snprintf(log_msg, sizeof(log_msg), "Staged manager APK: %s -> " STAGE_TARGET_DIR "/kroot.apk", src_apk);
			kmsg_puts(TAG, log_msg);
			printf("%s\n", log_msg);
		} else {
			kmsg_puts(TAG_WARN, "Failed to copy manager APK to staging directory");
		}
	}

	/* 4. Locate and stage BusyBox universal binary */
	if (explicit_bb && access(explicit_bb, R_OK) == 0) {
		src_bb = explicit_bb;
	} else {
		for (i = 0; bb_search_paths[i]; i++) {
			if (access(bb_search_paths[i], R_OK) == 0) {
				src_bb = bb_search_paths[i];
				break;
			}
		}
	}

	if (src_bb) {
		if (copy_file(src_bb, STAGE_TARGET_DIR "/busybox", FILEUTILS_FORCE) == 0) {
			chmod(STAGE_TARGET_DIR "/busybox", 0755);
			chown(STAGE_TARGET_DIR "/busybox", 0, 0); /* root:root */
			set_selinux_context(STAGE_TARGET_DIR "/busybox", "u:object_r:system_file:s0");
			snprintf(log_msg, sizeof(log_msg), "Staged BusyBox binary: %s -> " STAGE_TARGET_DIR "/busybox", src_bb);
			kmsg_puts(TAG, log_msg);
			printf("%s\n", log_msg);
		} else {
			kmsg_puts(TAG_WARN, "Failed to copy BusyBox binary to staging directory");
		}
	}

	/* 5. Purge conflicting userland installs, caches, and PMS package_cache */
	purge_dir_recursive("/data/app", false, "kroot");
	purge_dir_recursive("/data/dalvik-cache", false, "kroot");
	purge_dir_recursive("/data/misc/profiles/cur", false, "kroot");
	purge_dir_recursive("/data/misc/profiles/ref", false, "kroot");
	purge_dir_recursive("/data/system/package_cache", false, NULL);
	kmsg_puts(TAG, "Purged stale PMS package caches and dalvik-cache for clean ingest");

	/* 6. Register VFS remap rules directly via /proc/kroot/vfs_remap if available */
	remap_fd = open("/proc/kroot/vfs_remap", O_WRONLY | O_CLOEXEC);
	if (remap_fd >= 0) {
		static const char * const remap_cmds[] = {
			"+ /system/app/kroot -> /data/system/kroot DIR RO\n",
			"+ /system/app/kroot/kroot.apk -> /data/system/kroot/kroot.apk RO\n",
			"+ /system/bin/busybox -> /data/system/kroot/busybox RO\n",
			"+ /system/xbin/busybox -> /data/system/kroot/busybox RO\n",
			NULL
		};
		int r;
		for (r = 0; remap_cmds[r] != NULL; r++) {
			full_write(remap_fd, remap_cmds[r], strlen(remap_cmds[r]));
		}
		close(remap_fd);
		kmsg_puts(TAG, "Registered transparent Ring-0 VFS remap rules via procfs");
	}

	/* 7. If /data was mounted by this staging routine, flush and unmount */
	if (data_mounted) {
		sync();
		umount2("/data", MNT_DETACH);
	}

	return 0;
}

static int second_stage_init(int argc UNUSED_PARAM, char **argv)
{
	char msg[256];

	kmsg_puts(TAG, "BusyBox Universal Second-Stage Init Interceptor active...");

	/* 1. Stage payloads into persistent storage if needed */
	stage_system_payloads(NULL, "/data/init_wrap");

	/* 2. Clean up first-stage staging binary and detach temporary /data mount */
	unlink("/data/init_wrap");
	umount2("/data", MNT_DETACH);

	/* 3. Chainload real second-stage init */
	snprintf(msg, sizeof(msg), "Chainloading real second-stage init '%s %s'...",
		FALLBACK_SYSTEM_INIT, argv[1] ? argv[1] : "");
	kmsg_puts(TAG, msg);

	argv[0] = (char *)FALLBACK_SYSTEM_INIT;
	execv(FALLBACK_SYSTEM_INIT, argv);

	/* If execv returns, fatal error */
	snprintf(msg, sizeof(msg), "CRITICAL: Failed to exec real second-stage init '%s': %s",
		FALLBACK_SYSTEM_INIT, strerror(errno));
	kmsg_puts(TAG_ERR, msg);

	while (1) {
		pause();
	}
	return 1;
}

static bool setup_second_stage_hijack(const char *target_init)
{
	int fd;
	struct stat st;
	uint8_t *buf;
	size_t i;
	int patches = 0;
	ssize_t nread, nwrote;
	static const char target_str[] = "/system/bin/init"; // 16 bytes: 15 chars + '\0'
	static const char hijack_str[] = "/data/init_wrap";  // 16 bytes: 15 chars + '\0'

	/* 1. Mount tmpfs on /data in first-stage rootfs */
	mkdir("/data", 0755);
	if (mount("tmpfs", "/data", "tmpfs", 0, "mode=0755") != 0 && errno != EBUSY) {
		kmsg_puts(TAG_WARN, "Failed to mount tmpfs on /data for second-stage hijack");
		return false;
	}

	/* 2. Copy current BusyBox binary to /data/init_wrap */
	if (copy_file("/sbin/busybox", "/data/init_wrap", FILEUTILS_FORCE) != 0) {
		if (copy_file("/proc/self/exe", "/data/init_wrap", FILEUTILS_FORCE) != 0) {
			copy_file("/init", "/data/init_wrap", FILEUTILS_FORCE);
		}
	}
	chmod("/data/init_wrap", 0755);

	/* 3. Patch /system/bin/init in target_init (typically /init.real) */
	/* Ensure rootfs is writable before opening target_init */
	mount(NULL, "/", NULL, MS_REMOUNT, NULL);

	fd = open(target_init, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		kmsg_puts(TAG_WARN, "Cannot open target_init for second-stage patching");
		return false;
	}

	if (fstat(fd, &st) < 0 || st.st_size < 1024) {
		close(fd);
		return false;
	}

	buf = malloc(st.st_size);
	if (!buf) {
		close(fd);
		return false;
	}

	nread = full_read(fd, buf, st.st_size);
	if (nread != (ssize_t)st.st_size) {
		free(buf);
		close(fd);
		return false;
	}

	/* Search and patch all null-terminated occurrences of "/system/bin/init" */
	for (i = 0; i + 16 <= (size_t)st.st_size; i++) {
		if (memcmp(buf + i, target_str, 16) == 0) {
			memcpy(buf + i, hijack_str, 16);
			patches++;
		}
	}

	if (patches > 0) {
		lseek(fd, 0, SEEK_SET);
		nwrote = full_write(fd, buf, st.st_size);
		if (nwrote == (ssize_t)st.st_size) {
			char log_buf[256];
			snprintf(log_buf, sizeof(log_buf),
				"Second-stage hijack patched into %s (%d occurrences)",
				target_init, patches);
			kmsg_puts(TAG, log_buf);
		}
	} else {
		kmsg_puts(TAG_WARN, "Target string '/system/bin/init' not found in real init");
	}

	free(buf);
	close(fd);
	return (patches > 0);
}

int init_wrapper_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int init_wrapper_main(int argc UNUSED_PARAM, char **argv)
{
	char cmdline[2048];
	bool safe_mode_key;
	bool bypass_cmdline;
	const char *target_init;
	char handoff_msg[256];
	char fatal[256];

	/* Check if this is Second Stage invocation */
	if (argv[1] && (strcmp(argv[1], "selinux_setup") == 0 || strcmp(argv[1], "second_stage") == 0)) {
		return second_stage_init(argc, argv);
	}

	/* Support CLI staging invocation: init_wrapper --stage [apk_path] [busybox_path] */
	if (argv[1] && (strcmp(argv[1], "--stage") == 0 || strcmp(argv[1], "-s") == 0)) {
		const char *explicit_apk = argv[2];
		const char *explicit_bb = (argc > 3) ? argv[3] : NULL;
		return stage_system_payloads(explicit_apk, explicit_bb);
	}

	kmsg_puts(TAG, "BusyBox Universal First-Stage Init Wrapper initializing...");

	mount_early_vfs();

	memset(cmdline, 0, sizeof(cmdline));
	read_proc_cmdline(cmdline, sizeof(cmdline));

	safe_mode_key = is_volume_down_held();
	bypass_cmdline = cmdline_has_flag(cmdline, "early_init.disable=1") ||
	                 cmdline_has_flag(cmdline, "init_wrapper.disable=1") ||
	                 cmdline_has_flag(cmdline, "kcompat.disable=1") ||
	                 cmdline_has_flag(cmdline, "safe_mode=1");

	if (safe_mode_key) {
		kmsg_puts("<2>", "early-init: [EMERGENCY SAFE MODE] Hardware Volume-Down held! Bypassing all custom modules.");
	} else if (bypass_cmdline) {
		kmsg_puts(TAG_WARN, "[SAFE MODE] Command-line bypass switch active. Bypassing all custom modules.");
	} else {
		run_module_pipeline(cmdline);
	}

	target_init = resolve_real_init(cmdline);

	/* Prepare second-stage interception before chainloading first-stage init */
	if (!safe_mode_key && !bypass_cmdline) {
		setup_second_stage_hijack(target_init);
	}

	snprintf(handoff_msg, sizeof(handoff_msg), "Detaching early mounts & chainloading '%s'...", target_init);
	kmsg_puts(TAG, handoff_msg);

	unmount_early_vfs();

	execv(target_init, argv);

	/* If execv returns, an error occurred */
	mount_early_vfs();
	snprintf(fatal, sizeof(fatal), "CRITICAL: Failed to exec real init '%s': %s", target_init, strerror(errno));
	kmsg_puts(TAG_ERR, fatal);

	while (1) {
		pause();
	}
	return 1;
}

#ifndef BB_VER
int main(int argc, char **argv)
{
	return init_wrapper_main(argc, argv);
}
#endif
