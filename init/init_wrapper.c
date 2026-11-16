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

//applet:IF_INIT_WRAPPER(APPLET(init_wrapper, BB_DIR_SBIN, BB_SUID_DROP))
//applet:IF_INIT_WRAPPER(APPLET_ODDNAME(early_init, init_wrapper, BB_DIR_SBIN, BB_SUID_DROP, init_wrapper))

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

static int load_single_module(const char *mod_path, const char *params)
{
	int fd;
	const char *mod_params;
	long ret;
	char msg[256];

	fd = open(mod_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(msg, sizeof(msg), "Failed to open module '%s': %s", mod_path, strerror(errno));
		kmsg_puts(TAG_WARN, msg);
		return -1;
	}

	mod_params = params ? params : "";
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

	if (ret == 0 || errno == EEXIST) {
		snprintf(msg, sizeof(msg), "Loaded module '%s' %s", mod_path, (errno == EEXIST) ? "(already loaded)" : "successfully");
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
	char file_name[128];
	int i;

	if (access(name, R_OK) == 0) {
		snprintf(out_path, out_sz, "%s", name);
		return true;
	}

	if (strstr(name, ".ko") == NULL) {
		snprintf(file_name, sizeof(file_name), "%s.ko", name);
	} else {
		snprintf(file_name, sizeof(file_name), "%s", name);
	}

	for (i = 0; search_dirs[i] != NULL; i++) {
		char cand[256];
		if (strcmp(search_dirs[i], "/") == 0) {
			snprintf(cand, sizeof(cand), "/%s", file_name);
		} else {
			snprintf(cand, sizeof(cand), "%s/%s", search_dirs[i], file_name);
		}
		if (access(cand, R_OK) == 0) {
			snprintf(out_path, out_sz, "%s", cand);
			return true;
		}
	}
	return false;
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
			char *ext = strstr(de->d_name, ".ko");
			char full[512];
			char stem[64];
			char params[256];

			if (!ext || strcmp(ext, ".ko") != 0)
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

int init_wrapper_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int init_wrapper_main(int argc UNUSED_PARAM, char **argv)
{
	char cmdline[2048];
	bool safe_mode_key;
	bool bypass_cmdline;
	const char *target_init;
	char handoff_msg[256];
	char fatal[256];

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
