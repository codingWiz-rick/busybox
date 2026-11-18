/* vi: set sw=4 ts=4: */
/*
 * displayswitch - Mobile Display Environment Switcher & GPU/Framebuffer Tools
 *
 * Provides zero-dependency display management between Android SurfaceFlinger
 * and Linux mobile desktop environments (Xorg, Phoc, Phosh, Wayland).
 *
 * Supports both modern DRM/KMS (/dev/dri/card0) and legacy FBDEV (/dev/graphics/fb0,
 * /dev/fb0) pipelines with direct test pattern rendering, VRAM manipulation,
 * display kicking, backlight control, and process ownership auditing.
 *
 * Licensed under GPLv2 or later.
 */

//config:config DISPLAYSWITCH
//config:	bool "displayswitch (display switch & GPU/FB tools)"
//config:	default y
//config:	help
//config:	  Mobile display environment switcher and GPU/framebuffer tool.
//config:	  Transitions display ownership between SurfaceFlinger and Linux
//config:	  desktop UI (Xorg/Phoc/Wayland) by managing system_server,
//config:	  SurfaceFlinger, and display locks. Supports DRM/KMS and FBDEV.

//applet:IF_DISPLAYSWITCH(APPLET_NOEXEC(displayswitch, displayswitch, BB_DIR_USR_BIN, BB_SUID_DROP, displayswitch))
//applet:IF_DISPLAYSWITCH(APPLET_NOEXEC(fbswitch, displayswitch, BB_DIR_USR_BIN, BB_SUID_DROP, fbswitch))
//applet:IF_DISPLAYSWITCH(APPLET_NOEXEC(fbtools, displayswitch, BB_DIR_USR_BIN, BB_SUID_DROP, fbtools))

//kbuild:lib-$(CONFIG_DISPLAYSWITCH) += displayswitch.o

//usage:#define displayswitch_trivial_usage
//usage:       "COMMAND [ARGS...]"
//usage:#define displayswitch_full_usage "\n\n"
//usage:       "Mobile display environment switcher and hardware GPU/framebuffer suite\n"
//usage:     "\nCommands:"
//usage:     "\n	status, info     Display hardware info, active owner, resolution, and GPU state"
//usage:     "\n	linux, to-linux  Transition physical screen to Linux (pause system_server & stop SurfaceFlinger)"
//usage:     "\n	android          Transition physical screen back to Android (restore SurfaceFlinger & wake UI)"
//usage:     "\n	test             Render SMPTE 8-color test bars directly to screen"
//usage:     "\n	clear [HEX]      Fill screen with solid color (default: 000000)"
//usage:     "\n	kick             Trigger hardware display controller refresh and unblank"
//usage:     "\n	backlight [PCT]  Get or set screen backlight brightness (0-100% or raw value)"
//usage:     "\n	dump [FILE.ppm]  Capture screen framebuffer to raw PPM image file"
//usage:
//usage:#define fbswitch_trivial_usage displayswitch_trivial_usage
//usage:#define fbswitch_full_usage displayswitch_full_usage
//usage:#define fbtools_trivial_usage displayswitch_trivial_usage
//usage:#define fbtools_full_usage displayswitch_full_usage

#include "libbb.h"
#include <linux/fb.h>
#include <drm/drm.h>
#include <drm/drm_mode.h>
#include <sys/mman.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#ifndef FBIOBLANK
#define FBIOBLANK 0x4611
#endif
#ifndef FB_BLANK_UNBLANK
#define FB_BLANK_UNBLANK 0
#endif
#ifndef FB_BLANK_POWERDOWN
#define FB_BLANK_POWERDOWN 4
#endif

#ifndef DRM_IOCTL_BASE
#define DRM_IOCTL_BASE 'd'
#endif
#ifndef DRM_IOCTL_MODE_GETRESOURCES
#define DRM_IOCTL_MODE_GETRESOURCES _IOWR(DRM_IOCTL_BASE, 0xA0, struct drm_mode_card_res)
#endif
#ifndef DRM_IOCTL_MODE_GETCONNECTOR
#define DRM_IOCTL_MODE_GETCONNECTOR _IOWR(DRM_IOCTL_BASE, 0xA7, struct drm_mode_get_connector)
#endif
#ifndef DRM_IOCTL_MODE_GETCRTC
#define DRM_IOCTL_MODE_GETCRTC _IOWR(DRM_IOCTL_BASE, 0xA1, struct drm_mode_crtc)
#endif
#ifndef DRM_IOCTL_MODE_CREATE_DUMB
#define DRM_IOCTL_MODE_CREATE_DUMB _IOWR(DRM_IOCTL_BASE, 0xB2, struct drm_mode_create_dumb)
#endif
#ifndef DRM_IOCTL_MODE_MAP_DUMB
#define DRM_IOCTL_MODE_MAP_DUMB _IOWR(DRM_IOCTL_BASE, 0xB3, struct drm_mode_map_dumb)
#endif
#ifndef DRM_IOCTL_MODE_DESTROY_DUMB
#define DRM_IOCTL_MODE_DESTROY_DUMB _IOWR(DRM_IOCTL_BASE, 0xB4, struct drm_mode_destroy_dumb)
#endif
#ifndef DRM_IOCTL_MODE_ADDFB
#define DRM_IOCTL_MODE_ADDFB _IOWR(DRM_IOCTL_BASE, 0xAE, struct drm_mode_fb_cmd)
#endif
#ifndef DRM_IOCTL_MODE_RMFB
#define DRM_IOCTL_MODE_RMFB _IOWR(DRM_IOCTL_BASE, 0xAF, unsigned int)
#endif
#ifndef DRM_IOCTL_MODE_SETCRTC
#define DRM_IOCTL_MODE_SETCRTC _IOWR(DRM_IOCTL_BASE, 0xA2, struct drm_mode_crtc)
#endif

/* ==============================================================================
 * Section 1: Helper Primitives & Hardware Discovery
 * ============================================================================== */

static const char *get_backlight_path(void)
{
	static const char *paths[] = {
		"/sys/class/leds/lcd-backlight/brightness",
		"/sys/class/backlight/panel0-backlight/brightness",
		NULL
	};
	int i;

	for (i = 0; paths[i]; i++) {
		if (access(paths[i], W_OK) == 0)
			return paths[i];
	}

	/* Fallback: scan /sys/class/backlight directory */
	{
		DIR *d = opendir("/sys/class/backlight");
		if (d) {
			struct dirent *de;
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] != '.') {
					char *found = xasprintf("/sys/class/backlight/%s/brightness", de->d_name);
					closedir(d);
					return found;
				}
			}
			closedir(d);
		}
	}

	return paths[0];
}

static int get_backlight_max(const char *bright_path)
{
	char max_path[256];
	char *slash;
	FILE *f;
	int max_val = 255;

	strncpy(max_path, bright_path, sizeof(max_path) - 1);
	max_path[sizeof(max_path) - 1] = '\0';
	slash = strrchr(max_path, '/');
	if (slash) {
		strcpy(slash + 1, "max_brightness");
		f = fopen(max_path, "r");
		if (f) {
			if (fscanf(f, "%d", &max_val) != 1 || max_val <= 0)
				max_val = 255;
			fclose(f);
		}
	}
	return max_val;
}

static int read_backlight(int *out_max)
{
	const char *path = get_backlight_path();
	int max_val = get_backlight_max(path);
	FILE *f = fopen(path, "r");
	int val = -1;

	if (f) {
		if (fscanf(f, "%d", &val) != 1)
			val = -1;
		fclose(f);
	}
	if (out_max)
		*out_max = max_val;
	return val;
}

static int set_backlight(int val)
{
	const char *path = get_backlight_path();
	FILE *f = fopen(path, "w");
	if (!f)
		return -1;
	fprintf(f, "%d\n", val);
	fclose(f);
	return 0;
}

static pid_t disp_find_pid(const char *name)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	pid_t found = -1;

	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		pid_t pid;
		char comm_path[64], comm[64];
		int fd;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		pid = (pid_t)atoi(de->d_name);
		if (pid <= 1)
			continue;

		snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
		fd = open(comm_path, O_RDONLY);
		if (fd >= 0) {
			ssize_t n = read(fd, comm, sizeof(comm) - 1);
			close(fd);
			if (n > 0) {
				char *nl;
				comm[n] = '\0';
				nl = strchr(comm, '\n');
				if (nl)
					*nl = '\0';
				if (strcmp(comm, name) == 0) {
					found = pid;
					break;
				}
			}
		}
	}
	closedir(d);
	return found;
}

static char get_process_state(pid_t pid)
{
	char stat_path[64];
	char buf[256];
	int fd;

	snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", (int)pid);
	fd = open(stat_path, O_RDONLY);
	if (fd < 0)
		return '?';

	if (read(fd, buf, sizeof(buf) - 1) > 0) {
		char *close_paren = strrchr(buf, ')');
		close(fd);
		if (close_paren && *(close_paren + 1) == ' ')
			return *(close_paren + 2);
	} else {
		close(fd);
	}
	return '?';
}

static int get_drm_sysfs_info(char *conn_name, size_t conn_sz, char *mode_str, size_t mode_sz)
{
	DIR *d = opendir("/sys/class/drm");
	struct dirent *de;
	int found = 0;

	if (!d)
		return 0;

	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "card0-", 6) == 0) {
			char path[PATH_MAX];
			char status[32];
			FILE *f;

			snprintf(path, sizeof(path), "/sys/class/drm/%s/status", de->d_name);
			f = fopen(path, "r");
			if (f) {
				if (fgets(status, sizeof(status), f)) {
					char *nl = strchr(status, '\n');
					if (nl)
						*nl = '\0';
					if (strcmp(status, "connected") == 0) {
						if (conn_name)
							safe_strncpy(conn_name, de->d_name + 6, conn_sz);
						fclose(f);

						snprintf(path, sizeof(path), "/sys/class/drm/%s/modes", de->d_name);
						f = fopen(path, "r");
						if (f) {
							if (fgets(mode_str, mode_sz, f)) {
								nl = strchr(mode_str, '\n');
								if (nl)
									*nl = '\0';
							}
							fclose(f);
						}
						found = 1;
						break;
					}
				}
				fclose(f);
			}
		}
	}
	closedir(d);
	return found;
}

static pid_t get_display_holder(char *out_comm, size_t comm_sz)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	pid_t holder_pid = -1;

	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		pid_t pid;
		char fd_dir[64];
		DIR *fdd;
		struct dirent *fde;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		pid = (pid_t)atoi(de->d_name);
		if (pid <= 1)
			continue;

		snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
		fdd = opendir(fd_dir);
		if (!fdd)
			continue;

		while ((fde = readdir(fdd)) != NULL) {
			char fpath[PATH_MAX];
			char link_target[PATH_MAX];
			ssize_t len;

			if (fde->d_name[0] == '.')
				continue;
			snprintf(fpath, sizeof(fpath), "/proc/%d/fd/%s", pid, fde->d_name);
			len = readlink(fpath, link_target, sizeof(link_target) - 1);
			if (len > 0) {
				link_target[len] = '\0';
				if (strstr(link_target, "card0") || strstr(link_target, "fb0")) {
					holder_pid = pid;
					if (out_comm) {
						char comm_path[PATH_MAX];
						int cfd;
						out_comm[0] = '\0';
						snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
						cfd = open(comm_path, O_RDONLY);
						if (cfd >= 0) {
							ssize_t n = read(cfd, out_comm, comm_sz - 1);
							close(cfd);
							if (n > 0) {
								char *nl;
								out_comm[n] = '\0';
								nl = strchr(out_comm, '\n');
								if (nl)
									*nl = '\0';
							}
						}
					}
					break;
				}
			}
		}
		closedir(fdd);
		if (holder_pid > 0)
			break;
	}
	closedir(d);
	return holder_pid;
}

static bool is_display_held(const char *target_comm)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	bool held = false;

	if (!d)
		return false;

	while ((de = readdir(d)) != NULL) {
		pid_t pid;
		char fd_dir[64];
		DIR *fdd;
		struct dirent *fde;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		pid = (pid_t)atoi(de->d_name);
		if (pid <= 1)
			continue;

		if (target_comm) {
			char comm[64], comm_path[64];
			int cfd;

			snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
			cfd = open(comm_path, O_RDONLY);
			if (cfd >= 0) {
				ssize_t n = read(cfd, comm, sizeof(comm) - 1);
				close(cfd);
				if (n > 0) {
					char *nl;
					comm[n] = '\0';
					nl = strchr(comm, '\n');
					if (nl)
						*nl = '\0';
					if (strcmp(comm, target_comm) != 0 && strstr(comm, target_comm) == NULL)
						continue;
				} else {
					continue;
				}
			} else {
				continue;
			}
		}

		snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
		fdd = opendir(fd_dir);
		if (!fdd)
			continue;

		while ((fde = readdir(fdd)) != NULL) {
			char fpath[PATH_MAX];
			char link_target[PATH_MAX];
			ssize_t len;

			if (fde->d_name[0] == '.')
				continue;
			snprintf(fpath, sizeof(fpath), "/proc/%d/fd/%s", pid, fde->d_name);
			len = readlink(fpath, link_target, sizeof(link_target) - 1);
			if (len > 0) {
				link_target[len] = '\0';
				if (strstr(link_target, "fb0") || strstr(link_target, "card0")) {
					held = true;
					break;
				}
			}
		}
		closedir(fdd);
		if (held)
			break;
	}
	closedir(d);
	return held;
}

static int run_cmd_quiet(const char *cmd, ...)
{
	va_list ap;
	const char *argv[32];
	int idx = 0;
	pid_t pid;
	int status = 0;

	argv[idx++] = cmd;
	va_start(ap, cmd);
	while (idx < 30) {
		const char *arg = va_arg(ap, const char *);
		if (!arg)
			break;
		argv[idx++] = arg;
	}
	va_end(ap);
	argv[idx] = NULL;

	pid = fork();
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execvp(cmd, (char *const *)argv);
		_exit(127);
	}
	if (pid < 0)
		return -1;

	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ==============================================================================
 * Section 2: Low-Level Framebuffer & DRM Graphics Pipeline
 * ============================================================================== */

static int open_fb_device(void)
{
	static const char *fb_paths[] = {
		"/dev/graphics/fb0",
		"/dev/fb0",
		NULL
	};
	int i;

	for (i = 0; fb_paths[i]; i++) {
		int fd = open(fb_paths[i], O_RDWR | O_CLOEXEC);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int open_drm_device(void)
{
	int fd = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
	return fd;
}

/* SMPTE 8-color test bar generator */
static uint32_t smpte_pixel_color(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
	static const uint32_t smpte_bars[8] = {
		0x00FFFFFF, /* White   */
		0x00FFFF00, /* Yellow  */
		0x0000FFFF, /* Cyan    */
		0x0000FF00, /* Green   */
		0x00FF00FF, /* Magenta */
		0x00FF0000, /* Red     */
		0x000000FF, /* Blue    */
		0x00000000  /* Black   */
	};

	if (y < (h * 3) / 4) {
		uint32_t bar = (x * 8) / (w ? w : 1);
		if (bar > 7)
			bar = 7;
		return smpte_bars[bar];
	} else {
		/* Bottom 25%: Grayscale ramp in 8 steps */
		uint32_t step = (x * 8) / (w ? w : 1);
		uint32_t val;
		if (step > 7)
			step = 7;
		val = (step * 255) / 7;
		return (val << 16) | (val << 8) | val;
	}
}

static int fbdev_draw_pattern(uint32_t solid_color, bool is_test)
{
	int fd = open_fb_device();
	struct fb_fix_screeninfo finfo;
	struct fb_var_screeninfo vinfo;
	size_t fb_size;
	uint8_t *fb_mem;
	uint32_t y, x;

	if (fd < 0)
		return -1;

	if (ioctl(fd, FBIOGET_FSCREENINFO, &finfo) < 0 ||
	    ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) < 0) {
		close(fd);
		return -1;
	}

	fb_size = finfo.smem_len;
	if (fb_size == 0)
		fb_size = (size_t)vinfo.yres_virtual * finfo.line_length;
	if (fb_size == 0) {
		close(fd);
		return -1;
	}

	fb_mem = mmap(NULL, fb_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (fb_mem == MAP_FAILED) {
		close(fd);
		return -1;
	}

	ioctl(fd, FBIOBLANK, FB_BLANK_UNBLANK);

	for (y = 0; y < vinfo.yres; y++) {
		uint32_t *row32 = (uint32_t *)(fb_mem + (y * finfo.line_length));
		uint16_t *row16 = (uint16_t *)(fb_mem + (y * finfo.line_length));

		for (x = 0; x < vinfo.xres; x++) {
			uint32_t c = is_test ? smpte_pixel_color(x, y, vinfo.xres, vinfo.yres) : solid_color;
			if (vinfo.bits_per_pixel == 32) {
				row32[x] = c;
			} else if (vinfo.bits_per_pixel == 16) {
				/* RGB565 */
				uint16_t r5 = (uint16_t)((c >> 19) & 0x1F);
				uint16_t g6 = (uint16_t)((c >> 10) & 0x3F);
				uint16_t b5 = (uint16_t)((c >> 3) & 0x1F);
				row16[x] = (uint16_t)((r5 << 11) | (g6 << 5) | b5);
			}
		}
	}

	msync(fb_mem, fb_size, MS_SYNC);
	munmap(fb_mem, fb_size);

	ioctl(fd, FBIOPAN_DISPLAY, &vinfo);
	close(fd);
	return 0;
}

static int drm_draw_pattern(uint32_t solid_color, bool is_test)
{
	int fd = open_drm_device();
	struct drm_mode_card_res res;
	uint32_t crtc_id = 0, conn_id = 0;
	struct drm_mode_crtc crtc;
	struct drm_mode_create_dumb creq;
	struct drm_mode_map_dumb mreq;
	struct drm_mode_fb_cmd fb_cmd;
	void *map_ptr;
	uint32_t x, y;
	uint32_t width, height;

	if (fd < 0)
		return -1;

	memset(&res, 0, sizeof(res));
	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
		close(fd);
		return -1;
	}

	if (res.count_crtcs > 0) {
		uint32_t *crtcs = xzalloc(res.count_crtcs * sizeof(uint32_t));
		res.crtc_id_ptr = (uint64_t)(uintptr_t)crtcs;
		if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0 && res.count_crtcs > 0)
			crtc_id = crtcs[0];
		free(crtcs);
	}

	if (res.count_connectors > 0) {
		uint32_t *conns = xzalloc(res.count_connectors * sizeof(uint32_t));
		res.connector_id_ptr = (uint64_t)(uintptr_t)conns;
		if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0 && res.count_connectors > 0)
			conn_id = conns[0];
		free(conns);
	}

	if (!crtc_id) {
		close(fd);
		return -1;
	}

	memset(&crtc, 0, sizeof(crtc));
	crtc.crtc_id = crtc_id;
	if (ioctl(fd, DRM_IOCTL_MODE_GETCRTC, &crtc) < 0 || crtc.mode_valid == 0) {
		close(fd);
		return -1;
	}

	width = crtc.mode.hdisplay;
	height = crtc.mode.vdisplay;
	if (!width || !height) {
		close(fd);
		return -1;
	}

	memset(&creq, 0, sizeof(creq));
	creq.width = width;
	creq.height = height;
	creq.bpp = 32;

	if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &creq) < 0) {
		close(fd);
		return -1;
	}

	memset(&fb_cmd, 0, sizeof(fb_cmd));
	fb_cmd.width = width;
	fb_cmd.height = height;
	fb_cmd.pitch = creq.pitch;
	fb_cmd.bpp = creq.bpp;
	fb_cmd.depth = 24;
	fb_cmd.handle = creq.handle;

	if (ioctl(fd, DRM_IOCTL_MODE_ADDFB, &fb_cmd) < 0) {
		ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &creq.handle);
		close(fd);
		return -1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.handle = creq.handle;
	if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq) < 0) {
		ioctl(fd, DRM_IOCTL_MODE_RMFB, &fb_cmd.fb_id);
		ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &creq.handle);
		close(fd);
		return -1;
	}

	map_ptr = mmap(NULL, creq.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)mreq.offset);
	if (map_ptr == MAP_FAILED) {
		ioctl(fd, DRM_IOCTL_MODE_RMFB, &fb_cmd.fb_id);
		ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &creq.handle);
		close(fd);
		return -1;
	}

	for (y = 0; y < height; y++) {
		uint32_t *row = (uint32_t *)((uint8_t *)map_ptr + (y * creq.pitch));
		for (x = 0; x < width; x++) {
			row[x] = is_test ? smpte_pixel_color(x, y, width, height) : solid_color;
		}
	}

	msync(map_ptr, creq.size, MS_SYNC);
	munmap(map_ptr, creq.size);

	/* Set CRTC to display the dumb buffer */
	crtc.fb_id = fb_cmd.fb_id;
	crtc.set_connectors_ptr = (uint64_t)(uintptr_t)&conn_id;
	crtc.count_connectors = conn_id ? 1 : 0;
	ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &crtc);

	close(fd);
	return 0;
}

/* ==============================================================================
 * Section 3: Subcommand Implementations
 * ============================================================================== */

static int do_status(void)
{
	int fd_drm = open_drm_device();
	int fd_fb = open_fb_device();
	pid_t pid_sf = disp_find_pid("surfaceflinger");
	pid_t pid_hwc = disp_find_pid("composer-servic");
	pid_t pid_ss = disp_find_pid("system_server");
	pid_t pid_xorg = disp_find_pid("Xorg");
	pid_t pid_phoc = disp_find_pid("phoc");
	int bl_max = 255;
	int bl_cur = read_backlight(&bl_max);

	if (pid_hwc < 0)
		pid_hwc = disp_find_pid("vendor.qti.hardware.display.composer-service");
	if (pid_hwc < 0)
		pid_hwc = disp_find_pid("android.hardware.graphics.composer@2.1-service");
	if (pid_hwc < 0)
		pid_hwc = disp_find_pid("vendor.hwcomposer-2-1");

	puts("\n=== Mobile Display Hardware & Subsystem Status ===");

	/* 1. Active Display Pipeline */
	if (fd_drm >= 0) {
		bool got_res = false;
		struct drm_mode_card_res res;
		memset(&res, 0, sizeof(res));
		if (ioctl(fd_drm, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0 && res.count_crtcs > 0) {
			uint32_t crtc_id = 0;
			uint32_t *crtcs = xzalloc(res.count_crtcs * sizeof(uint32_t));
			res.crtc_id_ptr = (uint64_t)(uintptr_t)crtcs;
			if (ioctl(fd_drm, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0)
				crtc_id = crtcs[0];
			free(crtcs);

			if (crtc_id) {
				struct drm_mode_crtc crtc;
				memset(&crtc, 0, sizeof(crtc));
				crtc.crtc_id = crtc_id;
				if (ioctl(fd_drm, DRM_IOCTL_MODE_GETCRTC, &crtc) == 0 && crtc.mode_valid) {
					printf("  Pipeline:    DRM/KMS (/dev/dri/card0)\n");
					printf("  Resolution:  %ux%u @ %u Hz (DRM mode: %s)\n",
					       crtc.mode.hdisplay, crtc.mode.vdisplay,
					       crtc.mode.vrefresh, crtc.mode.name);
					got_res = true;
				}
			}
		}

		if (!got_res) {
			char conn[64];
			char mode[64];
			unsigned w = 0, h = 0, hz = 60;
			conn[0] = '\0';
			mode[0] = '\0';
			printf("  Pipeline:    DRM/KMS (/dev/dri/card0)\n");
			if (get_drm_sysfs_info(conn, sizeof(conn), mode, sizeof(mode)) && mode[0]) {
				if (sscanf(mode, "%ux%ux%u", &w, &h, &hz) >= 2) {
					printf("  Resolution:  %ux%u @ %u Hz (Connector: %s, mode: %s)\n",
					       w, h, hz, conn[0] ? conn : "DSI-1", mode);
				} else {
					printf("  Resolution:  %s (Connector: %s)\n", mode, conn[0] ? conn : "DSI-1");
				}
			} else {
				printf("  Resolution:  [DRM Master lock active on card0]\n");
			}
		}
		close(fd_drm);
	} else if (fd_fb >= 0) {
		struct fb_fix_screeninfo finfo;
		struct fb_var_screeninfo vinfo;
		if (ioctl(fd_fb, FBIOGET_FSCREENINFO, &finfo) == 0 &&
		    ioctl(fd_fb, FBIOGET_VSCREENINFO, &vinfo) == 0) {
			printf("  Pipeline:    FBDEV (%s)\n", finfo.id[0] ? finfo.id : "/dev/graphics/fb0");
			printf("  Resolution:  %ux%u @ %u bpp (stride: %u bytes)\n",
			       vinfo.xres, vinfo.yres, vinfo.bits_per_pixel, finfo.line_length);
			printf("  Virtual:     %ux%u (panning: %u,%u)\n",
			       vinfo.xres_virtual, vinfo.yres_virtual, vinfo.xoffset, vinfo.yoffset);
			printf("  VRAM Buffer: %.2f MB (%u bytes)\n",
			       (double)finfo.smem_len / (1024.0 * 1024.0), finfo.smem_len);
		}
		close(fd_fb);
	} else {
		printf("  Pipeline:    [NO DISPLAY DETECTED]\n");
	}

	/* 2. GPU Nodes */
	printf("  GPU Nodes:   ");
	{
		int g_found = 0;
		if (access("/dev/kgsl-3d0", F_OK) == 0) { printf("/dev/kgsl-3d0 (Adreno) "); g_found++; }
		if (access("/dev/dri/renderD128", F_OK) == 0) { printf("/dev/dri/renderD128 "); g_found++; }
		if (access("/dev/mali0", F_OK) == 0) { printf("/dev/mali0 (Mali) "); g_found++; }
		if (!g_found) printf("none");
		putchar('\n');
	}

	/* 3. Backlight */
	if (bl_cur >= 0) {
		int pct = (bl_max > 0) ? (bl_cur * 100 / bl_max) : 0;
		printf("  Backlight:   %d / %d (%d%%) [%s]\n", bl_cur, bl_max, pct, get_backlight_path());
	} else {
		printf("  Backlight:   [unavailable]\n");
	}

	/* 4. Display Ownership & Process Audit */
	puts("\n=== Display Ownership & Process States ===");
	{
		char holder_comm[64];
		pid_t holder_pid = get_display_holder(holder_comm, sizeof(holder_comm));
		bool sf_holds = is_display_held("surfaceflinger");
		bool xorg_holds = is_display_held("Xorg");
		char ss_state = (pid_ss > 0) ? get_process_state(pid_ss) : ' ';

		if (holder_pid > 0)
			printf("  Display Lock:   PID %-6d [%s] (HOLDING /dev/dri or /dev/fb)\n",
			       (int)holder_pid, holder_comm[0] ? holder_comm : "active");
		else
			printf("  Display Lock:   [FREE / UNLOCKED]\n");

		printf("  SurfaceFlinger: PID %-6d [%s] %s\n",
		       (int)pid_sf,
		       (pid_sf > 0) ? "RUNNING" : "STOPPED",
		       sf_holds ? "(HOLDING DISPLAY LOCK)" : "");

		printf("  system_server:  PID %-6d [%s%s]\n",
		       (int)pid_ss,
		       (pid_ss > 0) ? "RUNNING" : "STOPPED",
		       (ss_state == 'T') ? " (PAUSED via SIGSTOP)" : "");

		if (pid_hwc > 0)
			printf("  HWC Composer:   PID %-6d [RUNNING]%s\n", (int)pid_hwc,
			       (holder_pid == pid_hwc) ? " (HOLDING DISPLAY LOCK)" : "");

		printf("  Linux Desktop:  %s%s%s\n",
		       (pid_phoc > 0) ? "Phoc " : "",
		       (pid_xorg > 0) ? "Xorg " : "",
		       (pid_phoc <= 0 && pid_xorg <= 0) ? "[INACTIVE]" : (xorg_holds ? "(HOLDING DISPLAY LOCK)" : "[RUNNING]"));
	}

	putchar('\n');
	return EXIT_SUCCESS;
}

static int do_kick(void)
{
	int fd_fb = open_fb_device();
	int ret = -1;

	if (fd_fb >= 0) {
		struct fb_var_screeninfo vinfo;
		ioctl(fd_fb, FBIOBLANK, FB_BLANK_UNBLANK);
		if (ioctl(fd_fb, FBIOGET_VSCREENINFO, &vinfo) == 0) {
			ret = ioctl(fd_fb, FBIOPAN_DISPLAY, &vinfo);
		}
		close(fd_fb);
	}

	if (ret < 0) {
		/* Try DRM page-flip / CRTC refresh */
		int fd_drm = open_drm_device();
		if (fd_drm >= 0) {
			ret = drm_draw_pattern(0, false);
			close(fd_drm);
		}
	}

	if (ret == 0)
		puts("[+] Display pipeline kicked and refreshed successfully.");
	else
		bb_error_msg("failed to kick display pipeline");

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int do_test(void)
{
	int ret;

	puts("[*] Rendering SMPTE 8-color test bars directly to hardware VRAM...");

	/* Try DRM dumb buffer first, then FBDEV */
	ret = drm_draw_pattern(0, true);
	if (ret != 0)
		ret = fbdev_draw_pattern(0, true);

	if (ret == 0)
		puts("[+] SMPTE test pattern displayed successfully on physical screen.");
	else
		bb_error_msg("failed to render test pattern to display");

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int do_clear(const char *hex_str)
{
	uint32_t color = 0x000000;
	int ret;

	if (hex_str && hex_str[0]) {
		if (hex_str[0] == '#')
			hex_str++;
		color = (uint32_t)strtoul(hex_str, NULL, 16);
	}

	printf("[*] Clearing VRAM to solid color #%06X...\n", (unsigned)(color & 0xFFFFFF));

	ret = drm_draw_pattern(color, false);
	if (ret != 0)
		ret = fbdev_draw_pattern(color, false);

	if (ret == 0)
		puts("[+] Screen cleared successfully.");
	else
		bb_error_msg("failed to clear display");

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int do_backlight(const char *arg)
{
	int max_val = 255;
	int cur = read_backlight(&max_val);

	if (!arg) {
		int pct = (max_val > 0) ? (cur * 100 / max_val) : 0;
		printf("Backlight: %d / %d (%d%%)\n", cur, max_val, pct);
		return EXIT_SUCCESS;
	}

	{
		int target = atoi(arg);
		int val;

		if (strchr(arg, '%') || target <= 100) {
			if (target < 0) target = 0;
			if (target > 100) target = 100;
			val = (target * max_val) / 100;
		} else {
			if (target < 0) target = 0;
			if (target > max_val) target = max_val;
			val = target;
		}

		if (set_backlight(val) == 0) {
			printf("Backlight set to %d (%d%%)\n", val, (val * 100) / max_val);
			return EXIT_SUCCESS;
		} else {
			bb_perror_msg("failed to write backlight");
			return EXIT_FAILURE;
		}
	}
}

static int do_dump(const char *outfile)
{
	int fd = open_fb_device();
	struct fb_fix_screeninfo finfo;
	struct fb_var_screeninfo vinfo;
	size_t fb_size;
	uint8_t *fb_mem;
	FILE *out_fp;
	uint32_t y, x;

	if (fd < 0)
		bb_error_msg_and_die("can't open framebuffer device for dumping");

	if (ioctl(fd, FBIOGET_FSCREENINFO, &finfo) < 0 ||
	    ioctl(fd, FBIOGET_VSCREENINFO, &vinfo) < 0) {
		close(fd);
		bb_error_msg_and_die("FBIOGET screeninfo failed");
	}

	fb_size = finfo.smem_len;
	if (fb_size == 0)
		fb_size = (size_t)vinfo.yres_virtual * finfo.line_length;

	fb_mem = mmap(NULL, fb_size, PROT_READ, MAP_SHARED, fd, 0);
	if (fb_mem == MAP_FAILED) {
		close(fd);
		bb_error_msg_and_die("mmap VRAM failed");
	}

	out_fp = (outfile && strcmp(outfile, "-") != 0) ? fopen(outfile, "wb") : stdout;
	if (!out_fp) {
		munmap(fb_mem, fb_size);
		close(fd);
		bb_perror_msg_and_die("can't open dump output");
	}

	/* Write standard PPM P6 Header */
	fprintf(out_fp, "P6\n%u %u\n255\n", vinfo.xres, vinfo.yres);

	for (y = 0; y < vinfo.yres; y++) {
		uint32_t *row32 = (uint32_t *)(fb_mem + (y * finfo.line_length));
		for (x = 0; x < vinfo.xres; x++) {
			uint32_t c = row32[x];
			uint8_t rgb[3];
			rgb[0] = (uint8_t)((c >> 16) & 0xFF); /* Red   */
			rgb[1] = (uint8_t)((c >> 8) & 0xFF);  /* Green */
			rgb[2] = (uint8_t)(c & 0xFF);         /* Blue  */
			fwrite(rgb, 1, 3, out_fp);
		}
	}

	if (out_fp != stdout) {
		fclose(out_fp);
		printf("[+] Framebuffer dumped successfully to '%s' (%ux%u PPM).\n", outfile, vinfo.xres, vinfo.yres);
	}

	munmap(fb_mem, fb_size);
	close(fd);
	return EXIT_SUCCESS;
}

static int do_switch_linux(void)
{
	pid_t sspid;
	int elapsed_ms;

	if (getuid() != 0)
		bb_error_msg_and_die("root privileges required to switch display");

	puts("\n======================================================");
	puts("  Mobile Display Environment Switcher: TO LINUX");
	puts("======================================================");

	/* 1. Stop Android Display Services and HALs */
	puts("[*] Stopping Android Display Server and HALs...");
	run_cmd_quiet("stop", "surfaceflinger", NULL);
	run_cmd_quiet("stop", "vendor.qti.hardware.display.composer", NULL);
	run_cmd_quiet("stop", "vendor.hwcomposer-2-1", NULL);
	run_cmd_quiet("stop", "android.hardware.graphics.composer@2.1-service", NULL);
	run_cmd_quiet("stop", "vendor.livedisplay-sdm", NULL);
	run_cmd_quiet("stop", "vendor.livedisplay-sysfs", NULL);
	run_cmd_quiet("stop", "display-color-hal-1-0", NULL);
	run_cmd_quiet("stop", "audioserver", NULL);
	run_cmd_quiet("stop", "vendor.audio-hal", NULL);

	/* 2. Await release of display device by SurfaceFlinger and Composer (up to 3s) */
	puts("[*] Waiting for display device release by SurfaceFlinger and Composer...");
	elapsed_ms = 0;
	while (elapsed_ms < 3000) {
		if (!is_display_held("surfaceflinger") && !is_display_held("composer"))
			break;
		usleep(20000); /* 20ms */
		elapsed_ms += 20;
	}

	if (elapsed_ms < 3000)
		printf("[+] Display device released by Android (waited %.2fs).\n", (double)elapsed_ms / 1000.0);
	else
		puts("[!] Warning: Display device may still have active descriptors.");

	/* 3. Pause system_server AFTER SurfaceFlinger to prevent Watchdog abort */
	sspid = disp_find_pid("system_server");
	if (sspid > 0) {
		kill(sspid, SIGSTOP);
		printf("[+] Paused system_server (PID %d with SIGSTOP) to prevent Watchdog abort.\n", (int)sspid);
	}

	/* 4. Configure LCD backlight and unblank display */
	set_backlight(120);
	puts("[+] Backlight configured (brightness=120).");

	/* 5. Clear VRAM and kick display */
	puts("[*] Clearing VRAM to slate and kicking display controller...");
	do_clear("181818");
	do_kick();

	puts("\n[SUCCESS] Display environment switched to LINUX.");
	puts("          Physical screen is now ready for Xorg / Phoc / Wayland.");
	return EXIT_SUCCESS;
}

static int do_switch_android(void)
{
	pid_t sspid;
	int elapsed_ms;
	bool sf_active;

	if (getuid() != 0)
		bb_error_msg_and_die("root privileges required to switch display");

	puts("\n======================================================");
	puts("  Mobile Display Environment Switcher: TO ANDROID");
	puts("======================================================");

	/* 1. Terminate any running Linux desktop compositors */
	puts("[*] Terminating Linux desktop sessions if running...");
	{
		static const char *const procs[] = { "phoc", "phosh", "squeekboard", "foot", "Xorg", NULL };
		int i;
		for (i = 0; procs[i]; i++) {
			pid_t p = disp_find_pid(procs[i]);
			if (p > 0)
				kill(p, SIGTERM);
		}
		usleep(20000);
	}

	/* 2. Resume system_server via SIGCONT */
	sspid = disp_find_pid("system_server");
	if (sspid > 0) {
		kill(sspid, SIGCONT);
		printf("[+] Resumed system_server (PID %d with SIGCONT).\n", (int)sspid);
	}

	/* 3. Restore Hardware Composer and Display HALs */
	puts("[*] Restoring Hardware Composer & Display HALs...");
	run_cmd_quiet("start", "vendor.qti.hardware.display.composer", NULL);
	run_cmd_quiet("start", "vendor.hwcomposer-2-1", NULL);
	run_cmd_quiet("start", "android.hardware.graphics.composer@2.1-service", NULL);
	run_cmd_quiet("start", "display-color-hal-1-0", NULL);
	run_cmd_quiet("start", "vendor.livedisplay-sdm", NULL);
	run_cmd_quiet("start", "vendor.livedisplay-sysfs", NULL);
	run_cmd_quiet("start", "vendor.audio-hal", NULL);
	run_cmd_quiet("start", "audioserver", NULL);
	usleep(20000);

	/* 4. Restore SurfaceFlinger */
	puts("[*] Restoring SurfaceFlinger display server...");
	run_cmd_quiet("start", "surfaceflinger", NULL);

	sf_active = false;
	elapsed_ms = 0;
	while (elapsed_ms < 6000) {
		if (disp_find_pid("surfaceflinger") > 0) {
			sf_active = true;
			break;
		}
		usleep(20000); /* 20ms */
		elapsed_ms += 20;
	}

	if (sf_active)
		printf("[+] SurfaceFlinger process is active (waited %.2fs).\n", (double)elapsed_ms / 1000.0);
	else
		puts("[-] Warning: SurfaceFlinger PID not detected yet.");

	/* 5. Dismiss boot animation, wake screen, and focus Android home launcher */
	puts("[*] Dismissing lockscreen and focusing Android Home launcher...");
	run_cmd_quiet("setprop", "service.bootanim.exit", "1", NULL);
	run_cmd_quiet("setprop", "ctl.stop", "bootanim", NULL);
	run_cmd_quiet("input", "keyevent", "224", NULL); /* WAKEUP */
	run_cmd_quiet("input", "keyevent", "82", NULL);  /* MENU / unlock */
	run_cmd_quiet("cmd", "statusbar", "collapse", NULL);
	run_cmd_quiet("wm", "dismiss-keyguard", NULL);
	run_cmd_quiet("am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME", NULL);
	run_cmd_quiet("input", "keyevent", "3", NULL);   /* HOME */

	puts("\n[SUCCESS] Android UI restored successfully.");
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 4: Main Dispatcher
 * ============================================================================== */

int displayswitch_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int displayswitch_main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2)
		return do_status();

	cmd = argv[1];

	if (strcmp(cmd, "status") == 0 || strcmp(cmd, "info") == 0)
		return do_status();
	if (strcmp(cmd, "linux") == 0 || strcmp(cmd, "to-linux") == 0)
		return do_switch_linux();
	if (strcmp(cmd, "android") == 0 || strcmp(cmd, "to-android") == 0)
		return do_switch_android();
	if (strcmp(cmd, "kick") == 0)
		return do_kick();
	if (strcmp(cmd, "test") == 0)
		return do_test();
	if (strcmp(cmd, "clear") == 0)
		return do_clear(argc > 2 ? argv[2] : "000000");
	if (strcmp(cmd, "backlight") == 0)
		return do_backlight(argc > 2 ? argv[2] : NULL);
	if (strcmp(cmd, "dump") == 0)
		return do_dump(argc > 2 ? argv[2] : NULL);

	bb_show_usage();
	return EXIT_FAILURE;
}
