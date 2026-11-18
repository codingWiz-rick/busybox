/* vi: set sw=4 ts=4: */
/*
 * gpio_tools.c - Modern Linux Character Device GPIO Suite (/dev/gpiochip*)
 *
 * Applets:
 *   gpiodetect - List all GPIO chips, hardware labels, and line counts
 *   gpioinfo   - Display detailed line information, directions, and consumers
 *   gpioget    - Read logical values (0 or 1) from GPIO lines
 *   gpioset    - Set and drive output values on GPIO lines
 *   gpiomon    - Monitor real-time edge events with timestamps
 *
 * Implements Linux GPIO character device ABI (Linux 4.8+ v1, 5.10+ v2):
 *   - Universal support across Android GKI, Qualcomm SoC pinctrl, and embedded Linux.
 *   - Dual ABI: Prefers GPIO v2 ioctls (GPIO_V2_GET_LINE_IOCTL, GPIO_V2_LINE_*),
 *     automatically falling back to v1 (GPIO_GET_LINEHANDLE_IOCTL) on older kernels.
 *   - Replaces obsolete, deprecated /sys/class/gpio.
 *
 * Copyright (C) 2026 Antigravity (Google DeepMind)
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config GPIODETECT
//config:	bool "gpiodetect (List GPIO chips)"
//config:	default y
//config:	help
//config:	  List all GPIO chips, hardware labels, and line counts.
//config:
//config:config GPIOINFO
//config:	bool "gpioinfo (Inspect GPIO line details)"
//config:	default y
//config:	help
//config:	  Display GPIO line status, direction, flags, and consumers.
//config:
//config:config GPIOGET
//config:	bool "gpioget (Read GPIO line values)"
//config:	default y
//config:	help
//config:	  Read logical values (0 or 1) from GPIO lines.
//config:
//config:config GPIOSET
//config:	bool "gpioset (Set GPIO line output values)"
//config:	default y
//config:	help
//config:	  Set and drive GPIO line output values.
//config:
//config:config GPIOMON
//config:	bool "gpiomon (Monitor GPIO edge events)"
//config:	default y
//config:	help
//config:	  Monitor real-time GPIO edge transitions with timestamps.

//applet:IF_GPIODETECT(APPLET(gpiodetect, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_GPIOINFO(APPLET(gpioinfo, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_GPIOGET(APPLET(gpioget, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_GPIOSET(APPLET(gpioset, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_GPIOMON(APPLET(gpiomon, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_GPIODETECT) += gpio_tools.o
//kbuild:lib-$(CONFIG_GPIOINFO)   += gpio_tools.o
//kbuild:lib-$(CONFIG_GPIOGET)    += gpio_tools.o
//kbuild:lib-$(CONFIG_GPIOSET)    += gpio_tools.o
//kbuild:lib-$(CONFIG_GPIOMON)    += gpio_tools.o

//usage:#define gpiodetect_trivial_usage
//usage:       ""
//usage:#define gpiodetect_full_usage "\n\n"
//usage:       "List all GPIO chips in /dev/gpiochip*\n"

//usage:#define gpioinfo_trivial_usage
//usage:       "[CHIP] [LINE...]"
//usage:#define gpioinfo_full_usage "\n\n"
//usage:       "Display detailed information for lines on specified GPIO chip(s)\n"

//usage:#define gpioget_trivial_usage
//usage:       "[-l] CHIP LINE [LINE...]"
//usage:#define gpioget_full_usage "\n\n"
//usage:       "Read logical values from one or more GPIO lines\n"
//usage:     "\n	-l	Active-low (invert values)"

//usage:#define gpioset_trivial_usage
//usage:       "[-l] [-m MS] [-t] CHIP LINE=VAL [LINE=VAL...]"
//usage:#define gpioset_full_usage "\n\n"
//usage:       "Drive output values on specified GPIO lines\n"
//usage:     "\n	-l	Active-low (invert values)"
//usage:     "\n	-m MS	Hold state for MS milliseconds before exiting (default: 0)"
//usage:     "\n	-t	Toggle values repeatedly every MS milliseconds"

//usage:#define gpiomon_trivial_usage
//usage:       "[-r] [-f] [-l] [-U] [-u DRV[:DEV]] CHIP LINE"
//usage:#define gpiomon_full_usage "\n\n"
//usage:       "Monitor real-time edge transitions on a GPIO line\n"
//usage:     "\n	-r	Rising edge events only"
//usage:     "\n	-f	Falling edge events only"
//usage:     "\n	-l	Active-low"
//usage:     "\n	-U	Auto-unbind in-kernel consumer driver (auto-rebinds on exit)"
//usage:     "\n	-u DRV	Unbind specified driver (auto-rebinds on exit)"

#include "libbb.h"
#include <linux/gpio.h>
#include <dirent.h>

#ifndef GPIO_MAX_NAME_SIZE
#define GPIO_MAX_NAME_SIZE 32
#endif

#ifndef GPIO_V2_LINES_MAX
#define GPIO_V2_LINES_MAX 64
#endif

#ifndef GPIO_V2_LINE_NUM_ATTRS_MAX
#define GPIO_V2_LINE_NUM_ATTRS_MAX 10
#endif

#ifndef GPIO_V2_LINE_FLAG_USED
#define GPIO_V2_LINE_FLAG_USED                  (1ULL << 0)
#define GPIO_V2_LINE_FLAG_ACTIVE_LOW            (1ULL << 1)
#define GPIO_V2_LINE_FLAG_INPUT                 (1ULL << 2)
#define GPIO_V2_LINE_FLAG_OUTPUT                (1ULL << 3)
#define GPIO_V2_LINE_FLAG_EDGE_RISING           (1ULL << 4)
#define GPIO_V2_LINE_FLAG_EDGE_FALLING          (1ULL << 5)
#define GPIO_V2_LINE_FLAG_OPEN_DRAIN            (1ULL << 6)
#define GPIO_V2_LINE_FLAG_OPEN_SOURCE           (1ULL << 7)
#define GPIO_V2_LINE_FLAG_BIAS_PULL_UP          (1ULL << 8)
#define GPIO_V2_LINE_FLAG_BIAS_PULL_DOWN        (1ULL << 9)
#define GPIO_V2_LINE_FLAG_BIAS_DISABLED         (1ULL << 10)
#endif

#ifndef GPIO_GET_CHIPINFO_IOCTL
#define GPIO_GET_CHIPINFO_IOCTL _IOR(0xB4, 0x01, struct gpiochip_info)
#endif

#ifndef GPIO_V2_GET_LINEINFO_IOCTL
#define GPIO_V2_GET_LINEINFO_IOCTL _IOWR(0xB4, 0x05, struct gpio_v2_line_info)
#endif

#ifndef GPIO_V2_GET_LINE_IOCTL
#define GPIO_V2_GET_LINE_IOCTL _IOWR(0xB4, 0x07, struct gpio_v2_line_request)
#endif

#ifndef GPIO_V2_LINE_GET_VALUES_IOCTL
#define GPIO_V2_LINE_GET_VALUES_IOCTL _IOWR(0xB4, 0x0E, struct gpio_v2_line_values)
#define GPIO_V2_LINE_SET_VALUES_IOCTL _IOWR(0xB4, 0x0F, struct gpio_v2_line_values)
#endif

#ifndef GPIO_GET_LINEINFO_IOCTL
#define GPIO_GET_LINEINFO_IOCTL _IOWR(0xB4, 0x02, struct gpioline_info)
#endif

#ifndef GPIO_GET_LINEHANDLE_IOCTL
#define GPIO_GET_LINEHANDLE_IOCTL _IOWR(0xB4, 0x03, struct gpiohandle_request)
#define GPIOHANDLE_GET_LINE_VALUES_IOCTL _IOWR(0xB4, 0x08, struct gpiohandle_data)
#define GPIOHANDLE_SET_LINE_VALUES_IOCTL _IOWR(0xB4, 0x09, struct gpiohandle_data)
#endif

#ifndef GPIO_GET_LINEEVENT_IOCTL
struct gpioevent_request {
	uint32_t lineoffset;
	uint32_t handleflags;
	uint32_t eventflags;
	char consumer_label[GPIO_MAX_NAME_SIZE];
	int fd;
};

#define GPIOEVENT_REQUEST_RISING_EDGE	(1UL << 0)
#define GPIOEVENT_REQUEST_FALLING_EDGE	(1UL << 1)
#define GPIOEVENT_REQUEST_BOTH_EDGES	((1UL << 0) | (1UL << 1))

struct gpioevent_data {
	uint64_t timestamp;
	uint32_t id;
};

#define GPIOEVENT_EVENT_RISING_EDGE 0x01
#define GPIOEVENT_EVENT_FALLING_EDGE 0x02

#define GPIO_GET_LINEEVENT_IOCTL _IOWR(0xB4, 0x04, struct gpioevent_request)
#endif

static char *resolve_chip_path(const char *arg)
{
	if (arg[0] == '/')
		return xstrdup(arg);
	if (strncmp(arg, "gpiochip", 8) == 0)
		return xasprintf("/dev/%s", arg);
	return xasprintf("/dev/gpiochip%s", arg);
}

static int filter_gpiochip(const struct dirent *d)
{
	return (strncmp(d->d_name, "gpiochip", 8) == 0);
}

/* ==============================================================================
 * Section 1: gpiodetect
 * ============================================================================== */

#if ENABLE_GPIODETECT

int gpiodetect_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int gpiodetect_main(int argc UNUSED_PARAM, char **argv UNUSED_PARAM)
{
	struct dirent **namelist;
	int n, i;
	int found = 0;

	n = scandir("/dev", &namelist, filter_gpiochip, alphasort);
	if (n < 0)
		bb_simple_perror_msg_and_die("scandir /dev failed");

	for (i = 0; i < n; i++) {
		char *path = xasprintf("/dev/%s", namelist[i]->d_name);
		int fd = open(path, O_RDONLY);
		if (fd >= 0) {
			struct gpiochip_info cinfo;
			memset(&cinfo, 0, sizeof(cinfo));
			if (ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, &cinfo) == 0) {
				printf("%s [%s] (%u lines)\n",
				       cinfo.name,
				       cinfo.label[0] ? cinfo.label : "unknown",
				       (unsigned)cinfo.lines);
				found++;
			}
			close(fd);
		}
		free(path);
		free(namelist[i]);
	}
	free(namelist);

	if (!found)
		puts("No GPIO chips detected in /dev");

	return EXIT_SUCCESS;
}

#endif /* ENABLE_GPIODETECT */

/* ==============================================================================
 * Section 2: gpioinfo
 * ============================================================================== */

#if ENABLE_GPIOINFO

static void dump_chip_lines(const char *chip_name, int num_targets, char **targets)
{
	char *path = resolve_chip_path(chip_name);
	int fd = open(path, O_RDONLY);
	struct gpiochip_info cinfo;
	int count, idx;

	if (fd < 0) {
		bb_perror_msg("can't open %s", path);
		free(path);
		return;
	}

	memset(&cinfo, 0, sizeof(cinfo));
	if (ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, &cinfo) < 0) {
		bb_perror_msg("can't get chip info for %s", path);
		close(fd);
		free(path);
		return;
	}

	printf("%s - %u lines:\n", cinfo.name, (unsigned)cinfo.lines);

	count = (num_targets > 0) ? num_targets : (int)cinfo.lines;

	for (idx = 0; idx < count; idx++) {
		int l = (num_targets > 0) ? xatoi(targets[idx]) : idx;
		struct gpio_v2_line_info info_v2;
		char flag_buf[128];
		char *fp = flag_buf;
		int rc;

		if (l < 0 || l >= (int)cinfo.lines) {
			bb_error_msg("line %d out of range (max %u)", l, (unsigned)cinfo.lines - 1);
			continue;
		}

		memset(&info_v2, 0, sizeof(info_v2));
		info_v2.offset = (uint32_t)l;

		rc = ioctl(fd, GPIO_V2_GET_LINEINFO_IOCTL, &info_v2);
		if (rc == 0) {
			/* Decode v2 flags */
			fp += sprintf(fp, "[%s", (info_v2.flags & GPIO_V2_LINE_FLAG_USED) ? "used" : "unused");
			if (info_v2.consumer[0])
				fp += sprintf(fp, ", consumer=\"%s\"", info_v2.consumer);
			if (info_v2.flags & GPIO_V2_LINE_FLAG_OUTPUT)
				fp += sprintf(fp, ", output");
			else
				fp += sprintf(fp, ", input");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_ACTIVE_LOW)
				fp += sprintf(fp, ", active-low");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_OPEN_DRAIN)
				fp += sprintf(fp, ", open-drain");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_OPEN_SOURCE)
				fp += sprintf(fp, ", open-source");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_BIAS_PULL_UP)
				fp += sprintf(fp, ", pull-up");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_BIAS_PULL_DOWN)
				fp += sprintf(fp, ", pull-down");
			if (info_v2.flags & GPIO_V2_LINE_FLAG_BIAS_DISABLED)
				fp += sprintf(fp, ", bias-disabled");
			strcat(fp, "]");

			printf("\tline %3u: %16s %s\n",
			       (unsigned)l,
			       info_v2.name[0] ? info_v2.name : "unnamed",
			       flag_buf);
		} else {
			/* Fallback to v1 */
			struct gpioline_info info_v1;
			memset(&info_v1, 0, sizeof(info_v1));
			info_v1.line_offset = (uint32_t)l;

			if (ioctl(fd, GPIO_GET_LINEINFO_IOCTL, &info_v1) == 0) {
				fp += sprintf(fp, "[%s", (info_v1.flags & GPIOLINE_FLAG_IS_OUT) ? "output" : "input");
				if (info_v1.flags & GPIOLINE_FLAG_ACTIVE_LOW)
					fp += sprintf(fp, ", active-low");
				if (info_v1.consumer[0])
					fp += sprintf(fp, ", consumer=\"%s\"", info_v1.consumer);
				strcat(fp, "]");

				printf("\tline %3u: %16s %s\n",
				       (unsigned)l,
				       info_v1.name[0] ? info_v1.name : "unnamed",
				       flag_buf);
			} else {
				printf("\tline %3u: [query error]\n", (unsigned)l);
			}
		}
	}

	close(fd);
	free(path);
}

int gpioinfo_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int gpioinfo_main(int argc, char **argv)
{
	if (argc > 1) {
		const char *chip = argv[1];
		if (argc > 2) {
			dump_chip_lines(chip, argc - 2, argv + 2);
		} else {
			dump_chip_lines(chip, 0, NULL);
		}
	} else {
		struct dirent **namelist;
		int n, i;

		n = scandir("/dev", &namelist, filter_gpiochip, alphasort);
		if (n < 0)
			bb_simple_perror_msg_and_die("scandir /dev failed");

		for (i = 0; i < n; i++) {
			dump_chip_lines(namelist[i]->d_name, 0, NULL);
			free(namelist[i]);
		}
		free(namelist);
	}

	return EXIT_SUCCESS;
}

#endif /* ENABLE_GPIOINFO */

/* ==============================================================================
 * Section 3: gpioget
 * ============================================================================== */

#if ENABLE_GPIOGET

int gpioget_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int gpioget_main(int argc, char **argv)
{
	unsigned opts;
	int active_low = 0;
	const char *chip_name;
	char *path;
	int chip_fd;
	int num_lines;
	uint32_t line_offsets[GPIO_V2_LINES_MAX];
	int i;
	struct gpio_v2_line_request req;
	struct gpio_v2_line_values vals;
	int use_v2 = 1;

	opts = getopt32(argv, "l");
	if (opts & 1) active_low = 1;

	argv += optind;
	argc -= optind;

	if (argc < 2)
		bb_show_usage();

	chip_name = argv[0];
	num_lines = argc - 1;
	if (num_lines > GPIO_V2_LINES_MAX)
		bb_error_msg_and_die("too many lines requested (max %u)", GPIO_V2_LINES_MAX);

	for (i = 0; i < num_lines; i++)
		line_offsets[i] = xatou(argv[i + 1]);

	path = resolve_chip_path(chip_name);
	chip_fd = xopen(path, O_RDONLY);

	/* Try GPIO v2 */
	memset(&req, 0, sizeof(req));
	req.num_lines = (uint32_t)num_lines;
	strncpy(req.consumer, "gpioget", sizeof(req.consumer) - 1);
	req.config.flags = GPIO_V2_LINE_FLAG_INPUT;
	if (active_low)
		req.config.flags |= GPIO_V2_LINE_FLAG_ACTIVE_LOW;

	for (i = 0; i < num_lines; i++)
		req.offsets[i] = line_offsets[i];

	if (ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &req) < 0) {
		use_v2 = 0;
	}

	if (use_v2) {
		memset(&vals, 0, sizeof(vals));
		vals.mask = (num_lines == 64) ? ~0ULL : ((1ULL << num_lines) - 1ULL);
		if (ioctl(req.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &vals) < 0)
			bb_simple_perror_msg_and_die("GPIO_V2_LINE_GET_VALUES_IOCTL failed");

		for (i = 0; i < num_lines; i++)
			printf("%d%c", (int)((vals.bits >> i) & 1ULL), (i == num_lines - 1) ? '\n' : ' ');

		close(req.fd);
	} else {
		/* Fallback to v1 linehandle */
		struct gpiohandle_request hreq;
		struct gpiohandle_data hdata;

		memset(&hreq, 0, sizeof(hreq));
		hreq.lines = (uint32_t)num_lines;
		hreq.flags = GPIOHANDLE_REQUEST_INPUT;
		if (active_low)
			hreq.flags |= GPIOHANDLE_REQUEST_ACTIVE_LOW;
		strncpy(hreq.consumer_label, "gpioget", sizeof(hreq.consumer_label) - 1);

		for (i = 0; i < num_lines; i++)
			hreq.lineoffsets[i] = line_offsets[i];

		if (ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &hreq) < 0)
			bb_simple_perror_msg_and_die("line request failed (v1 and v2)");

		memset(&hdata, 0, sizeof(hdata));
		if (ioctl(hreq.fd, GPIOHANDLE_GET_LINE_VALUES_IOCTL, &hdata) < 0)
			bb_simple_perror_msg_and_die("GPIOHANDLE_GET_LINE_VALUES_IOCTL failed");

		for (i = 0; i < num_lines; i++)
			printf("%d%c", (int)hdata.values[i], (i == num_lines - 1) ? '\n' : ' ');

		close(hreq.fd);
	}

	close(chip_fd);
	free(path);
	return EXIT_SUCCESS;
}

#endif /* ENABLE_GPIOGET */

/* ==============================================================================
 * Section 4: gpioset
 * ============================================================================== */

#if ENABLE_GPIOSET

int gpioset_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int gpioset_main(int argc, char **argv)
{
	unsigned opts;
	int active_low = 0;
	int toggle_mode = 0;
	const char *opt_m = "0";
	unsigned long hold_ms = 0;
	const char *chip_name;
	char *path;
	int chip_fd;
	int num_lines;
	uint32_t line_offsets[GPIO_V2_LINES_MAX];
	uint8_t line_values[GPIO_V2_LINES_MAX];
	int i;
	struct gpio_v2_line_request req;
	int use_v2 = 1;

	opts = getopt32(argv, "ltm:", &opt_m);
	if (opts & 1) active_low = 1;
	if (opts & 2) toggle_mode = 1;
	hold_ms = xatoul(opt_m);

	argv += optind;
	argc -= optind;

	if (argc < 2)
		bb_show_usage();

	chip_name = argv[0];
	num_lines = argc - 1;
	if (num_lines > GPIO_V2_LINES_MAX)
		bb_error_msg_and_die("too many lines requested (max %u)", GPIO_V2_LINES_MAX);

	for (i = 0; i < num_lines; i++) {
		char *eq = strchr(argv[i + 1], '=');
		if (!eq)
			bb_error_msg_and_die("expected LINE=VAL, got '%s'", argv[i + 1]);
		*eq = '\0';
		line_offsets[i] = xatou(argv[i + 1]);
		line_values[i] = (uint8_t)(xatoi(eq + 1) ? 1 : 0);
	}

	path = resolve_chip_path(chip_name);
	chip_fd = xopen(path, O_RDONLY);

	/* Prepare v2 line request */
	memset(&req, 0, sizeof(req));
	req.num_lines = (uint32_t)num_lines;
	strncpy(req.consumer, "gpioset", sizeof(req.consumer) - 1);
	req.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
	if (active_low)
		req.config.flags |= GPIO_V2_LINE_FLAG_ACTIVE_LOW;

	req.config.num_attrs = 1;
	req.config.attrs[0].attr.id = 2; /* GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES */
	req.config.attrs[0].mask = (num_lines == 64) ? ~0ULL : ((1ULL << num_lines) - 1ULL);
	for (i = 0; i < num_lines; i++) {
		req.offsets[i] = line_offsets[i];
		if (line_values[i])
			req.config.attrs[0].attr.values |= (1ULL << i);
	}

	if (ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &req) < 0)
		use_v2 = 0;

	if (use_v2) {
		if (toggle_mode) {
			uint64_t cur_val = req.config.attrs[0].attr.values;
			uint64_t mask = (num_lines == 64) ? ~0ULL : ((1ULL << num_lines) - 1ULL);
			while (1) {
				struct gpio_v2_line_values svals;
				cur_val ^= mask;
				svals.mask = mask;
				svals.bits = cur_val;
				ioctl(req.fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &svals);
				usleep(hold_ms > 0 ? hold_ms * 1000 : 500000);
			}
		} else if (hold_ms > 0) {
			usleep(hold_ms * 1000);
		}
		close(req.fd);
	} else {
		/* Fallback to v1 linehandle */
		struct gpiohandle_request hreq;
		memset(&hreq, 0, sizeof(hreq));
		hreq.lines = (uint32_t)num_lines;
		hreq.flags = GPIOHANDLE_REQUEST_OUTPUT;
		if (active_low)
			hreq.flags |= GPIOHANDLE_REQUEST_ACTIVE_LOW;
		strncpy(hreq.consumer_label, "gpioset", sizeof(hreq.consumer_label) - 1);

		for (i = 0; i < num_lines; i++) {
			hreq.lineoffsets[i] = line_offsets[i];
			hreq.default_values[i] = line_values[i];
		}

		if (ioctl(chip_fd, GPIO_GET_LINEHANDLE_IOCTL, &hreq) < 0)
			bb_simple_perror_msg_and_die("line request failed (v1 and v2)");

		if (toggle_mode) {
			while (1) {
				struct gpiohandle_data hdata;
				for (i = 0; i < num_lines; i++) {
					line_values[i] ^= 1;
					hdata.values[i] = line_values[i];
				}
				ioctl(hreq.fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, &hdata);
				usleep(hold_ms > 0 ? hold_ms * 1000 : 500000);
			}
		} else if (hold_ms > 0) {
			usleep(hold_ms * 1000);
		}
		close(hreq.fd);
	}

	close(chip_fd);
	free(path);
	return EXIT_SUCCESS;
}

#endif /* ENABLE_GPIOSET */

/* ==============================================================================
 * Section 5: gpiomon
 * ============================================================================== */

#if ENABLE_GPIOMON

struct driver_bind_info {
	char bus[32];
	char driver[64];
	char device[64];
	int active;
};

static struct driver_bind_info g_driver_unbind;
static int g_event_fd = -1;
static int g_chip_fd = -1;

static void rebind_driver_handler(void)
{
	if (g_event_fd >= 0) {
		close(g_event_fd);
		g_event_fd = -1;
	}
	if (g_chip_fd >= 0) {
		close(g_chip_fd);
		g_chip_fd = -1;
	}
	if (g_driver_unbind.active) {
		char path[256];
		int fd;

		snprintf(path, sizeof(path), "/sys/bus/%s/drivers/%s/bind",
			 g_driver_unbind.bus, g_driver_unbind.driver);
		fd = open(path, O_WRONLY);
		if (fd >= 0) {
			full_write(fd, g_driver_unbind.device, strlen(g_driver_unbind.device));
			close(fd);
		}
		g_driver_unbind.active = 0;
	}
}

static void sig_exit_handler(int sig UNUSED_PARAM)
{
	rebind_driver_handler();
	_exit(EXIT_SUCCESS);
}

static int unbind_driver(const char *spec, int chip_fd, uint32_t line_offset)
{
	const char *buses[] = { "platform", "i2c", "spi", "pci", "usb", NULL };
	char driver_name[64];
	char device_name[64];
	char consumer_buf[GPIO_MAX_NAME_SIZE];
	int b;

	driver_name[0] = '\0';
	device_name[0] = '\0';
	consumer_buf[0] = '\0';

	if (spec && spec[0]) {
		const char *colon = strchr(spec, ':');
		if (colon) {
			int dlen = (int)(colon - spec);
			if (dlen >= (int)sizeof(driver_name))
				dlen = (int)sizeof(driver_name) - 1;
			strncpy(driver_name, spec, (size_t)dlen);
			driver_name[dlen] = '\0';
			strncpy(device_name, colon + 1, sizeof(device_name) - 1);
			device_name[sizeof(device_name) - 1] = '\0';
		} else {
			strncpy(driver_name, spec, sizeof(driver_name) - 1);
			driver_name[sizeof(driver_name) - 1] = '\0';
		}
	} else {
		/* Attempt to query line consumer */
		struct gpio_v2_line_info info_v2;
		memset(&info_v2, 0, sizeof(info_v2));
		info_v2.offset = line_offset;
		if (ioctl(chip_fd, GPIO_V2_GET_LINEINFO_IOCTL, &info_v2) == 0 && info_v2.consumer[0]) {
			strncpy(consumer_buf, info_v2.consumer, sizeof(consumer_buf) - 1);
		} else {
			struct gpioline_info info_v1;
			memset(&info_v1, 0, sizeof(info_v1));
			info_v1.line_offset = line_offset;
			if (ioctl(chip_fd, GPIO_GET_LINEINFO_IOCTL, &info_v1) == 0 && info_v1.consumer[0]) {
				strncpy(consumer_buf, info_v1.consumer, sizeof(consumer_buf) - 1);
			}
		}

		if (consumer_buf[0]) {
			if (strstr(consumer_buf, "volume") || strstr(consumer_buf, "key"))
				strncpy(driver_name, "gpio-keys", sizeof(driver_name) - 1);
			else
				strncpy(driver_name, consumer_buf, sizeof(driver_name) - 1);
		} else {
			strncpy(driver_name, "gpio-keys", sizeof(driver_name) - 1);
		}
		driver_name[sizeof(driver_name) - 1] = '\0';
	}

	for (b = 0; buses[b]; b++) {
		char dirpath[256];
		DIR *dir;
		struct dirent *de;

		snprintf(dirpath, sizeof(dirpath), "/sys/bus/%s/drivers/%s", buses[b], driver_name);
		dir = opendir(dirpath);
		if (!dir)
			continue;

		if (device_name[0] == '\0') {
			while ((de = readdir(dir)) != NULL) {
				if (de->d_name[0] == '.')
					continue;
				if (strcmp(de->d_name, "bind") == 0 ||
				    strcmp(de->d_name, "unbind") == 0 ||
				    strcmp(de->d_name, "uevent") == 0 ||
				    strcmp(de->d_name, "module") == 0)
					continue;
				strncpy(device_name, de->d_name, sizeof(device_name) - 1);
				device_name[sizeof(device_name) - 1] = '\0';
				break;
			}
		}
		closedir(dir);

		if (device_name[0] != '\0') {
			char unbind_path[256];
			int fd;

			snprintf(unbind_path, sizeof(unbind_path), "/sys/bus/%s/drivers/%s/unbind",
				 buses[b], driver_name);
			fd = open(unbind_path, O_WRONLY);
			if (fd >= 0) {
				if (full_write(fd, device_name, strlen(device_name)) > 0) {
					strncpy(g_driver_unbind.bus, buses[b], sizeof(g_driver_unbind.bus) - 1);
					strncpy(g_driver_unbind.driver, driver_name, sizeof(g_driver_unbind.driver) - 1);
					strncpy(g_driver_unbind.device, device_name, sizeof(g_driver_unbind.device) - 1);
					g_driver_unbind.active = 1;
					close(fd);
					atexit(rebind_driver_handler);
					signal(SIGINT, sig_exit_handler);
					signal(SIGTERM, sig_exit_handler);
					signal(SIGHUP, sig_exit_handler);
					printf("Unbound %s from %s (will rebind on exit)\n", device_name, driver_name);
					fflush(stdout);
					return 0;
				}
				close(fd);
			}
		}
	}

	return -1;
}

int gpiomon_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int gpiomon_main(int argc, char **argv)
{
	unsigned opts;
	int edge_rising = 1, edge_falling = 1;
	int active_low = 0;
	const char *chip_name;
	char *opt_u = NULL;
	uint32_t line_offset;
	char *path;
	int chip_fd;
	int event_fd = -1;
	int is_v2 = 0;
	struct gpio_v2_line_request req_v2;

	opts = getopt32(argv, "rflUu:", &opt_u);
	if (opts & 1) { edge_rising = 1; edge_falling = 0; }
	if (opts & 2) { edge_falling = 1; if (!(opts & 1)) edge_rising = 0; }
	if (opts & 4) active_low = 1;

	argv += optind;
	argc -= optind;

	if (argc < 2)
		bb_show_usage();

	chip_name = argv[0];
	line_offset = xatou(argv[1]);

	path = resolve_chip_path(chip_name);
	chip_fd = xopen(path, O_RDONLY);
	g_chip_fd = chip_fd;

	if (opts & (8 | 16))
		unbind_driver((opts & 16) ? opt_u : NULL, chip_fd, line_offset);

	/* Try GPIO v2 ABI first */
	memset(&req_v2, 0, sizeof(req_v2));
	req_v2.num_lines = 1;
	req_v2.offsets[0] = line_offset;
	strncpy(req_v2.consumer, "gpiomon", sizeof(req_v2.consumer) - 1);
	req_v2.config.flags = GPIO_V2_LINE_FLAG_INPUT;
	if (edge_rising)
		req_v2.config.flags |= GPIO_V2_LINE_FLAG_EDGE_RISING;
	if (edge_falling)
		req_v2.config.flags |= GPIO_V2_LINE_FLAG_EDGE_FALLING;
	if (active_low)
		req_v2.config.flags |= GPIO_V2_LINE_FLAG_ACTIVE_LOW;
	req_v2.event_buffer_size = 64;

	if (ioctl(chip_fd, GPIO_V2_GET_LINE_IOCTL, &req_v2) == 0) {
		event_fd = req_v2.fd;
		g_event_fd = event_fd;
		is_v2 = 1;
	} else {
		/* Fallback to GPIO v1 ABI for Linux 4.19 / older kernels */
		struct gpioevent_request req_v1;

		memset(&req_v1, 0, sizeof(req_v1));
		req_v1.lineoffset = line_offset;
		req_v1.handleflags = GPIOHANDLE_REQUEST_INPUT;
		if (active_low)
			req_v1.handleflags |= GPIOHANDLE_REQUEST_ACTIVE_LOW;
		if (edge_rising)
			req_v1.eventflags |= GPIOEVENT_REQUEST_RISING_EDGE;
		if (edge_falling)
			req_v1.eventflags |= GPIOEVENT_REQUEST_FALLING_EDGE;
		strncpy(req_v1.consumer_label, "gpiomon", sizeof(req_v1.consumer_label) - 1);

		if (ioctl(chip_fd, GPIO_GET_LINEEVENT_IOCTL, &req_v1) == 0) {
			event_fd = req_v1.fd;
			g_event_fd = event_fd;
			is_v2 = 0;
		} else {
			bb_simple_perror_msg_and_die("line event request failed (v1 and v2)");
		}
	}

	printf("Monitoring line %u on %s (waiting for events)...\n", (unsigned)line_offset, chip_name);
	fflush(stdout);

	while (1) {
		uint64_t timestamp_ns;
		uint32_t event_id;
		uint32_t line = line_offset;

		if (is_v2) {
			struct gpio_v2_line_event ev_v2;
			ssize_t n = full_read(event_fd, &ev_v2, sizeof(ev_v2));
			if (n <= 0)
				break;
			if (n != sizeof(ev_v2))
				continue;
			timestamp_ns = ev_v2.timestamp_ns;
			event_id = ev_v2.id;
			line = ev_v2.offset;
		} else {
			struct gpioevent_data ev_v1;
			ssize_t n = full_read(event_fd, &ev_v1, sizeof(ev_v1));
			if (n <= 0)
				break;
			if (n != sizeof(ev_v1))
				continue;
			timestamp_ns = ev_v1.timestamp;
			event_id = ev_v1.id;
		}

		{
			uint64_t sec = timestamp_ns / 1000000000ULL;
			uint64_t usec = (timestamp_ns % 1000000000ULL) / 1000ULL;
			const char *ename = (event_id == 1) ? "RISING " : ((event_id == 2) ? "FALLING" : "UNKNOWN");
			printf("event: %s on line %u at [%llu.%06llu]\n", ename, (unsigned)line,
			       (unsigned long long)sec, (unsigned long long)usec);
			fflush(stdout);
		}
	}

	close(event_fd);
	close(chip_fd);
	free(path);
	rebind_driver_handler();
	return EXIT_SUCCESS;
}

#endif /* ENABLE_GPIOMON */
