/* vi: set sw=4 ts=4: */
/*
 * log - Android Logging Suite (Logcat Writer & Kernel Log Watcher)
 *
 * Applets:
 *   log  - Send messages to Android logcat (/dev/socket/logdw) or read kernel log (-k)
 *   klog - Enhanced kernel ring-buffer watcher with delta-timing, filtering & coloring
 *
 * Copyright (C) 2016 The Android Open Source Project
 * Extended for standalone static BusyBox by Antigravity
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config LOG
//config:	bool "log (Android logcat writer & kernel log watcher)"
//config:	default y
//config:	help
//config:	  Unified Android logging suite. Provides 'log' to write messages
//config:	  to Android's logd daemon (/dev/socket/logdw) and 'klog' to watch,
//config:	  filter, and time kernel ring-buffer logs (/dev/kmsg).

//applet:IF_LOG(APPLET(log, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_LOG(APPLET_ODDNAME(klog, log, BB_DIR_USR_BIN, BB_SUID_DROP, klog))

//kbuild:lib-$(CONFIG_LOG) += log.o

//usage:#define log_trivial_usage
//usage:	"[-k] [-b BUFFER] [-p PRI] [-t TAG] [MESSAGE...]"
//usage:#define log_full_usage "\n\n"
//usage:       "Android logging suite (logcat writer and kernel log reader)\n"
//usage:     "\n	-k, --kernel	Read/watch kernel log (same as running 'klog')"
//usage:     "\n	-b BUFFER	Log buffer: main, radio, events, system, crash, stats, security, kernel (default: main)"
//usage:     "\n	-p PRI		Priority: v (verbose), d (debug), i (info), w (warn), e (error), f (fatal), s (silent) (default: i)"
//usage:     "\n	-t TAG		Log tag (default: log)"
//usage:
//usage:#define klog_trivial_usage
//usage:	"[-f] [-c] [-d] [-l LEVEL] [-s SUBSYS...] [--no-color]"
//usage:#define klog_full_usage "\n\n"
//usage:       "Enhanced kernel ring-buffer watcher with delta-timing and filtering\n"
//usage:     "\n	-f		Follow new messages in real-time"
//usage:     "\n	-c		Clear kernel ring buffer after reading"
//usage:     "\n	-d		Show microsecond delta time since previous message (default)"
//usage:     "\n	-l LEVEL	Minimum severity: emerg, alert, crit, err, warn, notice, info, debug (or 0-7)"
//usage:     "\n	-s SUBSYS	Filter by subsystem prefix/tag (comma-separated or repeatable)"
//usage:     "\n	--no-color	Disable ANSI color highlighting"

#include "libbb.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/klog.h>

#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#endif
#ifndef SYSLOG_ACTION_CLEAR
#define SYSLOG_ACTION_CLEAR 5
#endif

/* ==============================================================================
 * Section 1: Android Logcat Writer (/dev/socket/logdw)
 * ============================================================================== */

/* Android log priorities */
enum {
	ANDROID_LOG_UNKNOWN = 0,
	ANDROID_LOG_DEFAULT = 1,
	ANDROID_LOG_VERBOSE = 2,
	ANDROID_LOG_DEBUG   = 3,
	ANDROID_LOG_INFO    = 4,
	ANDROID_LOG_WARN    = 5,
	ANDROID_LOG_ERROR   = 6,
	ANDROID_LOG_FATAL   = 7,
	ANDROID_LOG_SILENT  = 8,
};

/* Android log buffer IDs */
enum {
	LOG_ID_MAIN     = 0,
	LOG_ID_RADIO    = 1,
	LOG_ID_EVENTS   = 2,
	LOG_ID_SYSTEM   = 3,
	LOG_ID_CRASH    = 4,
	LOG_ID_STATS    = 5,
	LOG_ID_SECURITY = 6,
	LOG_ID_KERNEL   = 7,
};

/* Wire protocol header for /dev/socket/logdw */
struct __attribute__((__packed__)) android_log_header_t {
	uint8_t  id;
	uint16_t tid;
	struct {
		uint32_t tv_sec;
		uint32_t tv_nsec;
	} realtime;
};

static int parse_buffer(const char *name)
{
	static const char *const names[] = {
		"main", "radio", "events", "system",
		"crash", "stats", "security", "kernel",
		NULL
	};
	int i;

	for (i = 0; names[i]; i++) {
		if (strcmp(name, names[i]) == 0)
			return i;
	}
	bb_error_msg_and_die("unknown log buffer: %s", name);
}

static int parse_priority(const char *pri)
{
	char c;

	if (!pri || !*pri)
		return ANDROID_LOG_INFO;

	c = tolower(pri[0]);
	switch (c) {
	case 'v': return ANDROID_LOG_VERBOSE;
	case 'd': return ANDROID_LOG_DEBUG;
	case 'i': return ANDROID_LOG_INFO;
	case 'w': return ANDROID_LOG_WARN;
	case 'e': return ANDROID_LOG_ERROR;
	case 'f': return ANDROID_LOG_FATAL;
	case 's': return ANDROID_LOG_SILENT;
	default:
		bb_error_msg_and_die("bad -p '%s'", pri);
	}
}

static void android_log_write(int buf_id, int prio, const char *tag, const char *msg)
{
	int sock;
	struct sockaddr_un addr;
	struct android_log_header_t header;
	struct timespec ts;
	struct iovec vec[4];
	uint8_t p = (uint8_t)prio;
	ssize_t ret;

	sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		/* Fall back to stderr if socket creation fails */
		fprintf(stderr, "[%s] %s\n", tag, msg);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	safe_strncpy(addr.sun_path, "/dev/socket/logdw", sizeof(addr.sun_path));

	clock_gettime(CLOCK_REALTIME, &ts);
	header.id = (uint8_t)buf_id;
	header.tid = (uint16_t)gettid();
	header.realtime.tv_sec = (uint32_t)ts.tv_sec;
	header.realtime.tv_nsec = (uint32_t)ts.tv_nsec;

	vec[0].iov_base = &header;
	vec[0].iov_len  = sizeof(header);
	vec[1].iov_base = &p;
	vec[1].iov_len  = 1;
	vec[2].iov_base = (void *)tag;
	vec[2].iov_len  = strlen(tag) + 1;
	vec[3].iov_base = (void *)msg;
	vec[3].iov_len  = strlen(msg) + 1;

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		ret = writev(sock, vec, 4);
		(void)ret;
	} else {
		/* If logd socket is unavailable (e.g. non-Android desktop), write to stderr */
		fprintf(stderr, "[%s] %s\n", tag, msg);
	}

	close(sock);
}

/* ==============================================================================
 * Section 2: Kernel Ring-Buffer Watcher (klog / log -k)
 * ============================================================================== */

static int parse_klog_level(const char *str)
{
	if (!str || !*str)
		return 7;
	if (isdigit(str[0]))
		return atoi(str);

	if (strcasecmp(str, "emerg") == 0) return 0;
	if (strcasecmp(str, "alert") == 0) return 1;
	if (strcasecmp(str, "crit") == 0) return 2;
	if (strcasecmp(str, "err") == 0 || strcasecmp(str, "error") == 0) return 3;
	if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) return 4;
	if (strcasecmp(str, "notice") == 0) return 5;
	if (strcasecmp(str, "info") == 0) return 6;
	if (strcasecmp(str, "debug") == 0) return 7;

	return 7;
}

static bool match_subsystem_filter(const char *msg, char **subsys_list, int subsys_count)
{
	int i;
	if (subsys_count == 0)
		return true;

	for (i = 0; i < subsys_count; i++) {
		const char *tag = subsys_list[i];
		size_t taglen = strlen(tag);

		/* Match "tag: " */
		if (strncmp(msg, tag, taglen) == 0 && (msg[taglen] == ':' || msg[taglen] == ' ' || msg[taglen] == '/'))
			return true;

		/* Match "[tag]" */
		if (msg[0] == '[' && strncmp(msg + 1, tag, taglen) == 0 && msg[taglen + 1] == ']')
			return true;

		/* Substring match for compound tags (e.g. kroot in [kroot][vfs_remap]) */
		if (strstr(msg, tag) != NULL)
			return true;
	}
	return false;
}

static int klog_run(int argc, char **argv)
{
	bool follow = false;
	bool clear_buf = false;
	bool show_delta = true;
	bool use_color = isatty(STDOUT_FILENO);
	int min_level = 7; /* Default: all levels */
	char *subsys_filter = NULL;
	char *subsys_list[32];
	int subsys_count = 0;
	int fd;
	unsigned long long prev_ts_us = 0;
	char record[8192];
	int opt;
	char *tok;
	char *p;
	ssize_t n;
	char *semicolon;
	int pri;
	unsigned long long seq;
	unsigned long long ts_us;
	const char *msg;
	int level;
	double ts_sec;
	double delta_sec;
	const char *c_start;
	const char *c_end;
	size_t mlen;
	int bufsz;
	char *buf;
	int len;
	char *pos;
	char *line;
	const char *text;

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "-f") == 0 || strcmp(argv[opt], "--follow") == 0) {
			follow = true;
		} else if (strcmp(argv[opt], "-c") == 0 || strcmp(argv[opt], "--clear") == 0) {
			clear_buf = true;
		} else if (strcmp(argv[opt], "-d") == 0 || strcmp(argv[opt], "--delta") == 0) {
			show_delta = true;
		} else if (strcmp(argv[opt], "--no-delta") == 0) {
			show_delta = false;
		} else if (strcmp(argv[opt], "--no-color") == 0) {
			use_color = false;
		} else if (strcmp(argv[opt], "--color") == 0) {
			use_color = true;
		} else if ((strcmp(argv[opt], "-l") == 0 || strcmp(argv[opt], "--level") == 0) && opt + 1 < argc) {
			min_level = parse_klog_level(argv[++opt]);
		} else if ((strcmp(argv[opt], "-s") == 0 || strcmp(argv[opt], "--subsys") == 0) && opt + 1 < argc) {
			subsys_filter = xstrdup(argv[++opt]);
		} else if (argv[opt][0] == '-') {
			bb_show_usage();
		}
	}

	if (subsys_filter) {
		p = subsys_filter;
		while ((tok = strsep(&p, ",")) != NULL && subsys_count < 32) {
			if (*tok)
				subsys_list[subsys_count++] = tok;
		}
	}

	fd = open("/dev/kmsg", (follow ? O_RDONLY : (O_RDONLY | O_NONBLOCK)) | O_CLOEXEC);
	if (fd >= 0) {
		/* Seek to beginning of buffer */
		lseek(fd, 0, SEEK_SET);

		while (1) {
			n = read(fd, record, sizeof(record) - 1);
			if (n < 0) {
				if (errno == EINTR) continue;
				if (errno == EPIPE) continue; /* Ring buffer overrun: continue reading */
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					if (follow) {
						/* Switch to blocking read when caught up */
						int flags = fcntl(fd, F_GETFL);
						if (flags >= 0 && (flags & O_NONBLOCK)) {
							fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
						}
						continue;
					}
					break;
				}
				break;
			}
			if (n == 0) {
				if (!follow) break;
				continue;
			}

			record[n] = '\0';

			/* Parse record format: <pri>,<seq>,<ts_us>,<flags>;<message> */
			semicolon = strchr(record, ';');
			pri = 6;
			seq = 0;
			ts_us = 0;
			msg = "";

			if (semicolon) {
				*semicolon = '\0';
				msg = semicolon + 1;
				sscanf(record, "%d,%llu,%llu", &pri, &seq, &ts_us);
			} else {
				msg = record;
			}

			level = pri & 7;
			if (level > min_level)
				continue;

			if (!match_subsystem_filter(msg, subsys_list, subsys_count))
				continue;

			ts_sec = (double)ts_us / 1000000.0;
			delta_sec = (prev_ts_us > 0 && ts_us >= prev_ts_us) ?
			            ((double)(ts_us - prev_ts_us) / 1000000.0) : 0.0;
			prev_ts_us = ts_us;

			c_start = "";
			c_end = use_color ? "\033[0m" : "";

			if (use_color) {
				switch (level) {
				case 0: /* KERN_EMERG */
				case 1: /* KERN_ALERT */
				case 2: /* KERN_CRIT */
					c_start = "\033[1;31m"; break;
				case 3: /* KERN_ERR */
					c_start = "\033[31m"; break;
				case 4: /* KERN_WARNING */
					c_start = "\033[33m"; break;
				case 5: /* KERN_NOTICE */
					c_start = "\033[36m"; break;
				case 6: /* KERN_INFO */
					c_start = "\033[37m"; break;
				case 7: /* KERN_DEBUG */
					c_start = "\033[90m"; break;
				}
			}

			/* Strip trailing newline from msg if present */
			mlen = strlen(msg);
			while (mlen > 0 && (msg[mlen - 1] == '\n' || msg[mlen - 1] == '\r')) {
				((char *)msg)[--mlen] = '\0';
			}

			if (show_delta) {
				printf("%s[%10.6f (+%9.6fs)] %s%s\n", c_start, ts_sec, delta_sec, msg, c_end);
			} else {
				printf("%s[%10.6f] %s%s\n", c_start, ts_sec, msg, c_end);
			}
			fflush(stdout);
		}
		close(fd);
	} else {
		/* Fallback to klogctl() */
		bufsz = 256 * 1024;
		buf = xmalloc(bufsz);
		len = klogctl(SYSLOG_ACTION_READ_ALL, buf, bufsz - 1);
		if (len > 0) {
			buf[len] = '\0';
			pos = buf;
			while ((line = strsep(&pos, "\r\n")) != NULL) {
				if (!*line) continue;
				level = 6;
				text = line;
				if (line[0] == '<' && isdigit(line[1]) && line[2] == '>') {
					level = line[1] - '0';
					text = line + 3;
				}
				if (level > min_level)
					continue;
				if (!match_subsystem_filter(text, subsys_list, subsys_count))
					continue;
				c_start = "";
				c_end = use_color ? "\033[0m" : "";
				if (use_color) {
					switch (level) {
					case 0: case 1: case 2: c_start = "\033[1;31m"; break;
					case 3: c_start = "\033[31m"; break;
					case 4: c_start = "\033[33m"; break;
					case 5: c_start = "\033[36m"; break;
					case 7: c_start = "\033[90m"; break;
					}
				}
				printf("%s%s%s\n", c_start, text, c_end);
			}
		}
		free(buf);
	}

	if (clear_buf) {
		klogctl(SYSLOG_ACTION_CLEAR, NULL, 0);
	}

	free(subsys_filter);
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 3: Main Applet Dispatcher
 * ============================================================================== */

int log_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int log_main(int argc, char **argv)
{
	const char *opt_b = "main";
	const char *opt_p = "i";
	const char *opt_t = "log";
	int buf_id;
	int prio;

	/* If invoked as 'klog' */
	if (strcmp(applet_name, "klog") == 0) {
		return klog_run(argc, argv);
	}

	/* If invoked as 'log -k' or 'log --kernel' */
	if (argc > 1 && (strcmp(argv[1], "-k") == 0 || strcmp(argv[1], "--kernel") == 0)) {
		return klog_run(argc - 1, argv + 1);
	}

	getopt32(argv, "b:p:t:", &opt_b, &opt_p, &opt_t);
	argv += optind;
	argc -= optind;

	buf_id = parse_buffer(opt_b);
	prio = parse_priority(opt_p);

	if (argc > 0) {
		char *msg = argv[0];
		if (argc > 1) {
			size_t total_len = 0;
			int i;
			char *pmsg;

			for (i = 0; i < argc; i++)
				total_len += strlen(argv[i]) + 1;

			msg = xmalloc(total_len);
			pmsg = msg;
			for (i = 0; i < argc; i++) {
				if (i > 0)
					*pmsg++ = ' ';
				pmsg = stpcpy(pmsg, argv[i]);
			}
			*pmsg = '\0';
		}
		android_log_write(buf_id, prio, opt_t, msg);
		if (argc > 1)
			free(msg);
	} else {
		char *line_in;
		while ((line_in = xmalloc_fgetline(stdin)) != NULL) {
			android_log_write(buf_id, prio, opt_t, line_in);
			free(line_in);
		}
	}

	return EXIT_SUCCESS;
}
