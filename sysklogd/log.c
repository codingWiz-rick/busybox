/* vi: set sw=4 ts=4: */
/*
 * log - Write messages to Android logcat
 *
 * Copyright (C) 2016 The Android Open Source Project
 * Ported and rewritten for standalone static BusyBox by Antigravity
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config LOG
//config:	bool "log (Android logcat writer)"
//config:	default y
//config:	help
//config:	  log sends messages to Android's logd logger daemon
//config:	  (/dev/socket/logdw), making them visible in logcat.

//applet:IF_LOG(APPLET(log, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_LOG) += log.o

//usage:#define log_trivial_usage
//usage:	"[-b BUFFER] [-p PRI] [-t TAG] [MESSAGE...]"
//usage:#define log_full_usage "\n\n"
//usage:       "Send MESSAGE (or stdin) to Android logcat\n"
//usage:     "\n	-b BUFFER	Log buffer: main, radio, events, system, crash, stats, security, kernel (default: main)"
//usage:     "\n	-p PRI		Priority: v (verbose), d (debug), i (info), w (warn), e (error), f (fatal), s (silent) (default: i)"
//usage:     "\n	-t TAG		Log tag (default: log)"

#include "libbb.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

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

int log_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int log_main(int argc, char **argv)
{
	const char *opt_b = "main";
	const char *opt_p = "i";
	const char *opt_t = "log";
	int buf_id;
	int prio;

	getopt32(argv, "b:p:t:", &opt_b, &opt_p, &opt_t);
	argv += optind;
	argc -= optind;

	buf_id = parse_buffer(opt_b);
	prio = parse_priority(opt_p);

	if (argc > 0) {
		char *msg = argv[0];
		if (argc > 1) {
			/* Join arguments with space */
			size_t total_len = 0;
			int i;
			char *p;

			for (i = 0; i < argc; i++)
				total_len += strlen(argv[i]) + 1;

			msg = xmalloc(total_len);
			p = msg;
			for (i = 0; i < argc; i++) {
				if (i > 0)
					*p++ = ' ';
				p = stpcpy(p, argv[i]);
			}
			*p = '\0';
		}
		android_log_write(buf_id, prio, opt_t, msg);
		if (argc > 1)
			free(msg);
	} else {
		/* Read from stdin line-by-line */
		char *line;
		while ((line = xmalloc_fgetline(stdin)) != NULL) {
			android_log_write(buf_id, prio, opt_t, line);
			free(line);
		}
	}

	return EXIT_SUCCESS;
}
