/* vi: set sw=4 ts=4: */
/*
 * sendevent - Send Linux input subsystem events
 *
 * Copyright (C) 2016 The Android Open Source Project
 * Ported to BusyBox by Antigravity
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config SENDEVENT
//config:	bool "sendevent (Android input event injector)"
//config:	default y
//config:	help
//config:	  sendevent sends raw Linux input subsystem events to an input
//config:	  device node (e.g. /dev/input/event0).

//applet:IF_SENDEVENT(APPLET(sendevent, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SENDEVENT) += sendevent.o

//usage:#define sendevent_trivial_usage
//usage:	"DEVICE TYPE CODE VALUE"
//usage:#define sendevent_full_usage "\n\n"
//usage:       "Send a Linux input event to DEVICE\n"
//usage:     "\n	DEVICE	Path to input event device node (e.g. /dev/input/event0)"
//usage:     "\n	TYPE	Event type (decimal or hex, e.g. 1 or 0x01 for EV_KEY)"
//usage:     "\n	CODE	Event code (decimal or hex, e.g. 330 or 0x14a for BTN_TOUCH)"
//usage:     "\n	VALUE	Event value (decimal or hex, e.g. 1 for down, 0 for up)"

#include "libbb.h"
#include <linux/input.h>

int sendevent_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int sendevent_main(int argc, char **argv)
{
	int fd;
	int version;
	struct input_event ev;
	char *endp;

	if (argc != 5)
		bb_show_usage();

	fd = xopen(argv[1], O_RDWR);

	if (ioctl(fd, EVIOCGVERSION, &version) < 0)
		bb_perror_msg_and_die("EVIOCGVERSION failed for %s", argv[1]);

	memset(&ev, 0, sizeof(ev));

	/* Parse type (supports decimal and hex like 0x01) */
	ev.type = (uint16_t)strtoul(argv[2], &endp, 0);
	if (*endp != '\0')
		bb_error_msg_and_die("invalid type: %s", argv[2]);

	/* Parse code (supports decimal and hex like 0x14a) */
	ev.code = (uint16_t)strtoul(argv[3], &endp, 0);
	if (*endp != '\0')
		bb_error_msg_and_die("invalid code: %s", argv[3]);

	/* Parse value (supports decimal, hex, and negative values like -1) */
	ev.value = (int32_t)strtol(argv[4], &endp, 0);
	if (*endp != '\0')
		bb_error_msg_and_die("invalid value: %s", argv[4]);

	xwrite(fd, &ev, sizeof(ev));
	close(fd);

	return EXIT_SUCCESS;
}
