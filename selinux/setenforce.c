/*
 * setenforce
 *
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
//config:config SETENFORCE
//config:	bool "setenforce (2.1 kb)"
//config:	default n
//config:	depends on SELINUX
//config:	help
//config:	Enable support to modify the mode SELinux is running in.

//applet:IF_SETENFORCE(APPLET(setenforce, BB_DIR_USR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SETENFORCE) += setenforce.o

//usage:#define setenforce_trivial_usage
//usage:       "[Enforcing | Permissive | 1 | 0]"
//usage:#define setenforce_full_usage ""

#include "libbb.h"

/* These strings are arranged so that odd ones
 * result in security_setenforce(1) being done,
 * the rest will do security_setenforce(0) */
static const char *const setenforce_cmd[] ALIGN_PTR = {
	"0",
	"1",
	"permissive",
	"enforcing",
	NULL,
};

int setenforce_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int setenforce_main(int argc UNUSED_PARAM, char **argv)
{
	int i;
	int rc = -1;
	int enforce = -1;
	int fd;
	char c;

	if (!argv[1] || argv[2])
		bb_show_usage();

	for (i = 0; setenforce_cmd[i]; i++) {
		if (strcasecmp(argv[1], setenforce_cmd[i]) == 0) {
			enforce = i & 1;
			break;
		}
	}
	if (enforce < 0)
		bb_show_usage();

#if ENABLE_SELINUX
	if (is_selinux_enabled() == 1) {
		rc = security_setenforce(enforce);
	}
#endif

	/* Android fallback: /etc/selinux/config is absent so is_selinux_enabled() == 0.
	 * Mutate /sys/fs/selinux/enforce directly */
	if (rc < 0) {
		fd = open("/sys/fs/selinux/enforce", O_WRONLY);
		if (fd < 0)
			fd = open("/selinux/enforce", O_WRONLY);

		if (fd >= 0) {
			c = enforce ? '1' : '0';
			if (write(fd, &c, 1) == 1)
				rc = 0;
			close(fd);
		}
	}

	if (rc < 0)
		bb_simple_perror_msg_and_die("setenforce() failed");

	return 0;
}
