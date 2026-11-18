/*
 * getenforce
 *
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
//config:config GETENFORCE
//config:	bool "getenforce (1.7 kb)"
//config:	default n
//config:	depends on SELINUX
//config:	help
//config:	Enable support to get the current mode of SELinux.

//applet:IF_GETENFORCE(APPLET(getenforce, BB_DIR_USR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_GETENFORCE) += getenforce.o

//usage:#define getenforce_trivial_usage NOUSAGE_STR
//usage:#define getenforce_full_usage ""

#include "libbb.h"

#if ENABLE_SELINUX
extern void selinux_prune_anchor(void);
#endif

int getenforce_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int getenforce_main(int argc UNUSED_PARAM, char **argv UNUSED_PARAM)
{
	int rc = -1;
	int fd;
	char c;

#if ENABLE_SELINUX
	selinux_prune_anchor();
	if (is_selinux_enabled() == 1) {
		rc = security_getenforce();
	}
#endif

	/* If desktop libselinux returned -1 (or returned 0 because /etc/selinux/config
	 * is absent, which is universal on Android), inspect /sys/fs/selinux/enforce directly */
	if (rc < 0) {
		fd = open("/sys/fs/selinux/enforce", O_RDONLY);
		if (fd < 0)
			fd = open("/selinux/enforce", O_RDONLY);

		if (fd >= 0) {
			c = 0;
			if (read(fd, &c, 1) == 1) {
				if (c == '1')
					rc = 1;
				else if (c == '0')
					rc = 0;
			}
			close(fd);
		}
	}

	if (rc == 1)
		puts("Enforcing");
	else if (rc == 0)
		puts("Permissive");
	else
		puts("Disabled");

	return 0;
}
