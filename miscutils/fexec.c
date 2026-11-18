/* vi: set sw=4 ts=4: */
/*
 * fexec / memrun implementation for BusyBox
 *
 * Executes binaries or scripts directly from anonymous memory or file descriptors,
 * without touching persistent storage.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
//config:config FEXEC
//config:	bool "fexec / memrun (in-memory execution)"
//config:	default y
//config:	help
//config:	Execute binaries or scripts directly from anonymous memory (memfd)
//config:	or standard input without saving to persistent storage.

//applet:IF_FEXEC(APPLET(fexec, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_FEXEC(APPLET_ODDNAME(memrun, fexec, BB_DIR_USR_BIN, BB_SUID_DROP, fexec))

//kbuild:lib-$(CONFIG_FEXEC) += fexec.o

//usage:#define fexec_trivial_usage
//usage:       "[-n NAME] [-s] [-a ARG0] PROG [ARGS...]"
//usage:#define fexec_full_usage "\n\n"
//usage:       "Execute an executable binary or script directly from anonymous memory\n"
//usage:     "\n	-n NAME	Name for memfd / process (default: basename of PROG)"
//usage:     "\n	-s	Seal memfd before execution (prevent write/shrink/grow)"
//usage:     "\n	-a ARG0	Override argv[0] passed to target program"
//usage:     "\n"
//usage:     "\nPROG may be '-' to read the executable binary or script from stdin."
//usage:     "\nAll subsequent ARGS are passed directly to the target program."

#include "libbb.h"
#include <sys/mman.h>
#include <sys/sendfile.h>

#ifndef MFD_CLOEXEC
# define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
# define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_LINUX_SPECIFIC_BASE
# define F_LINUX_SPECIFIC_BASE 1024
#endif
#ifndef F_ADD_SEALS
# define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif
#ifndef F_SEAL_SEAL
# define F_SEAL_SEAL   0x0001
# define F_SEAL_SHRINK 0x0002
# define F_SEAL_GROW   0x0004
# define F_SEAL_WRITE  0x0008
#endif

#ifndef __NR_memfd_create
# if defined(__aarch64__)
#  define __NR_memfd_create 279
# elif defined(__x86_64__)
#  define __NR_memfd_create 319
# elif defined(__arm__)
#  define __NR_memfd_create 385
# elif defined(__i386__)
#  define __NR_memfd_create 356
# endif
#endif

extern char **environ;

enum {
	OPT_n = (1 << 0),
	OPT_s = (1 << 1),
	OPT_a = (1 << 2),
};

static int create_memfd(const char *name)
{
	int fd = -1;

#if defined(SYS_memfd_create)
	fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
#elif defined(__NR_memfd_create)
	fd = syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
#endif

	if (fd < 0 && (errno == EINVAL || errno == ENOSYS)) {
#if defined(SYS_memfd_create)
		fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);
#elif defined(__NR_memfd_create)
		fd = syscall(__NR_memfd_create, name, MFD_CLOEXEC);
#endif
	}

#ifdef O_TMPFILE
	if (fd < 0) {
		fd = open("/dev/shm", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
		if (fd < 0)
			fd = open("/tmp", O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
	}
#endif

	if (fd < 0) {
		char tmppath[64];
		snprintf(tmppath, sizeof(tmppath), "/dev/shm/.memrun-%d-%u", (int)getpid(), (unsigned)rand());
		fd = open(tmppath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
		if (fd < 0) {
			snprintf(tmppath, sizeof(tmppath), "/tmp/.memrun-%d-%u", (int)getpid(), (unsigned)rand());
			fd = open(tmppath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
		}
		if (fd >= 0)
			unlink(tmppath);
	}

	return fd;
}

int fexec_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int fexec_main(int argc UNUSED_PARAM, char **argv)
{
	char *opt_name = NULL;
	char *opt_arg0 = NULL;
	const char *src_prog;
	const char *mem_name;
	int mfd, in_fd;
	unsigned opts;

	opts = getopt32(argv, "^+" "n:sa:" "\0" "-1", &opt_name, &opt_arg0);
	argv += optind;

	src_prog = argv[0];

	if (opt_name && opt_name[0]) {
		mem_name = opt_name;
	} else if (LONE_CHAR(src_prog, '-')) {
		mem_name = "memrun";
	} else {
		mem_name = bb_basename(src_prog);
	}

	mfd = create_memfd(mem_name);
	if (mfd < 0)
		bb_simple_perror_msg_and_die("failed to create anonymous memory file");

	if (LONE_CHAR(src_prog, '-')) {
		in_fd = STDIN_FILENO;
	} else {
		in_fd = xopen(src_prog, O_RDONLY | O_CLOEXEC);
	}

	if (in_fd != STDIN_FILENO) {
		struct stat st;
		if (fstat(in_fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
			off_t remaining = st.st_size;
			off_t offset = 0;
			while (remaining > 0) {
				ssize_t sent = sendfile(mfd, in_fd, &offset, remaining);
				if (sent <= 0) {
					if (sent < 0 && (errno == EAGAIN || errno == EINTR))
						continue;
					break;
				}
				remaining -= sent;
			}
			if (remaining == 0)
				goto copy_done;

			lseek(mfd, offset, SEEK_SET);
			lseek(in_fd, offset, SEEK_SET);
		}
	}

	if (bb_copyfd_eof(in_fd, mfd) < 0)
		bb_perror_msg_and_die("failed to copy executable payload");

copy_done:
	if (in_fd != STDIN_FILENO)
		close(in_fd);

	/* Ensure executable permissions */
	fchmod(mfd, 0700);

	/* Clear FD_CLOEXEC: required by binfmt_script (shebang scripts) and
	 * binfmt_misc emulators so /proc/self/fd/<mfd> remains open and readable
	 * by the target interpreter across execve */
	fcntl(mfd, F_SETFD, 0);

	/* Optional sealing */
	if (opts & OPT_s) {
		fcntl(mfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
	}

	/* Set argv[0] */
	if (opts & OPT_a) {
		argv[0] = opt_arg0;
	} else if (LONE_CHAR(src_prog, '-')) {
		argv[0] = (char *)mem_name;
	}

	/* Execute from memory */
	fexecve(mfd, argv, environ);

	/* Fallback via /proc/self/fd/<fd> */
	{
		char procpath[32];
		snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", mfd);
		execve(procpath, argv, environ);
	}

	bb_perror_msg_and_die("can't execute '%s'", argv[0]);
}
