/* vi: set sw=4 ts=4: */
/*
 * Native libc-independent setprop applet for Android
 *
 * Connects directly to Android's property_service Unix domain stream socket
 * (/dev/socket/property_service) and sends the standard PROP_MSG_SETPROP2
 * or legacy PROP_MSG_SETPROP command packet.
 *
 * Compatible with Android 5.0 through 16.
 *
 * Licensed under GPLv2 or later.
 */

//config:config SETPROP
//config:	bool "setprop (Android system property setter)"
//config:	default y
//config:	help
//config:	  Sets Android properties via property_service socket.

//applet:IF_SETPROP(APPLET(setprop, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SETPROP) += setprop.o

//usage:#define setprop_trivial_usage
//usage:       "NAME VALUE"
//usage:#define setprop_full_usage "\n\n"
//usage:       "Set an Android system property.\n"

#include "libbb.h"
#include "bb_android.h"
#include <sys/socket.h>
#include <sys/un.h>

static int send_all(int sock, const void *buf, size_t len)
{
	const char *p = (const char *)buf;
	while (len > 0) {
		ssize_t nw = write(sock, p, len);
		if (nw <= 0) {
			if (nw < 0 && (errno == EINTR || errno == EAGAIN))
				continue;
			return -1;
		}
		p += nw;
		len -= nw;
	}
	return 0;
}

static int read_all(int sock, void *buf, size_t len)
{
	char *p = (char *)buf;
	while (len > 0) {
		ssize_t nr = read(sock, p, len);
		if (nr <= 0) {
			if (nr < 0 && (errno == EINTR || errno == EAGAIN))
				continue;
			return -1;
		}
		p += nr;
		len -= nr;
	}
	return 0;
}

int setprop_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int setprop_main(int argc, char **argv)
{
	const char *name;
	const char *value;
	uint32_t name_len;
	uint32_t val_len;
	uint32_t cmd;
	uint32_t result = 0;
	struct sockaddr_un addr;
	int sock;
	struct timeval tv;

	if (argc < 3)
		bb_show_usage();

	name = argv[1];
	value = argv[2];
	name_len = (uint32_t)strlen(name);
	val_len = (uint32_t)strlen(value);

	if (name_len == 0) {
		bb_error_msg("property name cannot be empty");
		return EXIT_FAILURE;
	}

	if (strstr(name, "..")) {
		bb_error_msg("'..' is not allowed in a property name");
		return EXIT_FAILURE;
	}

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		bb_perror_msg("failed to create socket");
		return EXIT_FAILURE;
	}

	/* Set timeout to prevent hangs */
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	safe_strncpy(addr.sun_path, ANDROID_PROP_SERVICE_SOCKET, sizeof(addr.sun_path));

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		bb_perror_msg("failed to connect to %s", ANDROID_PROP_SERVICE_SOCKET);
		close(sock);
		return EXIT_FAILURE;
	}

	/* 1. Try modern PROP_MSG_SETPROP2 protocol */
	cmd = PROP_MSG_SETPROP2;
	if (send_all(sock, &cmd, sizeof(cmd)) == 0 &&
	    send_all(sock, &name_len, sizeof(name_len)) == 0 &&
	    send_all(sock, name, name_len) == 0 &&
	    send_all(sock, &val_len, sizeof(val_len)) == 0 &&
	    send_all(sock, value, val_len) == 0) {

		if (read_all(sock, &result, sizeof(result)) == 0) {
			close(sock);
			if (result != PROP_SUCCESS) {
				bb_error_msg("failed to set property '%s' to '%s' (%s, status %u)",
				             name, value, android_prop_strerror(result), result);
				return EXIT_FAILURE;
			}
			return EXIT_SUCCESS;
		}
	}

	/* 2. Fallback to legacy 128-byte packet protocol */
	close(sock);
	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock >= 0) {
		char packet[128];
		memset(packet, 0, sizeof(packet));

		cmd = PROP_MSG_SETPROP;
		memcpy(packet, &cmd, 4);
		safe_strncpy(packet + 4, name, 32);
		safe_strncpy(packet + 4 + 32, value, 92);

		if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
			if (send_all(sock, packet, sizeof(packet)) == 0) {
				/* Some older daemons don't return a status code on legacy packets */
				read(sock, &result, sizeof(result));
				close(sock);
				return EXIT_SUCCESS;
			}
		}
		close(sock);
	}

	bb_error_msg("failed to set property '%s' to '%s'", name, value);
	return EXIT_FAILURE;
}
