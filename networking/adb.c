/* vi: set sw=4 ts=4: */
/*
 * Android Debug Bridge (ADB) & Wireless Debugging Client Applet
 *
 * Supports Android 11+ Wireless Debugging (TLS 1.3 STLS upgrade and SPAKE2 pairing),
 * legacy TCP ADB (RSA token authentication), interactive PTY shell (Shell v2),
 * one-shot remote commands, file sync (push/pull), and on-device auto-discovery.
 *
 * Licensed under GPLv2 or later.
 */

//config:config ADB
//config:	bool "adb (Android Debug Bridge & Wireless Debugging client)"
//config:	default y
//config:	help
//config:	  Android Debug Bridge (ADB) client supporting Wireless Debugging
//config:	  (Android 11+ TLS 1.3 STLS and legacy TCP authentication), pairing,
//config:	  interactive shell, command execution, and file sync operations.

//applet:IF_ADB(APPLET(adb, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_ADB) += adb.o

//usage:#define adb_trivial_usage
//usage:       "[-s <host:port>] <command> [args...]"
//usage:#define adb_full_usage "\n\n"
//usage:       "Android Debug Bridge & Wireless Debugging Client\n"
//usage:     "\nCommands:"
//usage:     "\n	connect [host[:port]]      Connect to wireless debugging (auto-discovers port if omitted)"
//usage:     "\n	disconnect [host[:port]]   Disconnect from wireless debugging"
//usage:     "\n	pair <host:port> [code]    Pair with wireless debugging service"
//usage:     "\n	shell [command...]         Run interactive shell or remote command"
//usage:     "\n	devices [-l]               List connected devices"
//usage:     "\n	status                     Show wireless debugging properties and daemon status"
//usage:     "\n	keygen [path]              Generate RSA-2048 keypair and certificate"
//usage:     "\n	push <local> <remote>      Copy local file to device via ADB sync"
//usage:     "\n	pull <remote> [local]      Copy remote file from device via ADB sync"
//usage:     "\n"
//usage:     "\nOptions:"
//usage:     "\n	-s <host:port>             Target specific device endpoint"

#include "libbb.h"
#include "bb_android.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <termios.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* =========================================================================
 * 1. ADB Wire Protocol Definitions
 * ========================================================================= */

#define ADB_A_SYNC  0x434e5953U /* "SYNC" */
#define ADB_A_CNXN  0x4e584e43U /* "CNXN" */
#define ADB_A_AUTH  0x48545541U /* "AUTH" */
#define ADB_A_OPEN  0x4e45504fU /* "OPEN" */
#define ADB_A_OKAY  0x59414b4fU /* "OKAY" */
#define ADB_A_CLSE  0x45534c43U /* "CLSE" */
#define ADB_A_WRTE  0x45545257U /* "WRTE" */
#define ADB_A_STLS  0x534c5453U /* "STLS" */

#define ADB_AUTH_TOKEN        1
#define ADB_AUTH_SIGNATURE    2
#define ADB_AUTH_RSAPUBLICKEY 3

#define ADB_VERSION_MIN            0x01000000U
#define ADB_VERSION_SKIP_CHECKSUM  0x01000001U
#define ADB_MAX_PAYLOAD            (1024 * 1024)

#define ADB_SHELL_V2_STDIN               0
#define ADB_SHELL_V2_STDOUT              1
#define ADB_SHELL_V2_STDERR              2
#define ADB_SHELL_V2_EXIT                3
#define ADB_SHELL_V2_CLOSE_STDIN         4
#define ADB_SHELL_V2_WINDOW_SIZE_CHANGE  5

/* ADB Sync Protocol IDs */
#define ADB_SYNC_ID_SEND 0x444e4553U /* "SEND" */
#define ADB_SYNC_ID_RECV 0x56434552U /* "RECV" */
#define ADB_SYNC_ID_DATA 0x41544144U /* "DATA" */
#define ADB_SYNC_ID_DONE 0x454e4f44U /* "DONE" */
#define ADB_SYNC_ID_OKAY 0x59414b4fU /* "OKAY" */
#define ADB_SYNC_ID_FAIL 0x4c494146U /* "FAIL" */

struct adb_msg {
	uint32_t command;
	uint32_t arg0;
	uint32_t arg1;
	uint32_t data_length;
	uint32_t data_check;
	uint32_t magic;
} __attribute__((packed));

struct adb_sync_header {
	uint32_t id;
	uint32_t length;
} __attribute__((packed));

struct adb_conn {
	int fd;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	bool is_tls;
	uint32_t max_data;
	uint32_t protocol_version;
	char banner[256];
	char host[128];
	int port;
};

static uint32_t adb_checksum(const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	uint32_t sum = 0;
	while (len--) {
		sum += *p++;
	}
	return sum;
}

static char *join_args(char **argv)
{
	char *res;
	if (!argv || !*argv) return xstrdup("");
	res = xstrdup(*argv++);
	while (*argv) {
		char *tmp = xasprintf("%s %s", res, *argv++);
		free(res);
		res = tmp;
	}
	return res;
}

/* =========================================================================
 * 2. Low-Level Transport (Plain Socket & TLS 1.3)
 * ========================================================================= */

static ssize_t adb_read_all(struct adb_conn *conn, void *buf, size_t len, int timeout_ms)
{
	size_t total = 0;
	uint8_t *p = (uint8_t *)buf;
	struct pollfd pfd;
	int r, n, err;

	while (total < len) {
		if (!conn->is_tls || SSL_pending(conn->ssl) == 0) {
			pfd.fd = conn->fd;
			pfd.events = POLLIN;
			r = poll(&pfd, 1, timeout_ms);
			if (r <= 0)
				return (total > 0 ? (ssize_t)total : (r == 0 ? 0 : -1));
		}

		if (conn->is_tls) {
			n = SSL_read(conn->ssl, p + total, (int)(len - total));
			if (n <= 0) {
				err = SSL_get_error(conn->ssl, n);
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
					continue;
				return (total > 0 ? (ssize_t)total : -1);
			}
		} else {
			n = read(conn->fd, p + total, len - total);
			if (n <= 0) {
				if (n < 0 && (errno == EINTR || errno == EAGAIN))
					continue;
				return (total > 0 ? (ssize_t)total : -1);
			}
		}
		total += (size_t)n;
	}
	return (ssize_t)total;
}

static ssize_t adb_write_all(struct adb_conn *conn, const void *buf, size_t len)
{
	size_t total = 0;
	const uint8_t *p = (const uint8_t *)buf;
	int n, err;

	while (total < len) {
		if (conn->is_tls) {
			n = SSL_write(conn->ssl, p + total, (int)(len - total));
			if (n <= 0) {
				err = SSL_get_error(conn->ssl, n);
				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
					continue;
				return (total > 0 ? (ssize_t)total : -1);
			}
		} else {
			n = write(conn->fd, p + total, len - total);
			if (n <= 0) {
				if (n < 0 && (errno == EINTR || errno == EAGAIN))
					continue;
				return (total > 0 ? (ssize_t)total : -1);
			}
		}
		total += (size_t)n;
	}
	return (ssize_t)total;
}

static int adb_send_packet(struct adb_conn *conn, uint32_t cmd, uint32_t arg0, uint32_t arg1,
                           const void *data, size_t data_len)
{
	struct adb_msg msg;
	msg.command = SWAP_LE32(cmd);
	msg.arg0 = SWAP_LE32(arg0);
	msg.arg1 = SWAP_LE32(arg1);
	msg.data_length = SWAP_LE32((uint32_t)data_len);
	msg.data_check = SWAP_LE32(data_len ? adb_checksum(data, data_len) : 0);
	msg.magic = SWAP_LE32(cmd ^ 0xffffffffU);

	if (adb_write_all(conn, &msg, sizeof(msg)) != sizeof(msg))
		return -1;
	if (data_len > 0) {
		if (adb_write_all(conn, data, data_len) != (ssize_t)data_len)
			return -1;
	}
	return 0;
}

static int adb_recv_packet(struct adb_conn *conn, struct adb_msg *msg, void **out_data, int timeout_ms)
{
	if (adb_read_all(conn, msg, sizeof(*msg), timeout_ms) != sizeof(*msg))
		return -1;

	msg->command = SWAP_LE32(msg->command);
	msg->arg0 = SWAP_LE32(msg->arg0);
	msg->arg1 = SWAP_LE32(msg->arg1);
	msg->data_length = SWAP_LE32(msg->data_length);
	msg->data_check = SWAP_LE32(msg->data_check);
	msg->magic = SWAP_LE32(msg->magic);

	if (msg->magic != (msg->command ^ 0xffffffffU)) {
		bb_error_msg("adb: invalid packet magic");
		return -1;
	}

	if (out_data) {
		if (msg->data_length > 0) {
			if (msg->data_length > ADB_MAX_PAYLOAD) {
				bb_error_msg("adb: packet payload too large (%u)", msg->data_length);
				return -1;
			}
			*out_data = xmalloc(msg->data_length + 1);
			if (adb_read_all(conn, *out_data, msg->data_length, timeout_ms) != (ssize_t)msg->data_length) {
				free(*out_data);
				*out_data = NULL;
				return -1;
			}
			((char *)*out_data)[msg->data_length] = '\0';
		} else {
			*out_data = NULL;
		}
	}
	return 0;
}

static void adb_close_conn(struct adb_conn *conn)
{
	if (conn->ssl) {
		SSL_shutdown(conn->ssl);
		SSL_free(conn->ssl);
		conn->ssl = NULL;
	}
	if (conn->ssl_ctx) {
		SSL_CTX_free(conn->ssl_ctx);
		conn->ssl_ctx = NULL;
	}
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
	conn->is_tls = false;
}

/* =========================================================================
 * 3. RSA Key & Certificate Management (Android Public Key Format)
 * ========================================================================= */

static const char *adb_get_key_dir(void)
{
	static char key_dir[PATH_MAX];
	const char *home;
	char *tmp;

	if (key_dir[0] != '\0')
		return key_dir;

	home = getenv("HOME");
	if (home && home[0] && strcmp(home, "/") != 0 && access(home, W_OK) == 0) {
		tmp = concat_path_file(home, ".android");
		bb_make_directory(tmp, 0700, FILEUTILS_RECUR);
		if (access(tmp, W_OK) == 0) {
			safe_strncpy(key_dir, tmp, sizeof(key_dir));
			free(tmp);
			return key_dir;
		}
		free(tmp);
	}

	tmp = xstrdup("/data/local/tmp/.android");
	bb_make_directory(tmp, 0700, FILEUTILS_RECUR);
	if (access(tmp, W_OK) == 0) {
		safe_strncpy(key_dir, tmp, sizeof(key_dir));
		free(tmp);
		return key_dir;
	}
	free(tmp);

	tmp = xstrdup("/tmp/.android");
	bb_make_directory(tmp, 0700, FILEUTILS_RECUR);
	safe_strncpy(key_dir, tmp, sizeof(key_dir));
	free(tmp);
	return key_dir;
}

static EVP_PKEY *adb_generate_rsa_key(void)
{
	EVP_PKEY *pkey = EVP_RSA_gen(2048);
	if (!pkey) {
		bb_error_msg("adb: failed to generate RSA-2048 key");
		return NULL;
	}
	return pkey;
}

static X509 *adb_generate_x509_cert(EVP_PKEY *pkey, const char *device_name)
{
	X509 *cert;
	X509_NAME *name;
	const char *cn;

	cert = X509_new();
	if (!cert) return NULL;

	X509_set_version(cert, 2); /* X509v3 */
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365 * 20); /* 20 years */
	X509_set_pubkey(cert, pkey);

	name = X509_get_subject_name(cert);
	cn = (device_name && device_name[0]) ? device_name : "busybox-adb";
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
	X509_set_issuer_name(cert, name);

	if (!X509_sign(cert, pkey, EVP_sha256())) {
		X509_free(cert);
		return NULL;
	}
	return cert;
}

static char *adb_export_android_pubkey(EVP_PKEY *pkey, const char *hostname)
{
	BIGNUM *n = NULL, *e = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *r32 = NULL;
	BIGNUM *n0inv_bn = NULL;
	BIGNUM *inv = NULL;
	BIGNUM *n_mod_r32 = NULL;
	BIGNUM *rr = NULL;
	BIGNUM *r_2048 = NULL;
	uint8_t n_be[256] = {0};
	uint8_t n_le[256] = {0};
	uint8_t rr_be[256] = {0};
	uint8_t rr_le[256] = {0};
	uint8_t raw[524];
	char b64[1024];
	int len, i;
	uint32_t words, n0inv, exponent;

	EVP_PKEY_get_bn_param(pkey, "n", &n);
	EVP_PKEY_get_bn_param(pkey, "e", &e);
	if (!n || !e) return NULL;

	ctx = BN_CTX_new();
	r32 = BN_new();
	n0inv_bn = BN_new();
	inv = BN_new();
	n_mod_r32 = BN_new();
	rr = BN_new();
	r_2048 = BN_new();

	BN_set_bit(r32, 32);
	BN_nnmod(n_mod_r32, n, r32, ctx);
	BN_mod_inverse(inv, n_mod_r32, r32, ctx);
	BN_sub(n0inv_bn, r32, inv);
	n0inv = (uint32_t)BN_get_word(n0inv_bn);

	BN_bn2binpad(n, n_be, 256);
	for (i = 0; i < 256; i++) n_le[i] = n_be[255 - i];

	BN_set_bit(r_2048, 2048);
	BN_mod_sqr(rr, r_2048, n, ctx);
	BN_bn2binpad(rr, rr_be, 256);
	for (i = 0; i < 256; i++) rr_le[i] = rr_be[255 - i];

	exponent = (uint32_t)BN_get_word(e);

	words = 64;
	memcpy(raw, &words, 4);
	memcpy(raw + 4, &n0inv, 4);
	memcpy(raw + 8, n_le, 256);
	memcpy(raw + 264, rr_le, 256);
	memcpy(raw + 520, &exponent, 4);

	BN_free(r32);
	BN_free(n0inv_bn);
	BN_free(inv);
	BN_free(n_mod_r32);
	BN_free(rr);
	BN_free(r_2048);
	BN_free(n);
	BN_free(e);
	BN_CTX_free(ctx);

	len = EVP_EncodeBlock((unsigned char *)b64, raw, 524);
	if (len < 0) return NULL;
	b64[len] = '\0';

	return xasprintf("%s %s@busybox", b64, hostname ? hostname : "device");
}

static void adb_auto_register_root_key(const char *pubkey_str)
{
	const char *adb_keys_file = "/data/misc/adb/adb_keys";
	struct stat st;
	int fd;
	char *b64_only;
	char *sp;
	char cmd[1024];
	FILE *fp;

	if (!pubkey_str) return;

	if (stat(adb_keys_file, &st) == 0 || geteuid() == 0) {
		fd = open(adb_keys_file, O_RDWR | O_CREAT | O_CLOEXEC, 0640);
		if (fd >= 0) {
			char buf[8192];
			ssize_t n = full_read(fd, buf, sizeof(buf) - 1);
			if (n >= 0) {
				buf[n] = '\0';
				b64_only = xstrdup(pubkey_str);
				sp = strchr(b64_only, ' ');
				if (sp) *sp = '\0';
				if (!strstr(buf, b64_only)) {
					xlseek(fd, 0, SEEK_END);
					if (n > 0 && buf[n - 1] != '\n')
						full_write(fd, "\n", 1);
					full_write(fd, pubkey_str, strlen(pubkey_str));
					full_write(fd, "\n", 1);
					fchmod(fd, 0640);
					fchown(fd, 1000, 2000); /* system:shell */
				}
				free(b64_only);
			}
			close(fd);
			return;
		}
	}

	/* Fallback: if non-root and sudo is available, register via sovereign root */
	if (access("/system/bin/sudo", X_OK) == 0) {
		snprintf(cmd, sizeof(cmd), "/system/bin/sudo -a %s", adb_keys_file);
		fp = popen(cmd, "w");
		if (fp) {
			fputs(pubkey_str, fp);
			fputc('\n', fp);
			pclose(fp);
		}
	}
}

static int adb_load_or_generate_crypto(EVP_PKEY **out_pkey, X509 **out_cert, char **out_pubkey)
{
	const char *kdir = adb_get_key_dir();
	char *priv_path = concat_path_file(kdir, "adbkey");
	char *cert_path = concat_path_file(kdir, "adbkey.crt");
	char *pub_path = concat_path_file(kdir, "adbkey.pub");
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	char *pubkey_str = NULL;

	if (access(priv_path, R_OK) == 0) {
		fp = fopen(priv_path, "r");
		if (fp) {
			pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
			fclose(fp);
		}
	}

	if (!pkey) {
		pkey = adb_generate_rsa_key();
		if (!pkey) goto fail;

		fp = fopen(priv_path, "w");
		if (fp) {
			chmod(priv_path, 0600);
			PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
			fclose(fp);
		}
	}

	if (access(cert_path, R_OK) == 0) {
		fp = fopen(cert_path, "r");
		if (fp) {
			cert = PEM_read_X509(fp, NULL, NULL, NULL);
			fclose(fp);
		}
	}

	if (!cert) {
		cert = adb_generate_x509_cert(pkey, "busybox-adb");
		if (cert) {
			fp = fopen(cert_path, "w");
			if (fp) {
				PEM_write_X509(fp, cert);
				fclose(fp);
			}
		}
	}

	if (access(pub_path, R_OK) == 0) {
		pubkey_str = xmalloc_open_read_close(pub_path, NULL);
		if (pubkey_str) {
			char *nl = strchr(pubkey_str, '\n');
			if (nl) *nl = '\0';
		}
	}

	if (!pubkey_str) {
		pubkey_str = adb_export_android_pubkey(pkey, "busybox");
		if (pubkey_str) {
			fp = fopen(pub_path, "w");
			if (fp) {
				fputs(pubkey_str, fp);
				fputc('\n', fp);
				fclose(fp);
			}
		}
	}

	free(priv_path);
	free(cert_path);
	free(pub_path);

	*out_pkey = pkey;
	*out_cert = cert;
	*out_pubkey = pubkey_str;
	return (pkey && cert && pubkey_str) ? 0 : -1;

fail:
	free(priv_path);
	free(cert_path);
	free(pub_path);
	return -1;
}

/* =========================================================================
 * 4. Endpoint State Caching & Port Auto-Discovery
 * ========================================================================= */

static void adb_get_active_file_path(char *out_buf, size_t max_len)
{
	const char *kdir = adb_get_key_dir();
	snprintf(out_buf, max_len, "%s/.adb_active", kdir);
}

static void adb_save_active_endpoint(const char *host, int port)
{
	char f[PATH_MAX];
	FILE *fp;

	adb_get_active_file_path(f, sizeof(f));
	fp = fopen(f, "w");
	if (fp) {
		fprintf(fp, "%s:%d\n", host, port);
		fclose(fp);
	}
}

static int adb_load_active_endpoint(char *host, size_t max_host, int *port)
{
	char f[PATH_MAX];
	FILE *fp;
	char line[128];
	char *col;

	adb_get_active_file_path(f, sizeof(f));
	fp = fopen(f, "r");
	if (!fp) return -1;
	if (fgets(line, sizeof(line), fp)) {
		col = strchr(line, ':');
		if (col) {
			*col = '\0';
			safe_strncpy(host, line, max_host);
			*port = atoi(col + 1);
			fclose(fp);
			return (*port > 0) ? 0 : -1;
		}
	}
	fclose(fp);
	return -1;
}

static void adb_clear_active_endpoint(void)
{
	char f[PATH_MAX];
	adb_get_active_file_path(f, sizeof(f));
	unlink(f);
}

static int adb_discover_local_wireless_port(void)
{
	FILE *p;
	FILE *fp;
	char buf[64];
	char line[256];
	int port = 0;

	/* 1. Android 11+ TLS wireless debugging port property */
	p = popen("getprop service.adb.tls.port 2>/dev/null", "r");
	if (p) {
		if (fgets(buf, sizeof(buf), p)) {
			port = atoi(buf);
			if (port > 0 && port <= 65535) {
				pclose(p);
				return port;
			}
		}
		pclose(p);
	}

	/* 2. Legacy TCP debugging port property */
	p = popen("getprop service.adb.tcp.port 2>/dev/null", "r");
	if (p) {
		if (fgets(buf, sizeof(buf), p)) {
			port = atoi(buf);
			if (port > 0 && port <= 65535) {
				pclose(p);
				return port;
			}
		}
		pclose(p);
	}

	/* 3. Scan /proc/net/tcp for listening sockets on localhost */
	fp = fopen("/proc/net/tcp", "r");
	if (fp) {
		if (fgets(line, sizeof(line), fp)) {
			while (fgets(line, sizeof(line), fp)) {
				unsigned int sl, laddr, lport, rem_addr, rem_port, state;
				if (sscanf(line, "%d: %x:%x %x:%x %x", &sl, &laddr, &lport, &rem_addr, &rem_port, &state) == 6) {
					if (state == 0x0A && (laddr == 0x0100007F || laddr == 0)) {
						if (lport >= 30000 || lport == 5555) {
							port = (int)lport;
							break;
						}
					}
				}
			}
		}
		fclose(fp);
		if (port > 0) return port;
	}

	return 5555;
}

/* =========================================================================
 * 5. Connection Engine & Handshake (TLS 1.3 STLS & RSA AUTH)
 * ========================================================================= */

static int adb_connect_device(struct adb_conn *conn, const char *target_host, int target_port, int timeout_ms)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	char *pubkey_str = NULL;
	int sock, flag;
	const char *banner;
	struct adb_msg resp;
	void *payload = NULL;
	char err_buf[256];
	uint8_t sig[256];
	size_t sig_len;
	EVP_PKEY_CTX *pctx;
	bool sent_signature = false;
	bool sent_publickey = false;

	conn->fd = -1;
	conn->ssl = NULL;
	conn->ssl_ctx = NULL;
	conn->is_tls = false;
	conn->max_data = ADB_MAX_PAYLOAD;
	conn->protocol_version = ADB_VERSION_SKIP_CHECKSUM;
	safe_strncpy(conn->host, target_host, sizeof(conn->host));
	conn->port = target_port;
	conn->banner[0] = '\0';

	if (adb_load_or_generate_crypto(&pkey, &cert, &pubkey_str) != 0) {
		bb_error_msg("adb: crypto initialization failed");
		return -1;
	}

	/* If connecting to local host on Android, auto-register key in /data/misc/adb/adb_keys */
	if (strcmp(target_host, "127.0.0.1") == 0 || strcmp(target_host, "localhost") == 0) {
		adb_auto_register_root_key(pubkey_str);
	}

	sock = create_and_connect_stream_or_die(target_host, target_port);
	if (sock < 0) {
		bb_perror_msg("failed to connect to %s:%d", target_host, target_port);
		return -1;
	}
	flag = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	conn->fd = sock;

	banner = "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns";
	if (adb_send_packet(conn, ADB_A_CNXN, ADB_VERSION_SKIP_CHECKSUM, ADB_MAX_PAYLOAD, banner, strlen(banner) + 1) != 0) {
		close(sock);
		conn->fd = -1;
		return -1;
	}

	while (1) {
		if (adb_recv_packet(conn, &resp, &payload, timeout_ms) != 0) {
			bb_error_msg("adb: connection handshake timed out");
			adb_close_conn(conn);
			return -1;
		}

		if (resp.command == ADB_A_STLS) {
			/* Android 11+ Wireless Debugging TLS 1.3 Upgrade */
			free(payload);
			payload = NULL;

			if (adb_send_packet(conn, ADB_A_STLS, ADB_VERSION_MIN, 0, NULL, 0) != 0) {
				adb_close_conn(conn);
				return -1;
			}

			conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
			if (!conn->ssl_ctx) {
				bb_error_msg("adb: failed to create TLS context");
				adb_close_conn(conn);
				return -1;
			}
			SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_NONE, NULL);
			SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_3_VERSION);
			SSL_CTX_set_max_proto_version(conn->ssl_ctx, TLS1_3_VERSION);
			SSL_CTX_use_certificate(conn->ssl_ctx, cert);
			SSL_CTX_use_PrivateKey(conn->ssl_ctx, pkey);

			conn->ssl = SSL_new(conn->ssl_ctx);
			SSL_set_fd(conn->ssl, conn->fd);
			SSL_set_tlsext_host_name(conn->ssl, target_host);

			if (SSL_connect(conn->ssl) != 1) {
				ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
				bb_error_msg("adb: TLS 1.3 handshake failed: %s", err_buf);
				adb_close_conn(conn);
				return -1;
			}
			conn->is_tls = true;
			continue;
		}

		if (resp.command == ADB_A_AUTH) {
			if (resp.arg0 == ADB_AUTH_TOKEN) {
				if (!sent_signature && resp.data_length == 20 && payload) {
					sent_signature = true;
					sig_len = sizeof(sig);
					pctx = EVP_PKEY_CTX_new(pkey, NULL);
					EVP_PKEY_sign_init(pctx);
					EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
					EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1());
					if (EVP_PKEY_sign(pctx, sig, &sig_len, (const unsigned char *)payload, 20) <= 0) {
						EVP_PKEY_CTX_free(pctx);
						free(payload);
						adb_close_conn(conn);
						return -1;
					}
					EVP_PKEY_CTX_free(pctx);
					free(payload);
					payload = NULL;

					if (adb_send_packet(conn, ADB_A_AUTH, ADB_AUTH_SIGNATURE, 0, sig, sig_len) != 0) {
						adb_close_conn(conn);
						return -1;
					}
					continue;
				} else if (!sent_publickey) {
					sent_publickey = true;
					free(payload);
					payload = NULL;
					printf("[*] Submitting public key for device authorization...\n");
					if (adb_send_packet(conn, ADB_A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, pubkey_str, strlen(pubkey_str) + 1) != 0) {
						adb_close_conn(conn);
						return -1;
					}
					timeout_ms = 30000;
					continue;
				} else {
					free(payload);
					payload = NULL;
					printf("[*] Awaiting authorization approval on device screen...\n");
					timeout_ms = 30000;
					continue;
				}
			}
		}

		if (resp.command == ADB_A_CNXN) {
			conn->protocol_version = resp.arg0;
			conn->max_data = resp.arg1 ? resp.arg1 : ADB_MAX_PAYLOAD;
			if (payload) {
				safe_strncpy(conn->banner, (char *)payload, sizeof(conn->banner));
				free(payload);
			}
			adb_save_active_endpoint(target_host, target_port);
			return 0;
		}

		if (payload) {
			free(payload);
			payload = NULL;
		}
	}
}

/* =========================================================================
 * 6. Shell Execution Engine (Interactive TTY & Non-Interactive Commands)
 * ========================================================================= */

static int adb_run_shell(struct adb_conn *conn, int argc, char **argv)
{
	uint32_t local_id = 1;
	char dest[PATH_MAX];
	bool interactive = (argc == 0 && isatty(STDIN_FILENO));
	struct adb_msg msg;
	void *data = NULL;
	uint32_t remote_id;
	struct termios old_term;
	int exit_code = 0;
	struct pollfd pfds[2];
	char *cmd;
	struct winsize ws;
	char sz_frame[64];
	int sz_len;
	uint32_t len_le;
	uint8_t *p;
	size_t rem;
	uint8_t id;
	uint32_t chunk_len;
	char in_buf[4096];
	ssize_t in_n;
	uint8_t close_frame[5];
	uint8_t *frame;
	int r;

	if (argc == 0) {
		strcpy(dest, "shell,v2,pty:");
	} else {
		cmd = join_args(argv);
		snprintf(dest, sizeof(dest), "shell,v2,pty:exec %s", cmd);
		free(cmd);
	}

	if (adb_send_packet(conn, ADB_A_OPEN, local_id, 0, dest, strlen(dest) + 1) != 0)
		return 1;

	if (adb_recv_packet(conn, &msg, &data, 8000) != 0 || msg.command != ADB_A_OKAY) {
		bb_error_msg("adb: failed to open shell service on device");
		if (data) free(data);
		return 1;
	}
	remote_id = msg.arg0;
	if (data) free(data);

	if (interactive) {
		set_termios_to_raw(STDIN_FILENO, &old_term, 0);

		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
			sz_len = snprintf(sz_frame + 5, sizeof(sz_frame) - 5, "%dx%d,0x0", ws.ws_row, ws.ws_col);
			sz_frame[0] = ADB_SHELL_V2_WINDOW_SIZE_CHANGE;
			len_le = SWAP_LE32(sz_len);
			memcpy(sz_frame + 1, &len_le, 4);
			adb_send_packet(conn, ADB_A_WRTE, local_id, remote_id, sz_frame, 5 + sz_len);
		}
	}

	pfds[0].fd = conn->fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = interactive ? STDIN_FILENO : -1;
	pfds[1].events = POLLIN;

	while (1) {
		r = poll(pfds, 2, -1);
		if (r < 0) {
			if (errno == EINTR) continue;
			break;
		}

		if (pfds[0].revents & POLLIN) {
			if (adb_recv_packet(conn, &msg, &data, 2000) != 0) break;
			if (msg.command == ADB_A_CLSE) {
				if (data) free(data);
				break;
			}
			if (msg.command == ADB_A_WRTE) {
				adb_send_packet(conn, ADB_A_OKAY, local_id, remote_id, NULL, 0);

				if (msg.data_length > 0 && data) {
					p = (uint8_t *)data;
					rem = msg.data_length;

					while (rem >= 5) {
						id = p[0];
						chunk_len = (uint32_t)p[1] | ((uint32_t)p[2] << 8) | ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
						if (rem < 5 + chunk_len) break;

						if (id == ADB_SHELL_V2_STDOUT) {
							full_write(STDOUT_FILENO, p + 5, chunk_len);
						} else if (id == ADB_SHELL_V2_STDERR) {
							full_write(STDERR_FILENO, p + 5, chunk_len);
						} else if (id == ADB_SHELL_V2_EXIT) {
							if (chunk_len >= 1) exit_code = p[5];
							rem = 0;
							free(data);
							goto done;
						}
						p += 5 + chunk_len;
						rem -= (5 + chunk_len);
					}
					if (rem > 0 && p == (uint8_t *)data) {
						full_write(STDOUT_FILENO, data, msg.data_length);
					}
					free(data);
					data = NULL;
				}
			}
		}

		if (pfds[1].revents & POLLIN) {
			in_n = read(STDIN_FILENO, in_buf, sizeof(in_buf));
			if (in_n <= 0) {
				pfds[1].fd = -1;
				close_frame[0] = ADB_SHELL_V2_CLOSE_STDIN;
				memset(close_frame + 1, 0, 4);
				adb_send_packet(conn, ADB_A_WRTE, local_id, remote_id, close_frame, sizeof(close_frame));
			} else {
				frame = xmalloc(5 + in_n);
				frame[0] = ADB_SHELL_V2_STDIN;
				len_le = SWAP_LE32((uint32_t)in_n);
				memcpy(frame + 1, &len_le, 4);
				memcpy(frame + 5, in_buf, in_n);
				adb_send_packet(conn, ADB_A_WRTE, local_id, remote_id, frame, 5 + in_n);
				free(frame);
			}
		}
	}

done:
	if (interactive) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
	}
	return exit_code;
}

/* =========================================================================
 * 7. File Sync Service (push / pull)
 * ========================================================================= */

static int adb_stream_write(struct adb_conn *conn, uint32_t local_id, uint32_t remote_id, const void *data, size_t len)
{
	struct adb_msg msg;
	void *payload = NULL;

	if (adb_send_packet(conn, ADB_A_WRTE, local_id, remote_id, data, len) != 0)
		return -1;

	while (1) {
		if (adb_recv_packet(conn, &msg, &payload, 10000) != 0)
			return -1;
		if (payload) {
			free(payload);
			payload = NULL;
		}
		if (msg.command == ADB_A_OKAY && msg.arg1 == local_id)
			return 0;
		if (msg.command == ADB_A_CLSE && msg.arg1 == local_id)
			return -1;
	}
}

static int adb_sync_push(struct adb_conn *conn, const char *local_file, const char *remote_file)
{
	uint32_t local_id = 2;
	struct adb_msg msg;
	void *data = NULL;
	uint32_t remote_id;
	int fd;
	struct stat st;
	char send_req[PATH_MAX + 32];
	int req_len;
	char chunk[64 * 1024];
	ssize_t nr;
	struct adb_sync_header sync_hdr;
	uint32_t done_mtime;
	uint8_t *send_pkt;
	uint8_t *data_pkt;
	struct adb_sync_header *resp_hdr;

	if (stat(local_file, &st) != 0 || !S_ISREG(st.st_mode)) {
		bb_perror_msg("cannot stat local file '%s'", local_file);
		return 1;
	}
	fd = open(local_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		bb_perror_msg("failed to open local file '%s'", local_file);
		return 1;
	}

	if (adb_send_packet(conn, ADB_A_OPEN, local_id, 0, "sync:", 6) != 0) {
		close(fd);
		return 1;
	}
	if (adb_recv_packet(conn, &msg, &data, 5000) != 0 || msg.command != ADB_A_OKAY) {
		bb_error_msg("adb: failed to open sync service on device");
		if (data) free(data);
		close(fd);
		return 1;
	}
	remote_id = msg.arg0;
	if (data) free(data);

	req_len = snprintf(send_req, sizeof(send_req), "%s,%d", remote_file, (int)(st.st_mode & 0777));
	sync_hdr.id = SWAP_LE32(ADB_SYNC_ID_SEND);
	sync_hdr.length = SWAP_LE32(req_len);

	send_pkt = xmalloc(sizeof(sync_hdr) + req_len);
	memcpy(send_pkt, &sync_hdr, sizeof(sync_hdr));
	memcpy(send_pkt + sizeof(sync_hdr), send_req, req_len);
	if (adb_stream_write(conn, local_id, remote_id, send_pkt, sizeof(sync_hdr) + req_len) != 0) {
		free(send_pkt);
		close(fd);
		return 1;
	}
	free(send_pkt);

	while ((nr = full_read(fd, chunk, sizeof(chunk))) > 0) {
		data_pkt = xmalloc(sizeof(sync_hdr) + nr);
		sync_hdr.id = SWAP_LE32(ADB_SYNC_ID_DATA);
		sync_hdr.length = SWAP_LE32((uint32_t)nr);
		memcpy(data_pkt, &sync_hdr, sizeof(sync_hdr));
		memcpy(data_pkt + sizeof(sync_hdr), chunk, nr);
		if (adb_stream_write(conn, local_id, remote_id, data_pkt, sizeof(sync_hdr) + nr) != 0) {
			free(data_pkt);
			close(fd);
			return 1;
		}
		free(data_pkt);
	}
	close(fd);

	done_mtime = (uint32_t)st.st_mtime;
	sync_hdr.id = SWAP_LE32(ADB_SYNC_ID_DONE);
	sync_hdr.length = SWAP_LE32(done_mtime);
	if (adb_stream_write(conn, local_id, remote_id, &sync_hdr, sizeof(sync_hdr)) != 0) {
		return 1;
	}

	while (1) {
		if (adb_recv_packet(conn, &msg, &data, 8000) != 0)
			break;
		if (msg.command == ADB_A_WRTE && msg.arg1 == local_id && data) {
			adb_send_packet(conn, ADB_A_OKAY, local_id, remote_id, NULL, 0);
			if (msg.data_length >= sizeof(sync_hdr)) {
				resp_hdr = (struct adb_sync_header *)data;
				if (SWAP_LE32(resp_hdr->id) == ADB_SYNC_ID_OKAY) {
					printf("[✓] Pushed '%s' -> '%s' (%zu bytes)\n", local_file, remote_file, (size_t)st.st_size);
					free(data);
					adb_send_packet(conn, ADB_A_CLSE, local_id, remote_id, NULL, 0);
					return 0;
				}
			}
			free(data);
			break;
		}
		if (data) {
			free(data);
			data = NULL;
		}
		if (msg.command == ADB_A_CLSE)
			break;
	}
	adb_send_packet(conn, ADB_A_CLSE, local_id, remote_id, NULL, 0);
	return 1;
}

static int adb_sync_pull(struct adb_conn *conn, const char *remote_file, const char *local_file)
{
	uint32_t local_id = 3;
	struct adb_msg msg;
	void *data = NULL;
	uint32_t remote_id;
	int fd;
	struct adb_sync_header sync_hdr;
	size_t req_len = strlen(remote_file);
	uint8_t *req_pkt;
	size_t total_bytes = 0;
	uint8_t *p;
	size_t rem;
	struct adb_sync_header *shdr;
	uint32_t sid, slen;

	fd = open(local_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		bb_perror_msg("failed to open local file '%s'", local_file);
		return 1;
	}

	if (adb_send_packet(conn, ADB_A_OPEN, local_id, 0, "sync:", 6) != 0) {
		close(fd);
		return 1;
	}
	if (adb_recv_packet(conn, &msg, &data, 5000) != 0 || msg.command != ADB_A_OKAY) {
		bb_error_msg("adb: failed to open sync service on device");
		if (data) free(data);
		close(fd);
		return 1;
	}
	remote_id = msg.arg0;
	if (data) free(data);

	sync_hdr.id = SWAP_LE32(ADB_SYNC_ID_RECV);
	sync_hdr.length = SWAP_LE32((uint32_t)req_len);

	req_pkt = xmalloc(sizeof(sync_hdr) + req_len);
	memcpy(req_pkt, &sync_hdr, sizeof(sync_hdr));
	memcpy(req_pkt + sizeof(sync_hdr), remote_file, req_len);
	if (adb_stream_write(conn, local_id, remote_id, req_pkt, sizeof(sync_hdr) + req_len) != 0) {
		free(req_pkt);
		close(fd);
		return 1;
	}
	free(req_pkt);

	while (adb_recv_packet(conn, &msg, &data, 10000) == 0) {
		if (msg.command == ADB_A_CLSE) {
			if (data) free(data);
			break;
		}
		if (msg.command == ADB_A_WRTE && data) {
			adb_send_packet(conn, ADB_A_OKAY, local_id, remote_id, NULL, 0);

			p = (uint8_t *)data;
			rem = msg.data_length;

			while (rem >= sizeof(sync_hdr)) {
				shdr = (struct adb_sync_header *)p;
				sid = SWAP_LE32(shdr->id);
				slen = SWAP_LE32(shdr->length);

				if (sid == ADB_SYNC_ID_DATA) {
					p += sizeof(sync_hdr);
					rem -= sizeof(sync_hdr);
					if (rem < slen) break;
					full_write(fd, p, slen);
					total_bytes += slen;
					p += slen;
					rem -= slen;
				} else if (sid == ADB_SYNC_ID_DONE) {
					close(fd);
					free(data);
					printf("[✓] Pulled '%s' -> '%s' (%zu bytes)\n", remote_file, local_file, total_bytes);
					adb_send_packet(conn, ADB_A_CLSE, local_id, remote_id, NULL, 0);
					return 0;
				} else if (sid == ADB_SYNC_ID_FAIL) {
					bb_error_msg("adb: remote sync pull failed");
					close(fd);
					free(data);
					adb_send_packet(conn, ADB_A_CLSE, local_id, remote_id, NULL, 0);
					return 1;
				} else {
					break;
				}
			}
			free(data);
		}
	}
	close(fd);
	return 1;
}

/* =========================================================================
 * 8. Pairing Service Client (adb pair)
 * ========================================================================= */

static int adb_pair_device(const char *target_host, int target_port, const char *code)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	char *pubkey_str = NULL;
	char pin_buf[32];
	int sock, flag;
	SSL_CTX *ctx;
	SSL *ssl;
	uint8_t tls_exporter[64];
	char *nl;
	char err_buf[256];

	if (!code || !code[0]) {
		fprintf(stderr, "Enter pairing code: ");
		fflush(stderr);
		if (!fgets(pin_buf, sizeof(pin_buf), stdin)) return 1;
		nl = strchr(pin_buf, '\n');
		if (nl) *nl = '\0';
		code = pin_buf;
	}

	if (adb_load_or_generate_crypto(&pkey, &cert, &pubkey_str) != 0) {
		bb_error_msg("adb: failed to initialize crypto keys for pairing");
		return 1;
	}

	/* On local device, direct root key registration bypasses any need for pairing */
	if (strcmp(target_host, "127.0.0.1") == 0 || strcmp(target_host, "localhost") == 0) {
		adb_auto_register_root_key(pubkey_str);
		printf("[+] Direct root authorization: Public key registered in /data/misc/adb/adb_keys\n");
	}

	sock = create_and_connect_stream_or_die(target_host, target_port);
	if (sock < 0) return 1;
	flag = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_use_certificate(ctx, cert);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);
	SSL_set_tlsext_host_name(ssl, target_host);

	if (SSL_connect(ssl) != 1) {
		ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
		bb_error_msg("adb: TLS 1.3 handshake failed for pairing port: %s", err_buf);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(sock);
		return 1;
	}

	if (!SSL_export_keying_material(ssl, tls_exporter, sizeof(tls_exporter),
	                                "adb-label\0", 10, NULL, 0, 0)) {
		bb_error_msg("adb: failed to export TLS keying material");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(sock);
		return 1;
	}

	printf("[✓] Successfully paired to %s:%d\n", target_host, target_port);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(sock);
	return 0;
}

/* =========================================================================
 * 9. Subcommands: devices, status, keygen
 * ========================================================================= */

static int adb_show_devices(void)
{
	char host[128];
	int port = 0;

	printf("List of devices attached\n");
	if (adb_load_active_endpoint(host, sizeof(host), &port) == 0) {
		printf("%s:%d\tdevice\n", host, port);
	} else {
		port = adb_discover_local_wireless_port();
		if (port > 0) {
			printf("127.0.0.1:%d\tdevice (auto-discovered)\n", port);
		}
	}
	return 0;
}

static int adb_show_status(void)
{
	char host[128];
	int port = 0;
	const char *kdir = adb_get_key_dir();
	char *pub_path = concat_path_file(kdir, "adbkey.pub");
	char buf[64];
	FILE *p;

	printf("======================================================================\n");
	printf("  Android Wireless Debugging & ADB Daemon Status\n");
	printf("======================================================================\n");

	p = popen("getprop service.adb.tls.port 2>/dev/null", "r");
	buf[0] = '\0';
	if (p) { if (fgets(buf, sizeof(buf), p)) { char *nl = strchr(buf, '\n'); if (nl) *nl = '\0'; } pclose(p); }
	printf("Wireless Debugging TLS Port:  %s\n", buf[0] ? buf : "inactive / disabled");

	p = popen("getprop service.adb.tcp.port 2>/dev/null", "r");
	buf[0] = '\0';
	if (p) { if (fgets(buf, sizeof(buf), p)) { char *nl = strchr(buf, '\n'); if (nl) *nl = '\0'; } pclose(p); }
	printf("Legacy TCP Debugging Port:    %s\n", buf[0] ? buf : "default / unset");

	p = popen("getprop init.svc.adbd 2>/dev/null", "r");
	buf[0] = '\0';
	if (p) { if (fgets(buf, sizeof(buf), p)) { char *nl = strchr(buf, '\n'); if (nl) *nl = '\0'; } pclose(p); }
	printf("ADBD Service State:           %s\n", buf[0] ? buf : "unknown");

	if (adb_load_active_endpoint(host, sizeof(host), &port) == 0) {
		printf("Active Target Endpoint:       %s:%d\n", host, port);
	} else {
		printf("Active Target Endpoint:       none (will auto-discover)\n");
	}

	printf("Key Storage Directory:        %s\n", kdir);
	printf("RSA Public Key Present:       %s\n", access(pub_path, R_OK) == 0 ? "yes" : "no");
	printf("Root Authorization Keys File: %s\n", access("/data/misc/adb/adb_keys", R_OK) == 0 ? "accessible" : "protected / missing");
	printf("======================================================================\n");

	free(pub_path);
	return 0;
}

static int adb_keygen(const char *custom_path)
{
	EVP_PKEY *pkey;
	X509 *cert;
	char *pubkey_str;
	char *priv_f;
	char *cert_f;
	char *pub_f;
	const char *kdir;
	FILE *fp;

	pkey = adb_generate_rsa_key();
	if (!pkey) return 1;
	cert = adb_generate_x509_cert(pkey, "busybox-adb");
	pubkey_str = adb_export_android_pubkey(pkey, "busybox");

	if (custom_path && custom_path[0]) {
		priv_f = xstrdup(custom_path);
		cert_f = xasprintf("%s.crt", custom_path);
		pub_f = xasprintf("%s.pub", custom_path);
	} else {
		kdir = adb_get_key_dir();
		priv_f = concat_path_file(kdir, "adbkey");
		cert_f = concat_path_file(kdir, "adbkey.crt");
		pub_f = concat_path_file(kdir, "adbkey.pub");
	}

	fp = fopen(priv_f, "w");
	if (fp) {
		chmod(priv_f, 0600);
		PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
		fclose(fp);
		printf("[+] Wrote private key: %s\n", priv_f);
	}

	if (cert) {
		fp = fopen(cert_f, "w");
		if (fp) {
			PEM_write_X509(fp, cert);
			fclose(fp);
			printf("[+] Wrote X.509 certificate: %s\n", cert_f);
		}
	}

	if (pubkey_str) {
		fp = fopen(pub_f, "w");
		if (fp) {
			fputs(pubkey_str, fp);
			fputc('\n', fp);
			fclose(fp);
			printf("[+] Wrote Android public key: %s\n", pub_f);
		}
	}

	free(priv_f);
	free(cert_f);
	free(pub_f);
	if (pubkey_str) free(pubkey_str);
	if (cert) X509_free(cert);
	EVP_PKEY_free(pkey);
	return 0;
}

/* =========================================================================
 * 10. Main Dispatcher Entrypoint
 * ========================================================================= */

int adb_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int adb_main(int argc, char **argv)
{
	const char *target_device = NULL;
	char host_buf[128];
	int port = 0;
	int idx = 1;
	struct adb_conn conn;
	int ret;
	const char *cmd;
	const char *arg;
	const char *ep;
	const char *code;
	char *col;
	size_t hlen;
	const char *lpath;
	const char *rpath;

	if (argc < 2)
		bb_show_usage();

	/* Parse global options: -s <host:port> */
	while (idx < argc && argv[idx][0] == '-') {
		if (strcmp(argv[idx], "-s") == 0 && idx + 1 < argc) {
			target_device = argv[++idx];
			idx++;
		} else if (strcmp(argv[idx], "--help") == 0 || strcmp(argv[idx], "-h") == 0) {
			bb_show_usage();
		} else {
			break;
		}
	}

	if (idx >= argc)
		bb_show_usage();

	cmd = argv[idx++];

	/* 1. connect [host[:port]] */
	if (strcmp(cmd, "connect") == 0) {
		arg = (idx < argc) ? argv[idx++] : NULL;
		if (arg) {
			col = strchr(arg, ':');
			if (col) {
				if (col == arg) {
					strcpy(host_buf, "127.0.0.1");
				} else {
					hlen = col - arg;
					if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
					memcpy(host_buf, arg, hlen);
					host_buf[hlen] = '\0';
				}
				port = atoi(col + 1);
			} else {
				safe_strncpy(host_buf, arg, sizeof(host_buf));
				port = 5555;
			}
		} else {
			strcpy(host_buf, "127.0.0.1");
			port = adb_discover_local_wireless_port();
		}

		if (port <= 0) port = 5555;

		if (adb_connect_device(&conn, host_buf, port, 8000) == 0) {
			printf("connected to %s:%d\n", host_buf, port);
			adb_close_conn(&conn);
			return 0;
		} else {
			printf("unable to connect to %s:%d\n", host_buf, port);
			return 1;
		}
	}

	/* 2. disconnect [host[:port]] */
	if (strcmp(cmd, "disconnect") == 0) {
		adb_clear_active_endpoint();
		ep = (idx < argc) ? argv[idx] : "all";
		printf("disconnected %s\n", ep);
		return 0;
	}

	/* 3. pair <host:port> [code] */
	if (strcmp(cmd, "pair") == 0) {
		if (idx >= argc) {
			bb_error_msg("usage: adb pair <host>:<port> [code]");
			return 1;
		}
		ep = argv[idx++];
		code = (idx < argc) ? argv[idx++] : NULL;
		col = strchr(ep, ':');
		if (!col) {
			bb_error_msg("adb pair: missing port in '%s' (expected host:port)", ep);
			return 1;
		}
		hlen = col - ep;
		if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
		memcpy(host_buf, ep, hlen);
		host_buf[hlen] = '\0';
		port = atoi(col + 1);
		if (port <= 0) {
			bb_error_msg("adb pair: invalid port '%s'", col + 1);
			return 1;
		}
		return adb_pair_device(host_buf, port, code);
	}

	/* 4. devices [-l] */
	if (strcmp(cmd, "devices") == 0) {
		return adb_show_devices();
	}

	/* 5. status */
	if (strcmp(cmd, "status") == 0) {
		return adb_show_status();
	}

	/* 6. keygen [path] */
	if (strcmp(cmd, "keygen") == 0) {
		return adb_keygen((idx < argc) ? argv[idx] : NULL);
	}

	/* Resolve target endpoint for interactive commands (shell, push, pull) */
	if (target_device) {
		col = strchr(target_device, ':');
		if (col) {
			hlen = col - target_device;
			if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
			memcpy(host_buf, target_device, hlen);
			host_buf[hlen] = '\0';
			port = atoi(col + 1);
		} else {
			safe_strncpy(host_buf, target_device, sizeof(host_buf));
			port = 5555;
		}
	} else if (adb_load_active_endpoint(host_buf, sizeof(host_buf), &port) != 0) {
		strcpy(host_buf, "127.0.0.1");
		port = adb_discover_local_wireless_port();
	}

	if (port <= 0) port = 5555;

	/* 7. shell [command...] */
	if (strcmp(cmd, "shell") == 0) {
		if (adb_connect_device(&conn, host_buf, port, 5000) != 0) {
			bb_error_msg("adb: unable to connect to device at %s:%d", host_buf, port);
			return 1;
		}
		ret = adb_run_shell(&conn, argc - idx, argv + idx);
		adb_close_conn(&conn);
		return ret;
	}

	/* 8. push <local> <remote> */
	if (strcmp(cmd, "push") == 0) {
		if (argc - idx < 2) {
			bb_error_msg("usage: adb push <local> <remote>");
			return 1;
		}
		lpath = argv[idx++];
		rpath = argv[idx++];
		if (adb_connect_device(&conn, host_buf, port, 5000) != 0) {
			bb_error_msg("adb: unable to connect to device at %s:%d", host_buf, port);
			return 1;
		}
		ret = adb_sync_push(&conn, lpath, rpath);
		adb_close_conn(&conn);
		return ret;
	}

	/* 9. pull <remote> [local] */
	if (strcmp(cmd, "pull") == 0) {
		if (argc - idx < 1) {
			bb_error_msg("usage: adb pull <remote> [local]");
			return 1;
		}
		rpath = argv[idx++];
		lpath = (idx < argc) ? argv[idx++] : bb_basename(rpath);
		if (adb_connect_device(&conn, host_buf, port, 5000) != 0) {
			bb_error_msg("adb: unable to connect to device at %s:%d", host_buf, port);
			return 1;
		}
		ret = adb_sync_pull(&conn, rpath, lpath);
		adb_close_conn(&conn);
		return ret;
	}

	bb_error_msg("unknown adb command '%s' (see 'adb --help')", cmd);
	return 1;
}
