/* vi: set sw=4 ts=4: */
/*
 * binder_tools - Android Binder IPC Client (Zero C++ Dependencies)
 *
 * Applets:
 *   binder_ping - Ping Android servicemanager or registered services via /dev/binder
 *   servicelist - Enumerate registered IPC services and test responsiveness
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config BINDER_TOOLS
//config:	bool "binder_tools (binder_ping, servicelist, binder_dump, binder_call)"
//config:	default y
//config:	help
//config:	  Standalone C Binder IPC client suite without Android C++ framework
//config:	  dependencies. Provides 'binder_ping' to test service responsiveness,
//config:	  'servicelist' to enumerate registered Android IPC services,
//config:	  'binder_dump' for zero-dependency dumpsys, and 'binder_call'
//config:	  for interactive AIDL transactions.

//applet:IF_BINDER_TOOLS(APPLET(binder_ping, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_BINDER_TOOLS(APPLET(servicelist, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_BINDER_TOOLS(APPLET(binder_dump, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_BINDER_TOOLS(APPLET(binder_call, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_BINDER_TOOLS) += binder_tools.o

//usage:#define binder_ping_trivial_usage
//usage:	"[-d DEVICE] [SERVICE_NAME]"
//usage:#define binder_ping_full_usage "\n\n"
//usage:       "Ping Android Binder services directly via kernel driver\n"
//usage:     "\n	-d DEVICE	Binder node: /dev/binder, /dev/vndbinder, /dev/hwbinder (default: /dev/binder)"
//usage:     "\n	SERVICE_NAME	Name of registered service to ping (e.g. SurfaceFlinger, activity, vold)."
//usage:     "\n			If omitted, pings servicemanager (handle 0)."
//usage:
//usage:#define servicelist_trivial_usage
//usage:	"[-d DEVICE] [-p] [-i]"
//usage:#define servicelist_full_usage "\n\n"
//usage:       "List registered Android Binder services\n"
//usage:     "\n	-d DEVICE	Binder node: /dev/binder, /dev/vndbinder, /dev/hwbinder (default: /dev/binder)"
//usage:     "\n	-p		Ping each service to verify responsiveness"
//usage:     "\n	-i		Query and show AIDL interface descriptor"
//usage:
//usage:#define binder_dump_trivial_usage
//usage:	"[-d DEVICE] SERVICE [ARGS...]"
//usage:#define binder_dump_full_usage "\n\n"
//usage:       "Stream service diagnostic dump (dumpsys) over raw Binder\n"
//usage:     "\n	-d DEVICE	Binder node: /dev/binder (default: /dev/binder)"
//usage:     "\n	SERVICE		Registered service name (e.g. SurfaceFlinger, meminfo, activity)"
//usage:     "\n	ARGS		Optional dump arguments passed to service"
//usage:
//usage:#define binder_call_trivial_usage
//usage:	"[-d DEVICE] SERVICE CODE [i32 N | i64 N | s16 STR | utf8 STR | null | fd PATH]..."
//usage:#define binder_call_full_usage "\n\n"
//usage:       "Invoke Binder / AIDL transactions with typed arguments\n"
//usage:     "\n	-d DEVICE	Binder node: /dev/binder (default: /dev/binder)"
//usage:     "\n	SERVICE		Registered service name (or 0 for servicemanager)"
//usage:     "\n	CODE		Numeric transaction opcode"
//usage:     "\n	i32 N		Write 32-bit integer"
//usage:     "\n	i64 N		Write 64-bit integer"
//usage:     "\n	s16 STR		Write UTF-16 string"
//usage:     "\n	utf8 STR	Write UTF-8 string"
//usage:     "\n	null		Write null binder object"
//usage:     "\n	fd PATH		Pass opened file descriptor"

#include "libbb.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <linux/android/binder.h>

#ifndef B_PACK_CHARS
#define B_PACK_CHARS(c1, c2, c3, c4) \
	((((uint32_t)(c1)) << 24) | (((uint32_t)(c2)) << 16) | \
	 (((uint32_t)(c3)) << 8) | ((uint32_t)(c4)))
#endif

#ifndef B_PING_TRANSACTION
#define B_PING_TRANSACTION B_PACK_CHARS('_', 'P', 'N', 'G')
#endif
#ifndef B_DUMP_TRANSACTION
#define B_DUMP_TRANSACTION B_PACK_CHARS('_', 'D', 'M', 'P')
#endif
#ifndef B_INTERFACE_TRANSACTION
#define B_INTERFACE_TRANSACTION B_PACK_CHARS('_', 'N', 'T', 'F')
#endif
#ifndef B_SYSPROPS_TRANSACTION
#define B_SYSPROPS_TRANSACTION B_PACK_CHARS('_', 'S', 'P', 'R')
#endif

/* ==============================================================================
 * Section 1: Binder State & Transaction Engine
 * ============================================================================== */

#define BINDER_MAP_SIZE (128 * 1024)
#define SVCMGR_HANDLE 0
#define SVCMGR_INTERFACE "android.os.IServiceManager"

/* Transaction codes for IServiceManager AIDL (Android 10+ / 14) */
#define SVCMGR_GET_SERVICE      1
#define SVCMGR_CHECK_SERVICE    3
#define SVCMGR_ADD_SERVICE      4
#define SVCMGR_LIST_SERVICES    6

struct binder_state {
	int fd;
	void *mapped;
	size_t mapsize;
};

static struct binder_state *binder_open(const char *driver)
{
	struct binder_state *bs;
	uint32_t max_threads = 1;

	bs = xzalloc(sizeof(*bs));
	bs->fd = open(driver, O_RDWR | O_CLOEXEC);
	if (bs->fd < 0) {
		free(bs);
		return NULL;
	}

	if (ioctl(bs->fd, BINDER_SET_MAX_THREADS, &max_threads) < 0) {
		/* Non-fatal */
	}

	bs->mapsize = BINDER_MAP_SIZE;
	bs->mapped = mmap(NULL, bs->mapsize, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, bs->fd, 0);
	if (bs->mapped == MAP_FAILED) {
		close(bs->fd);
		free(bs);
		return NULL;
	}

	return bs;
}

static void binder_close(struct binder_state *bs)
{
	if (!bs) return;
	if (bs->mapped && bs->mapped != MAP_FAILED)
		munmap(bs->mapped, bs->mapsize);
	if (bs->fd >= 0)
		close(bs->fd);
	free(bs);
}

/* Free a buffer allocated by kernel for a transaction reply */
static void binder_free_buffer(struct binder_state *bs, binder_uintptr_t buffer_ptr)
{
	struct {
		uint32_t cmd;
		binder_uintptr_t ptr;
	} __attribute__((__packed__)) writebuf;
	struct binder_write_read bwr;

	writebuf.cmd = BC_FREE_BUFFER;
	writebuf.ptr = buffer_ptr;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (binder_uintptr_t)&writebuf;
	bwr.write_size = sizeof(writebuf);

	ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
}

/* Acquire a strong reference to a binder handle */
static void binder_acquire_handle(struct binder_state *bs, uint32_t handle)
{
	struct {
		uint32_t cmd;
		uint32_t handle;
	} __attribute__((__packed__)) writebuf;
	struct binder_write_read bwr;

	writebuf.cmd = BC_ACQUIRE;
	writebuf.handle = handle;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (binder_uintptr_t)&writebuf;
	bwr.write_size = sizeof(writebuf);

	ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
}

/* Release strong reference to a binder handle */
static void binder_release_handle(struct binder_state *bs, uint32_t handle)
{
	struct {
		uint32_t cmd;
		uint32_t handle;
	} __attribute__((__packed__)) writebuf;
	struct binder_write_read bwr;

	writebuf.cmd = BC_RELEASE;
	writebuf.handle = handle;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (binder_uintptr_t)&writebuf;
	bwr.write_size = sizeof(writebuf);

	ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
}

/* ==============================================================================
 * Section 2: In-Memory Parcel Serialization & Deserialization
 * ============================================================================== */

struct parcel {
	uint8_t *data;
	size_t size;
	size_t capacity;
	size_t rpos;
	binder_size_t *offsets;
	size_t offsets_count;
	size_t offsets_capacity;
};

static void parcel_init(struct parcel *p, size_t cap)
{
	p->capacity = cap ? cap : 512;
	p->data = xzalloc(p->capacity);
	p->size = 0;
	p->rpos = 0;
	p->offsets = NULL;
	p->offsets_count = 0;
	p->offsets_capacity = 0;
}

static void parcel_free(struct parcel *p)
{
	free(p->data);
	free(p->offsets);
	p->data = NULL;
	p->offsets = NULL;
	p->size = p->capacity = p->rpos = 0;
	p->offsets_count = p->offsets_capacity = 0;
}

static void parcel_grow(struct parcel *p, size_t extra)
{
	if (p->size + extra > p->capacity) {
		p->capacity = (p->capacity * 2) + extra;
		p->data = xrealloc(p->data, p->capacity);
	}
}

static void parcel_write_int32(struct parcel *p, int32_t val)
{
	parcel_grow(p, 4);
	memcpy(p->data + p->size, &val, 4);
	p->size += 4;
}

/* Write UTF-16 String16: 32-bit char length + UTF-16 chars + null terminator + 4-byte padding */
static void parcel_write_string16(struct parcel *p, const char *str)
{
	size_t len = str ? strlen(str) : 0;
	size_t bytes = (len + 1) * 2;
	size_t padded = (bytes + 3) & ~3;
	size_t i;
	uint16_t *utf16;

	parcel_write_int32(p, (int32_t)len);
	parcel_grow(p, padded);

	utf16 = (uint16_t *)(p->data + p->size);
	for (i = 0; i < len; i++) {
		utf16[i] = (uint16_t)(uint8_t)str[i];
	}
	utf16[len] = 0;

	if (padded > bytes)
		memset((uint8_t *)utf16 + bytes, 0, padded - bytes);

	p->size += padded;
}

/* Write AIDL @utf8InCpp String: 32-bit byte length + UTF-8 bytes + null + 4-byte padding */
static void parcel_write_utf8(struct parcel *p, const char *str)
{
	size_t len = str ? strlen(str) : 0;
	size_t bytes = len + 1;
	size_t padded = (bytes + 3) & ~3;

	parcel_write_int32(p, (int32_t)len);
	parcel_grow(p, padded);
	memcpy(p->data + p->size, str, len);
	p->data[p->size + len] = '\0';
	if (padded > bytes)
		memset(p->data + p->size + bytes, 0, padded - bytes);
	p->size += padded;
}

/* Write modern Android AIDL interface token:
 * strictModePolicy (0x100) + workSourceUid (-1) + kHeaderForDomainFormat (0x53595354) + String16
 */
static void parcel_write_interface_token(struct parcel *p, const char *interface)
{
	parcel_write_int32(p, 0x100);
	parcel_write_int32(p, -1);
	parcel_write_int32(p, 0x53595354);
	parcel_write_string16(p, interface);
}

static int32_t parcel_read_int32(struct parcel *p, int *err)
{
	int32_t val = 0;
	if (p->rpos + 4 > p->size) {
		if (err) *err = -1;
		return 0;
	}
	memcpy(&val, p->data + p->rpos, 4);
	p->rpos += 4;
	if (err) *err = 0;
	return val;
}

/* Universal String Reader: automatically distinguishes UTF-8 vs UTF-16 */
static char *parcel_read_string(struct parcel *p)
{
	int err = 0;
	int32_t len = parcel_read_int32(p, &err);
	size_t bytes, padded, i;
	char *out;

	if (err || len < 0 || len > 4096)
		return NULL;

	/*
	 * Detect encoding:
	 * If UTF-16, second byte is typically 0 for ASCII characters.
	 * If UTF-8, characters are 1 byte each followed by null terminator.
	 */
	if (p->rpos + 2 <= p->size && p->data[p->rpos + 1] == 0 && len > 0) {
		/* UTF-16 String */
		bytes = (len + 1) * 2;
		padded = (bytes + 3) & ~3;
		if (p->rpos + padded > p->size)
			return NULL;

		out = xzalloc(len + 1);
		for (i = 0; i < (size_t)len; i++) {
			uint16_t c;
			memcpy(&c, p->data + p->rpos + (i * 2), 2);
			out[i] = (char)(c & 0x7F);
		}
		out[len] = '\0';
		p->rpos += padded;
		return out;
	} else {
		/* UTF-8 String (@utf8InCpp) */
		bytes = len + 1;
		padded = (bytes + 3) & ~3;
		if (p->rpos + padded > p->size)
			return NULL;

		out = xzalloc(len + 1);
		memcpy(out, p->data + p->rpos, len);
		out[len] = '\0';
		p->rpos += padded;
		return out;
	}
}

static void parcel_write_int64(struct parcel *p, int64_t val)
{
	parcel_grow(p, 8);
	memcpy(p->data + p->size, &val, 8);
	p->size += 8;
}

static void parcel_write_fd(struct parcel *p, int fd)
{
	struct binder_fd_object obj;
	size_t aligned_offset;

	aligned_offset = (p->size + 7) & ~7;
	if (aligned_offset > p->size) {
		parcel_grow(p, aligned_offset - p->size);
		memset(p->data + p->size, 0, aligned_offset - p->size);
		p->size = aligned_offset;
	}

	if (p->offsets_count >= p->offsets_capacity) {
		p->offsets_capacity = p->offsets_capacity ? p->offsets_capacity * 2 : 8;
		p->offsets = xrealloc(p->offsets, p->offsets_capacity * sizeof(binder_size_t));
	}
	p->offsets[p->offsets_count++] = p->size;

	memset(&obj, 0, sizeof(obj));
	obj.hdr.type = BINDER_TYPE_FD;
	obj.pad_flags = 0;
	obj.fd = (uint32_t)fd;
	obj.cookie = 0;

	parcel_grow(p, sizeof(obj));
	memcpy(p->data + p->size, &obj, sizeof(obj));
	p->size += sizeof(obj);
}

static void parcel_write_null_binder(struct parcel *p)
{
	struct flat_binder_object obj;
	size_t aligned_offset;

	aligned_offset = (p->size + 7) & ~7;
	if (aligned_offset > p->size) {
		parcel_grow(p, aligned_offset - p->size);
		memset(p->data + p->size, 0, aligned_offset - p->size);
		p->size = aligned_offset;
	}

	if (p->offsets_count >= p->offsets_capacity) {
		p->offsets_capacity = p->offsets_capacity ? p->offsets_capacity * 2 : 8;
		p->offsets = xrealloc(p->offsets, p->offsets_capacity * sizeof(binder_size_t));
	}
	p->offsets[p->offsets_count++] = p->size;

	memset(&obj, 0, sizeof(obj));
	obj.hdr.type = BINDER_TYPE_BINDER;
	obj.flags = 0;
	obj.binder = 0;
	obj.cookie = 0;

	parcel_grow(p, sizeof(obj));
	memcpy(p->data + p->size, &obj, sizeof(obj));
	p->size += sizeof(obj);
}

static void parcel_dump(struct parcel *p)
{
	int err;
	int32_t ex;
	size_t i, j;

	err = 0;
	if (p->size >= 4) {
		ex = parcel_read_int32(p, &err);
		printf("Status: ");
		switch (ex) {
		case 0:  printf("EX_NONE (Success)\n"); break;
		case -1: printf("EX_SECURITY\n"); break;
		case -2: printf("EX_BAD_PARCELABLE\n"); break;
		case -3: printf("EX_ILLEGAL_ARGUMENT\n"); break;
		case -4: printf("EX_NULL_POINTER\n"); break;
		case -5: printf("EX_ILLEGAL_STATE\n"); break;
		case -6: printf("EX_NETWORK_MAIN_THREAD\n"); break;
		case -7: printf("EX_UNSUPPORTED_OPERATION\n"); break;
		case -8: printf("EX_SERVICE_SPECIFIC\n"); break;
		default: printf("Exception %d\n", (int)ex); break;
		}
	}

	if (p->rpos < p->size) {
		printf("Payload (%zu bytes remaining):\n", p->size - p->rpos);
		for (i = p->rpos; i < p->size; i += 16) {
			printf("  %04zx: ", i - p->rpos);
			for (j = 0; j < 16; j++) {
				if (i + j < p->size)
					printf("%02x ", p->data[i + j]);
				else
					printf("   ");
			}
			printf(" |");
			for (j = 0; j < 16 && i + j < p->size; j++) {
				uint8_t c = p->data[i + j];
				printf("%c", (c >= 32 && c <= 126) ? (char)c : '.');
			}
			printf("|\n");
		}
	}
}

/* ==============================================================================
 * Section 3: Transaction Dispatcher
 * ============================================================================== */

static int binder_transact(struct binder_state *bs,
			   uint32_t target_handle,
			   uint32_t code,
			   struct parcel *req,
			   struct parcel *reply,
			   binder_uintptr_t *out_reply_buffer)
{
	struct {
		uint32_t cmd;
		struct binder_transaction_data txn;
	} __attribute__((__packed__)) writebuf;
	uint8_t readbuf[512];
	struct binder_write_read bwr;
	ssize_t ret;
	uint8_t *ptr, *end;
	uint32_t cmd;
	struct binder_transaction_data reply_txn;

	memset(&writebuf, 0, sizeof(writebuf));
	writebuf.cmd = BC_TRANSACTION;
	writebuf.txn.target.handle = target_handle;
	writebuf.txn.code = code;
	writebuf.txn.flags = 0;

	if (req && req->size > 0) {
		writebuf.txn.data_size = req->size;
		writebuf.txn.data.ptr.buffer = (binder_uintptr_t)req->data;
		if (req->offsets_count > 0) {
			writebuf.txn.offsets_size = req->offsets_count * sizeof(binder_size_t);
			writebuf.txn.data.ptr.offsets = (binder_uintptr_t)req->offsets;
		}
	}

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (binder_uintptr_t)&writebuf;
	bwr.write_size = sizeof(writebuf);
	bwr.read_buffer = (binder_uintptr_t)readbuf;
	bwr.read_size = sizeof(readbuf);

	ret = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
	if (ret < 0) {
		return -errno;
	}

	ptr = readbuf;
	end = readbuf + bwr.read_consumed;

	while (ptr < end) {
		memcpy(&cmd, ptr, 4);
		ptr += 4;

		switch (cmd) {
		case BR_NOOP:
		case BR_TRANSACTION_COMPLETE:
			break;
		case BR_DEAD_REPLY:
		case BR_FAILED_REPLY:
			return -EIO;
		case BR_REPLY:
			memcpy(&reply_txn, ptr, sizeof(reply_txn));
			ptr += sizeof(reply_txn);

			if (reply) {
				reply->data = xmemdup((void *)(uintptr_t)reply_txn.data.ptr.buffer, reply_txn.data_size);
				reply->size = reply_txn.data_size;
				reply->capacity = reply_txn.data_size;
				reply->rpos = 0;
			}

			if (out_reply_buffer)
				*out_reply_buffer = reply_txn.data.ptr.buffer;
			else
				binder_free_buffer(bs, reply_txn.data.ptr.buffer);

			return 0;
		case BR_ERROR:
			return -EPROTO;
		default:
			return -ENOSYS;
		}
	}

	return -ENODATA;
}

/* ==============================================================================
 * Section 4: High-Level Applet Handlers
 * ============================================================================== */

/* Ping a binder handle directly using universal B_PING_TRANSACTION */
static int binder_ping_handle(struct binder_state *bs, uint32_t handle, unsigned long long *out_us)
{
	struct timespec t1, t2;
	int ret;
	unsigned long long ns;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	ret = binder_transact(bs, handle, B_PING_TRANSACTION, NULL, NULL, NULL);
	clock_gettime(CLOCK_MONOTONIC, &t2);

	if (out_us) {
		ns = (t2.tv_sec - t1.tv_sec) * 1000000000ULL + (t2.tv_nsec - t1.tv_nsec);
		*out_us = ns / 1000ULL;
	}

	return ret;
}

/* Query canonical interface descriptor from an active binder handle via universal _NTF */
static char *binder_get_interface_descriptor(struct binder_state *bs, uint32_t handle)
{
	struct parcel reply;
	binder_uintptr_t reply_buf;
	int ret;
	char *desc;

	reply_buf = 0;
	desc = NULL;
	memset(&reply, 0, sizeof(reply));
	ret = binder_transact(bs, handle, B_INTERFACE_TRANSACTION, NULL, &reply, &reply_buf);
	if (ret == 0 && reply.size > 0) {
		desc = parcel_read_string(&reply);
	}
	if (reply_buf)
		binder_free_buffer(bs, reply_buf);
	parcel_free(&reply);
	return desc;
}

/* Query handle for a named service from servicemanager (tries UTF-8 then UTF-16) */
static int binder_get_service_handle_internal(struct binder_state *bs, const char *name, bool use_utf8, uint32_t *out_handle)
{
	struct parcel req, reply;
	int ret;
	binder_uintptr_t reply_buf = 0;
	int err = 0;
	int32_t exception;
	uint32_t type;
	uint32_t handle;
	size_t off;

	parcel_init(&req, 256);
	parcel_write_interface_token(&req, SVCMGR_INTERFACE);
	if (use_utf8)
		parcel_write_utf8(&req, name);
	else
		parcel_write_string16(&req, name);

	memset(&reply, 0, sizeof(reply));
	ret = binder_transact(bs, SVCMGR_HANDLE, SVCMGR_CHECK_SERVICE, &req, &reply, &reply_buf);
	parcel_free(&req);

	if (ret != 0)
		return ret;

	/* Parse reply: int32 exception code (0) + flat_binder_object */
	exception = parcel_read_int32(&reply, &err);
	(void)exception;

	ret = -ENOENT;
	/* Search for BINDER_TYPE_HANDLE in reply parcel */
	for (off = reply.rpos; off + 12 <= reply.size; off += 4) {
		memcpy(&type, reply.data + off, 4);
		if (type == BINDER_TYPE_HANDLE) {
			memcpy(&handle, reply.data + off + 8, 4);
			binder_acquire_handle(bs, handle);
			if (out_handle)
				*out_handle = handle;
			ret = 0;
			break;
		}
	}

	if (reply_buf)
		binder_free_buffer(bs, reply_buf);
	parcel_free(&reply);
	return ret;
}

static int binder_get_service_handle(struct binder_state *bs, const char *name, uint32_t *out_handle)
{
	/* Try canonical AIDL UTF-16 first */
	int ret = binder_get_service_handle_internal(bs, name, false, out_handle);
	if (ret == 0)
		return 0;

	/* Fallback to UTF-8 */
	return binder_get_service_handle_internal(bs, name, true, out_handle);
}

/* ==============================================================================
 * Section 5: CLI Applet Entry Points
 * ============================================================================== */

int binder_ping_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int binder_ping_main(int argc, char **argv)
{
	const char *dev = "/dev/binder";
	const char *service = NULL;
	struct binder_state *bs;
	unsigned long long ping_us = 0;
	int ret;
	int opt;
	uint32_t handle = 0;

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "-d") == 0 && opt + 1 < argc) {
			dev = argv[++opt];
		} else if (argv[opt][0] != '-') {
			service = argv[opt];
		} else {
			bb_show_usage();
		}
	}

	bs = binder_open(dev);
	if (!bs) {
		bb_perror_msg_and_die("failed to open binder driver '%s'", dev);
	}

	if (!service) {
		/* Ping servicemanager directly */
		ret = binder_ping_handle(bs, SVCMGR_HANDLE, &ping_us);
		if (ret == 0) {
			printf("Context manager (servicemanager) on '%s': ALIVE (ping %llu us)\n",
				dev, ping_us);
		} else {
			printf("Context manager (servicemanager) on '%s': UNRESPONSIVE (error %d: %s)\n",
				dev, ret, strerror(-ret));
		}
	} else {
		char *desc;

		desc = NULL;
		ret = binder_get_service_handle(bs, service, &handle);
		if (ret != 0) {
			printf("Service '%s': NOT FOUND (not registered with servicemanager)\n", service);
			binder_close(bs);
			return EXIT_FAILURE;
		}

		desc = binder_get_interface_descriptor(bs, handle);
		ret = binder_ping_handle(bs, handle, &ping_us);
		if (ret == 0) {
			if (desc)
				printf("Service '%s' (%s): ALIVE (handle %u, ping %llu us)\n",
					service, desc, handle, ping_us);
			else
				printf("Service '%s': ALIVE (handle %u, ping %llu us)\n",
					service, handle, ping_us);
		} else {
			if (desc)
				printf("Service '%s' (%s): DEAD / UNRESPONSIVE (handle %u, error %d)\n",
					service, desc, handle, ret);
			else
				printf("Service '%s': DEAD / UNRESPONSIVE (handle %u, error %d)\n",
					service, handle, ret);
		}
		free(desc);
		binder_release_handle(bs, handle);
	}

	binder_close(bs);
	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int servicelist_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int servicelist_main(int argc, char **argv)
{
	const char *dev;
	bool test_ping;
	bool show_interface;
	struct binder_state *bs;
	struct parcel req, reply;
	binder_uintptr_t reply_buf;
	int ret, opt, err;
	int32_t count;
	int i;
	char *name;
	char *desc;
	uint32_t handle;
	unsigned long long us;
	int sret;

	dev = "/dev/binder";
	test_ping = false;
	show_interface = false;
	reply_buf = 0;
	count = 0;

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "-d") == 0 && opt + 1 < argc) {
			dev = argv[++opt];
		} else if (strcmp(argv[opt], "-p") == 0 || strcmp(argv[opt], "--ping") == 0) {
			test_ping = true;
		} else if (strcmp(argv[opt], "-i") == 0 || strcmp(argv[opt], "--interface") == 0) {
			show_interface = true;
		} else {
			bb_show_usage();
		}
	}

	bs = binder_open(dev);
	if (!bs) {
		bb_perror_msg_and_die("failed to open binder driver '%s'", dev);
	}

	parcel_init(&req, 256);
	parcel_write_interface_token(&req, SVCMGR_INTERFACE);
	parcel_write_int32(&req, 15); /* DUMP_FLAG_PRIORITY_ALL = 15 */

	memset(&reply, 0, sizeof(reply));
	ret = binder_transact(bs, SVCMGR_HANDLE, SVCMGR_LIST_SERVICES, &req, &reply, &reply_buf);
	parcel_free(&req);

	if (ret != 0) {
		bb_error_msg("failed to query servicemanager on '%s': %s", dev, strerror(-ret));
		binder_close(bs);
		return EXIT_FAILURE;
	}

	err = 0;
	parcel_read_int32(&reply, &err); /* Exception code (0) */
	count = parcel_read_int32(&reply, &err);

	if (err || count < 0 || count > 2048) {
		printf("No services reported by servicemanager (or empty reply).\n");
	} else {
		printf("Found %d registered Binder services on '%s':\n", count, dev);

		for (i = 0; i < count; i++) {
			name = parcel_read_string(&reply);
			if (!name) break;

			handle = 0;
			desc = NULL;
			us = 0;
			sret = -1;

			if (test_ping || show_interface) {
				sret = binder_get_service_handle(bs, name, &handle);
				if (sret == 0) {
					if (show_interface)
						desc = binder_get_interface_descriptor(bs, handle);
					if (test_ping)
						binder_ping_handle(bs, handle, &us);
					binder_release_handle(bs, handle);
				}
			}

			if (show_interface && test_ping) {
				printf("  [%3d] %-36s -> %-36s [ALIVE, %llu us]\n",
					i, name, desc ? desc : "(unknown)", us);
			} else if (show_interface) {
				printf("  [%3d] %-36s -> %s\n",
					i, name, desc ? desc : "(unknown)");
			} else if (test_ping) {
				if (sret == 0)
					printf("  [%3d] %-36s [ALIVE, handle %u, %llu us]\n", i, name, handle, us);
				else
					printf("  [%3d] %-36s [DEAD / UNRESPONSIVE]\n", i, name);
			} else {
				printf("  [%3d] %s\n", i, name);
			}

			free(desc);
			free(name);
		}
	}

	if (reply_buf)
		binder_free_buffer(bs, reply_buf);
	parcel_free(&reply);
	binder_close(bs);
	return EXIT_SUCCESS;
}

int binder_dump_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int binder_dump_main(int argc, char **argv)
{
	const char *dev;
	const char *service;
	struct binder_state *bs;
	struct parcel req, reply;
	binder_uintptr_t reply_buf;
	uint32_t handle;
	int ret, i;
	int arg_start;

	dev = "/dev/binder";
	service = NULL;
	reply_buf = 0;
	handle = 0;
	arg_start = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			dev = argv[++i];
			arg_start = i + 1;
		} else if (argv[i][0] != '-') {
			service = argv[i];
			arg_start = i;
			break;
		}
	}

	if (!service) {
		bb_show_usage();
	}

	bs = binder_open(dev);
	if (!bs) {
		bb_perror_msg_and_die("failed to open binder driver '%s'", dev);
	}

	ret = binder_get_service_handle(bs, service, &handle);
	if (ret != 0) {
		bb_error_msg_and_die("service '%s' not found", service);
	}

	parcel_init(&req, 256);
	parcel_write_fd(&req, STDOUT_FILENO);
	parcel_write_int32(&req, argc - (arg_start + 1));
	for (i = arg_start + 1; i < argc; i++) {
		parcel_write_string16(&req, argv[i]);
	}

	memset(&reply, 0, sizeof(reply));
	ret = binder_transact(bs, handle, B_DUMP_TRANSACTION, &req, &reply, &reply_buf);
	parcel_free(&req);

	if (reply_buf)
		binder_free_buffer(bs, reply_buf);
	parcel_free(&reply);
	binder_release_handle(bs, handle);
	binder_close(bs);

	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

int binder_call_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int binder_call_main(int argc, char **argv)
{
	const char *dev;
	const char *service;
	uint32_t code;
	struct binder_state *bs;
	struct parcel req, reply;
	binder_uintptr_t reply_buf;
	uint32_t handle;
	char *desc;
	int ret, opt, i;
	int arg_start;

	dev = "/dev/binder";
	service = NULL;
	code = 0;
	reply_buf = 0;
	handle = 0;
	desc = NULL;
	arg_start = 1;

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "-d") == 0 && opt + 1 < argc) {
			dev = argv[++opt];
			arg_start = opt + 1;
		} else if (argv[opt][0] != '-') {
			service = argv[opt];
			arg_start = opt;
			break;
		}
	}

	if (!service || arg_start + 1 >= argc) {
		bb_show_usage();
	}

	code = (uint32_t)bb_strtou(argv[arg_start + 1], NULL, 0);

	bs = binder_open(dev);
	if (!bs) {
		bb_perror_msg_and_die("failed to open binder driver '%s'", dev);
	}

	if (strcmp(service, "0") == 0 || strcasecmp(service, "servicemanager") == 0) {
		handle = SVCMGR_HANDLE;
		desc = xstrdup(SVCMGR_INTERFACE);
	} else {
		ret = binder_get_service_handle(bs, service, &handle);
		if (ret != 0) {
			bb_error_msg_and_die("service '%s' not found", service);
		}
		desc = binder_get_interface_descriptor(bs, handle);
	}

	parcel_init(&req, 256);
	if (desc) {
		parcel_write_interface_token(&req, desc);
		free(desc);
	}

	/* Parse typed arguments */
	for (i = arg_start + 2; i < argc; i++) {
		if (strcmp(argv[i], "i32") == 0 && i + 1 < argc) {
			parcel_write_int32(&req, (int32_t)strtol(argv[++i], NULL, 0));
		} else if (strcmp(argv[i], "i64") == 0 && i + 1 < argc) {
			parcel_write_int64(&req, (int64_t)strtoll(argv[++i], NULL, 0));
		} else if (strcmp(argv[i], "s16") == 0 && i + 1 < argc) {
			parcel_write_string16(&req, argv[++i]);
		} else if (strcmp(argv[i], "utf8") == 0 && i + 1 < argc) {
			parcel_write_utf8(&req, argv[++i]);
		} else if (strcmp(argv[i], "null") == 0) {
			parcel_write_null_binder(&req);
		} else if (strcmp(argv[i], "fd") == 0 && i + 1 < argc) {
			int fd = open(argv[++i], O_RDWR);
			if (fd < 0) bb_perror_msg_and_die("failed to open '%s'", argv[i]);
			parcel_write_fd(&req, fd);
			close(fd);
		} else {
			bb_error_msg_and_die("unknown argument type '%s'", argv[i]);
		}
	}

	memset(&reply, 0, sizeof(reply));
	ret = binder_transact(bs, handle, code, &req, &reply, &reply_buf);
	parcel_free(&req);

	if (ret != 0) {
		printf("Result: FAILED (error %d: %s)\n", ret, strerror(-ret));
	} else {
		printf("Result: SUCCESS (%zu bytes reply)\n", reply.size);
		if (reply.size > 0) {
			parcel_dump(&reply);
		}
	}

	if (reply_buf)
		binder_free_buffer(bs, reply_buf);
	parcel_free(&reply);
	if (handle != SVCMGR_HANDLE)
		binder_release_handle(bs, handle);
	binder_close(bs);

	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
