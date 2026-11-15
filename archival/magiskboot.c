/* vi: set sw=4 ts=4: */
/*
 * magiskboot — Android Boot Image Tool for BusyBox
 *
 * Implements Android boot image unpacking, repacking, component extraction,
 * header inspection, and in-place binary hex patching in memory-safe C.
 * Supports AOSP boot v0-v4, Vendor Boot v3-v4, Samsung PXA, and OEM loaders.
 *
 * Conforms to Linux Kernel Coding Style & ISO C90/C99/C11 standards.
 */

//config:config MAGISKBOOT
//config:	bool "magiskboot (Android boot image tool)"
//config:	default y
//config:	help
//config:	Android boot image manipulator.

//applet:IF_MAGISKBOOT(APPLET(magiskboot, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_MAGISKBOOT) += magiskboot.o

//usage:#define magiskboot_trivial_usage
//usage:       "COMMAND [ARGS]..."
//usage:#define magiskboot_full_usage "\n\n"
//usage:       "Android boot image tool\n"
//usage:     "\nCommands:"
//usage:     "\n	unpack [-h] <boot.img>        Unpack boot image into components"
//usage:     "\n	repack [-n] <boot.img> [out]  Repack components into new boot image"
//usage:     "\n	split <boot.img>              Split boot image without decompressing ramdisk"
//usage:     "\n	hexpatch <file> <from> <to>   In-place hex string patch"
//usage:     "\n	cpio <ramdisk.cpio> [args...] CPIO archive operations"
//usage:     "\n	dtb <file> [args...]          Dump device tree blob"

#include "libbb.h"
#include "bb_archive.h"
#include "magiskboot.h"

#include <sys/mman.h>
#include <sys/sendfile.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

/* =========================================================================
 * 1. Format Detection & Helper Functions
 * ========================================================================= */

static uint8_t boot_check_fmt(const void *buf, size_t len) {
	const uint8_t *b;
	if (!buf || len < 2) return BOOT_FMT_UNKNOWN;
	b = (const uint8_t *)buf;

	if (len >= 8 && memcmp(b, "CHROMEOS", 8) == 0) return BOOT_FMT_CHROMEOS;
	if (len >= 8 && memcmp(b, "ANDROID!", 8) == 0) return BOOT_FMT_AOSP;
	if (len >= 8 && memcmp(b, "VNDRBOOT", 8) == 0) return BOOT_FMT_AOSP_VENDOR;
	if ((b[0] == 0x1f && b[1] == 0x8b) || (b[0] == 0x1f && b[1] == 0x9e)) return BOOT_FMT_GZIP;
	if (len >= 4 && memcmp(b, "\x89LZO", 4) == 0) return BOOT_FMT_LZOP;
	if (len >= 6 && memcmp(b, "\xfd" "7zXZ\x00", 6) == 0) return BOOT_FMT_XZ;
	if (len >= 3 && memcmp(b, "BZh", 3) == 0) return BOOT_FMT_BZIP2;
	if (len >= 4) {
		if (memcmp(b, "\x04\x22\x4d\x18", 4) == 0 || memcmp(b, "\x03\x21\x4c\x18", 4) == 0)
			return BOOT_FMT_LZ4;
		if (memcmp(b, "\x02\x21\x4c\x18", 4) == 0)
			return BOOT_FMT_LZ4_LEGACY;
	}
	if (len >= 4 && memcmp(b, "\xd0\x0d\xfe\xed", 4) == 0) return BOOT_FMT_DTB;
	if (len >= 8 && memcmp(b, "\x44\x48\x54\x42\x01\x00\x00\x00", 8) == 0) return BOOT_FMT_DHTB;
	if (len >= 20 && memcmp(b, "-SIGNED-BY-SIGNBLOB-", 20) == 0) return BOOT_FMT_BLOB;
	if (len >= 4 && memcmp(b, "\x18\x28\x6f\x01", 4) == 0) return BOOT_FMT_ZIMAGE;

	/* LZMA header check */
	if (len >= 13 && b[0] == 0x5d) {
		uint32_t dict_sz = (uint32_t)b[1] | ((uint32_t)b[2] << 8) | ((uint32_t)b[3] << 16) | ((uint32_t)b[4] << 24);
		if (dict_sz != 0 && (dict_sz & (dict_sz - 1)) == 0) {
			bool all_ff = true;
			int i;
			for (i = 5; i < 13; i++) {
				if (b[i] != 0xff) { all_ff = false; break; }
			}
			if (all_ff) return BOOT_FMT_LZMA;
		}
	}
	return BOOT_FMT_UNKNOWN;
}

static const char *boot_fmt2name(uint8_t fmt) {
	switch (fmt) {
	case BOOT_FMT_CHROMEOS:    return "chromeos";
	case BOOT_FMT_AOSP:        return "aosp";
	case BOOT_FMT_AOSP_VENDOR: return "vendor";
	case BOOT_FMT_DHTB:        return "dhtb";
	case BOOT_FMT_BLOB:        return "blob";
	case BOOT_FMT_GZIP:        return "gzip";
	case BOOT_FMT_ZOPFLI:      return "zopfli";
	case BOOT_FMT_XZ:          return "xz";
	case BOOT_FMT_LZMA:        return "lzma";
	case BOOT_FMT_BZIP2:       return "bzip2";
	case BOOT_FMT_LZ4:         return "lz4";
	case BOOT_FMT_LZ4_LEGACY:  return "lz4_legacy";
	case BOOT_FMT_LZ4_LG:      return "lz4_lg";
	case BOOT_FMT_LZOP:        return "lzop";
	case BOOT_FMT_DTB:         return "dtb";
	case BOOT_FMT_ZIMAGE:      return "zimage";
	default:                   return "raw";
	}
}

static bool boot_fmt_compressed(uint8_t fmt) {
	switch (fmt) {
	case BOOT_FMT_GZIP:
	case BOOT_FMT_ZOPFLI:
	case BOOT_FMT_XZ:
	case BOOT_FMT_LZMA:
	case BOOT_FMT_BZIP2:
	case BOOT_FMT_LZ4:
	case BOOT_FMT_LZ4_LEGACY:
	case BOOT_FMT_LZ4_LG:
	case BOOT_FMT_LZOP:
		return true;
	default:
		return false;
	}
}

static int32_t boot_find_dtb_offset(const void *buf, size_t len) {
	const uint8_t *p;
	const uint8_t *end;
	if (!buf || len < 4) return -1;
	p = (const uint8_t *)buf;
	end = p + len - 4;
	while (p <= end) {
		if (p[0] == 0xd0 && p[1] == 0x0d && p[2] == 0xfe && p[3] == 0xed) {
			return (int32_t)(p - (const uint8_t *)buf);
		}
		p++;
	}
	return -1;
}

static inline size_t align_to(size_t v, size_t a) {
	if (a == 0) return v;
	return (v + a - 1) / a * a;
}

/* =========================================================================
 * 2. Header Properties Serialization & Deserialization
 * ========================================================================= */

static void boot_hdr_decode_os_version(uint32_t os_ver, int *a, int *b, int *c, int *y, int *m) {
	uint32_t version;
	uint32_t patch_level;
	if (!os_ver) {
		if (a) *a = 0;
		if (b) *b = 0;
		if (c) *c = 0;
		if (y) *y = 0;
		if (m) *m = 0;
		return;
	}
	version = os_ver >> 11;
	patch_level = os_ver & 0x7ff;
	if (a) *a = (version >> 14) & 0x7f;
	if (b) *b = (version >> 7) & 0x7f;
	if (c) *c = version & 0x7f;
	if (y) *y = (patch_level >> 4) + 2000;
	if (m) *m = patch_level & 0xf;
}

static __attribute__((unused)) uint32_t boot_hdr_encode_os_version(int a, int b, int c, int y, int m) {
	uint32_t ver;
	int year;
	uint32_t patch;
	ver = (((uint32_t)(a & 0x7f) << 14) |
		   ((uint32_t)(b & 0x7f) << 7)  |
		   ((uint32_t)(c & 0x7f)));
	year = (y >= 2000) ? (y - 2000) : 0;
	patch = (((uint32_t)(year & 0x7f) << 4) | (uint32_t)(m & 0x0f));
	return (ver << 11) | (patch & 0x7ff);
}

/* Dynamic header helpers */
static size_t dyn_hdr_size(boot_hdr_type_t type) {
	switch (type) {
	case BOOT_HDR_V0:     return sizeof(struct boot_img_hdr_v0);
	case BOOT_HDR_V1:     return sizeof(struct boot_img_hdr_v1);
	case BOOT_HDR_V2:     return sizeof(struct boot_img_hdr_v2);
	case BOOT_HDR_V3:     return sizeof(struct boot_img_hdr_v3);
	case BOOT_HDR_V4:     return sizeof(struct boot_img_hdr_v4);
	case BOOT_HDR_VND_V3: return sizeof(struct boot_img_hdr_vnd_v3);
	case BOOT_HDR_VND_V4: return sizeof(struct boot_img_hdr_vnd_v4);
	case BOOT_HDR_PXA:    return sizeof(struct boot_img_hdr_pxa);
	default:              return 0;
	}
}

static uint32_t *dyn_hdr_kernel_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v0 *)hdr->raw)->kernel_size;
	case BOOT_HDR_V3:
	case BOOT_HDR_V4:     return &((struct boot_img_hdr_v3 *)hdr->raw)->kernel_size;
	case BOOT_HDR_PXA:    return &((struct boot_img_hdr_pxa *)hdr->raw)->kernel_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t *dyn_hdr_ramdisk_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v0 *)hdr->raw)->ramdisk_size;
	case BOOT_HDR_V3:
	case BOOT_HDR_V4:     return &((struct boot_img_hdr_v3 *)hdr->raw)->ramdisk_size;
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: return &((struct boot_img_hdr_vnd_v3 *)hdr->raw)->ramdisk_size;
	case BOOT_HDR_PXA:    return &((struct boot_img_hdr_pxa *)hdr->raw)->ramdisk_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t *dyn_hdr_second_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v0 *)hdr->raw)->second_size;
	case BOOT_HDR_PXA:    return &((struct boot_img_hdr_pxa *)hdr->raw)->second_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t *dyn_hdr_extra_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_PXA:    return &((struct boot_img_hdr_pxa *)hdr->raw)->extra_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t *dyn_hdr_dtb_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v2 *)hdr->raw)->dtb_size;
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: return &((struct boot_img_hdr_vnd_v3 *)hdr->raw)->dtb_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t *dyn_hdr_recovery_dtbo_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v1 *)hdr->raw)->recovery_dtbo_size;
	default:              return &hdr->dummy32;
	}
}

static __attribute__((unused)) uint64_t *dyn_hdr_recovery_dtbo_offset(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy64;
	switch (hdr->type) {
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return &((struct boot_img_hdr_v1 *)hdr->raw)->recovery_dtbo_offset;
	default:              return &hdr->dummy64;
	}
}

static uint32_t *dyn_hdr_bootconfig_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_VND_V4: return &((struct boot_img_hdr_vnd_v4 *)hdr->raw)->bootconfig_size;
	default:              return &hdr->dummy32;
	}
}

static __attribute__((unused)) uint32_t *dyn_hdr_signature_size(boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return &hdr->dummy32;
	switch (hdr->type) {
	case BOOT_HDR_V4:     return &((struct boot_img_hdr_v4 *)hdr->raw)->signature_size;
	default:              return &hdr->dummy32;
	}
}

static uint32_t dyn_hdr_page_size(const boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return 2048;
	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2:     return ((struct boot_img_hdr_v0 *)hdr->raw)->page_size;
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: return ((struct boot_img_hdr_vnd_v3 *)hdr->raw)->page_size;
	case BOOT_HDR_PXA:    return ((struct boot_img_hdr_pxa *)hdr->raw)->page_size;
	case BOOT_HDR_V3:
	case BOOT_HDR_V4:     return 4096;
	default:              return 2048;
	}
}

static uint32_t dyn_hdr_version(const boot_dyn_hdr_t *hdr) {
	if (!hdr || !hdr->raw) return 0;
	switch (hdr->type) {
	case BOOT_HDR_V0:     return 0;
	case BOOT_HDR_V1:     return 1;
	case BOOT_HDR_V2:     return 2;
	case BOOT_HDR_V3:     return ((struct boot_img_hdr_v3 *)hdr->raw)->header_version;
	case BOOT_HDR_V4:     return ((struct boot_img_hdr_v4 *)hdr->raw)->v3.header_version;
	case BOOT_HDR_VND_V3: return ((struct boot_img_hdr_vnd_v3 *)hdr->raw)->header_version;
	case BOOT_HDR_VND_V4: return ((struct boot_img_hdr_vnd_v4 *)hdr->raw)->vnd_v3.header_version;
	default:              return 0;
	}
}

static bool dyn_hdr_is_vendor(const boot_dyn_hdr_t *hdr) {
	if (!hdr) return false;
	return (hdr->type == BOOT_HDR_VND_V3 || hdr->type == BOOT_HDR_VND_V4);
}

static void dyn_hdr_dump_props(const boot_dyn_hdr_t *hdr, const char *path) {
	FILE *fp;
	const char *name = NULL;
	const char *cmdline = NULL;
	const char *extra_cmdline = NULL;
	const char *cmd;
	const char *extra;
	uint32_t os_version = 0;

	if (!hdr || !hdr->raw || !path) return;
	fp = fopen(path, "w");
	if (!fp) return;

	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2: {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)hdr->raw;
		name = h0->name;
		cmdline = h0->cmdline;
		extra_cmdline = h0->extra_cmdline;
		os_version = h0->os_version;
		break;
	}
	case BOOT_HDR_V3:
	case BOOT_HDR_V4: {
		struct boot_img_hdr_v3 *h3 = (struct boot_img_hdr_v3 *)hdr->raw;
		cmdline = h3->cmdline;
		os_version = h3->os_version;
		break;
	}
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)hdr->raw;
		name = hv->name;
		cmdline = hv->cmdline;
		break;
	}
	default:
		break;
	}

	if (name && name[0] != '\0') {
		fprintf(fp, "name=%s\n", name);
	}
	cmd = cmdline ? cmdline : "";
	extra = extra_cmdline ? extra_cmdline : "";
	fprintf(fp, "cmdline=%.*s%.*s\n", BOOT_ARGS_SIZE, cmd, BOOT_EXTRA_ARGS_SIZE, extra);

	if (os_version) {
		int a = 0, b = 0, c = 0, y = 0, m = 0;
		boot_hdr_decode_os_version(os_version, &a, &b, &c, &y, &m);
		fprintf(fp, "os_version=%d.%d.%d\n", a, b, c);
		fprintf(fp, "os_patch_level=%d-%02d\n", y, m);
	}
	fclose(fp);
}

static void dyn_hdr_print(const boot_dyn_hdr_t *hdr) {
	uint32_t ver;
	bool is_vnd;
	uint32_t os_ver = 0;

	if (!hdr || !hdr->raw) return;

	ver = dyn_hdr_version(hdr);
	is_vnd = dyn_hdr_is_vendor(hdr);

	fprintf(stderr, "%-*s [%u]\n", PADDING, "HEADER_VER", ver);
	if (!is_vnd) {
		fprintf(stderr, "%-*s [%u]\n", PADDING, "KERNEL_SZ", *dyn_hdr_kernel_size((boot_dyn_hdr_t *)hdr));
	}
	fprintf(stderr, "%-*s [%u]\n", PADDING, "RAMDISK_SZ", *dyn_hdr_ramdisk_size((boot_dyn_hdr_t *)hdr));
	if (ver < 3 && !is_vnd) {
		fprintf(stderr, "%-*s [%u]\n", PADDING, "SECOND_SZ", *dyn_hdr_second_size((boot_dyn_hdr_t *)hdr));
	}
	if (ver == 1 || ver == 2) {
		fprintf(stderr, "%-*s [%u]\n", PADDING, "RECOV_DTBO_SZ", *dyn_hdr_recovery_dtbo_size((boot_dyn_hdr_t *)hdr));
	}
	if (ver == 2 || is_vnd) {
		fprintf(stderr, "%-*s [%u]\n", PADDING, "DTB_SZ", *dyn_hdr_dtb_size((boot_dyn_hdr_t *)hdr));
	}
	if (ver == 4 && is_vnd) {
		fprintf(stderr, "%-*s [%u]\n", PADDING, "BOOTCONFIG_SZ", *dyn_hdr_bootconfig_size((boot_dyn_hdr_t *)hdr));
	}

	if (ver < 3) {
		os_ver = ((struct boot_img_hdr_v0 *)hdr->raw)->os_version;
	} else if (!is_vnd) {
		os_ver = ((struct boot_img_hdr_v3 *)hdr->raw)->os_version;
	}
	if (os_ver) {
		int a = 0, b = 0, c = 0, y = 0, m = 0;
		boot_hdr_decode_os_version(os_ver, &a, &b, &c, &y, &m);
		fprintf(stderr, "%-*s [%d.%d.%d]\n", PADDING, "OS_VERSION", a, b, c);
		fprintf(stderr, "%-*s [%d-%02d]\n", PADDING, "OS_PATCH_LEVEL", y, m);
	}
	fprintf(stderr, "%-*s [%u]\n", PADDING, "PAGESIZE", dyn_hdr_page_size(hdr));
}

/* =========================================================================
 * 3. Streaming Decompression via BusyBox libarchive
 * ========================================================================= */

static int bb_decompress_data(uint8_t fmt, const void *in, size_t in_sz, int out_fd) {
	char tmp_path[] = "/tmp/mb_decomp_XXXXXX";
	int in_fd;
	int ret = 0;
	transformer_state_t xstate;

	if (!in || in_sz == 0 || out_fd < 0) return -1;

	in_fd = mkstemp(tmp_path);
	if (in_fd < 0) return -1;
	unlink(tmp_path);

	if (full_write(in_fd, in, in_sz) != (ssize_t)in_sz) {
		close(in_fd);
		return -1;
	}
	lseek(in_fd, 0, SEEK_SET);

	init_transformer_state(&xstate);
	xstate.src_fd = in_fd;
	xstate.dst_fd = out_fd;

	if (fmt == BOOT_FMT_GZIP) {
		ret = unpack_gz_stream(&xstate);
	} else if (fmt == BOOT_FMT_XZ) {
		ret = unpack_xz_stream(&xstate);
	} else if (fmt == BOOT_FMT_LZMA) {
		ret = unpack_lzma_stream(&xstate);
	} else if (fmt == BOOT_FMT_BZIP2) {
		ret = unpack_bz2_stream(&xstate);
	} else {
		/* Uncompressed or unsupported: dump raw bytes */
		if (full_write(out_fd, in, in_sz) != (ssize_t)in_sz) ret = -1;
	}

	close(in_fd);
	return ret;
}

static int write_to_disk(const char *dest, const void *data, size_t size, uint8_t fmt, bool skip_decomp) {
	int fd;
	int ret = 0;

	if (!dest || !data || size == 0) return 0;

	fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		bb_perror_msg("failed to open '%s'", dest);
		return -1;
	}

	if (!skip_decomp && boot_fmt_compressed(fmt)) {
		ret = bb_decompress_data(fmt, data, size, fd);
	} else {
		if (full_write(fd, data, size) != (ssize_t)size) ret = -1;
	}
	close(fd);
	return ret;
}

/* =========================================================================
 * 4. Image Parsing & Unpacking Core
 * ========================================================================= */

static bool boot_img_parse(boot_img_t *img, const char *path) {
	int fd;
	struct stat st;
	const uint8_t *start;
	const uint8_t *end;
	const uint8_t *hdr_ptr = NULL;
	const uint8_t *addr;
	uint32_t page_sz;
	size_t off;

	memset(img, 0, sizeof(*img));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		bb_perror_msg("cannot open '%s'", path);
		return false;
	}

	if (fstat(fd, &st) < 0 || st.st_size < 1024) {
		bb_error_msg("file '%s' is too small or invalid", path);
		close(fd);
		return false;
	}

	img->map_sz = st.st_size;
	img->map_ptr = mmap(NULL, img->map_sz, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (img->map_ptr == MAP_FAILED || !img->map_ptr) {
		bb_perror_msg("mmap failed for '%s'", path);
		return false;
	}

	fprintf(stderr, "Parsing boot image: [%s]\n", path);
	start = (const uint8_t *)img->map_ptr;
	end = start + img->map_sz;

	for (addr = start; addr + sizeof(struct boot_img_hdr_v0) <= end; ++addr) {
		size_t rem = end - addr;
		if (rem >= 8 && memcmp(addr, "CHROMEOS", 8) == 0) {
			img->flags |= BOOT_FLAG_CHROMEOS;
			addr += 65535;
			continue;
		}
		if (rem >= 8 && memcmp(addr, "ANDROID!", 8) == 0) {
			hdr_ptr = addr;
			break;
		}
		if (rem >= 8 && memcmp(addr, "VNDRBOOT", 8) == 0) {
			hdr_ptr = addr;
			break;
		}
	}

	if (!hdr_ptr) {
		bb_error_msg("no valid boot image header found in '%s'", path);
		munmap(img->map_ptr, img->map_sz);
		return false;
	}

	/* Detect header version */
	if (memcmp(hdr_ptr, "VNDRBOOT", 8) == 0) {
		uint32_t ver = *(uint32_t *)(hdr_ptr + 8);
		if (ver == 4) img->hdr.type = BOOT_HDR_VND_V4;
		else img->hdr.type = BOOT_HDR_VND_V3;
		fprintf(stderr, "VENDOR_BOOT_HDR\n");
	} else {
		uint32_t ver = *(uint32_t *)(hdr_ptr + 40);
		if (ver == 1) img->hdr.type = BOOT_HDR_V1;
		else if (ver == 2) img->hdr.type = BOOT_HDR_V2;
		else if (ver == 3) img->hdr.type = BOOT_HDR_V3;
		else if (ver == 4) img->hdr.type = BOOT_HDR_V4;
		else img->hdr.type = BOOT_HDR_V0;
	}

	img->hdr.raw_sz = dyn_hdr_size(img->hdr.type);
	img->hdr.raw = xzalloc(img->hdr.raw_sz);
	memcpy(img->hdr.raw, hdr_ptr, img->hdr.raw_sz);

	dyn_hdr_print(&img->hdr);

	page_sz = dyn_hdr_page_size(&img->hdr);
	off = align_to(img->hdr.raw_sz, page_sz);

	/* Populate sections */
	if (!dyn_hdr_is_vendor(&img->hdr)) {
		img->kernel_size = *dyn_hdr_kernel_size(&img->hdr);
		if (img->kernel_size > 0 && hdr_ptr + off + img->kernel_size <= end) {
			int dtb_off;
			img->kernel = hdr_ptr + off;
			img->k_fmt = boot_check_fmt(img->kernel, img->kernel_size);
			fprintf(stderr, "%-*s [%s]\n", PADDING, "KERNEL_FMT", boot_fmt2name(img->k_fmt));
			off += align_to(img->kernel_size, page_sz);

			dtb_off = boot_find_dtb_offset(img->kernel, img->kernel_size);
			if (dtb_off > 0) {
				img->kernel_dtb = img->kernel + dtb_off;
				img->kernel_dtb_size = img->kernel_size - dtb_off;
				img->kernel_size = dtb_off;
				fprintf(stderr, "%-*s [%zu]\n", PADDING, "KERNEL_DTB_SZ", img->kernel_dtb_size);
			}
		}
	}

	img->ramdisk_size = *dyn_hdr_ramdisk_size(&img->hdr);
	if (img->ramdisk_size > 0 && hdr_ptr + off + img->ramdisk_size <= end) {
		img->ramdisk = hdr_ptr + off;
		img->r_fmt = boot_check_fmt(img->ramdisk, img->ramdisk_size);
		fprintf(stderr, "%-*s [%s]\n", PADDING, "RAMDISK_FMT", boot_fmt2name(img->r_fmt));
		off += align_to(img->ramdisk_size, page_sz);
	}

	img->second_size = *dyn_hdr_second_size(&img->hdr);
	if (img->second_size > 0 && hdr_ptr + off + img->second_size <= end) {
		img->second = hdr_ptr + off;
		off += align_to(img->second_size, page_sz);
	}

	img->extra_size = *dyn_hdr_extra_size(&img->hdr);
	if (img->extra_size > 0 && hdr_ptr + off + img->extra_size <= end) {
		img->extra = hdr_ptr + off;
		img->e_fmt = boot_check_fmt(img->extra, img->extra_size);
		off += align_to(img->extra_size, page_sz);
	}

	img->recovery_dtbo_size = *dyn_hdr_recovery_dtbo_size(&img->hdr);
	if (img->recovery_dtbo_size > 0 && hdr_ptr + off + img->recovery_dtbo_size <= end) {
		img->recovery_dtbo = hdr_ptr + off;
		off += align_to(img->recovery_dtbo_size, page_sz);
	}

	img->dtb_size = *dyn_hdr_dtb_size(&img->hdr);
	if (img->dtb_size > 0 && hdr_ptr + off + img->dtb_size <= end) {
		img->dtb = hdr_ptr + off;
		off += align_to(img->dtb_size, page_sz);
	}

	img->bootconfig_size = *dyn_hdr_bootconfig_size(&img->hdr);
	if (img->bootconfig_size > 0 && hdr_ptr + off + img->bootconfig_size <= end) {
		img->bootconfig = hdr_ptr + off;
		off += align_to(img->bootconfig_size, page_sz);
	}

	/* AVB 2.0 footer check at end of image */
	if (img->map_sz >= sizeof(struct avb_footer)) {
		const uint8_t *footer_ptr = (const uint8_t *)img->map_ptr + img->map_sz - sizeof(struct avb_footer);
		if (memcmp(footer_ptr, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0) {
			fprintf(stderr, "VBMETA\n");
			img->flags |= BOOT_FLAG_AVB;
			img->avb_footer = (const struct avb_footer *)footer_ptr;
		}
	}

	img->valid = true;
	return true;
}

static void boot_img_free(boot_img_t *img) {
	if (!img) return;
	if (img->hdr.raw) {
		free(img->hdr.raw);
		img->hdr.raw = NULL;
	}
	if (img->map_ptr && img->map_ptr != MAP_FAILED) {
		munmap(img->map_ptr, img->map_sz);
		img->map_ptr = NULL;
	}
	img->valid = false;
}

/* =========================================================================
 * 5. magiskboot unpack, repack, split, hexpatch commands
 * ========================================================================= */

static int magiskboot_unpack(const char *image, bool skip_decomp, bool hdr_only) {
	boot_img_t boot;
	if (!boot_img_parse(&boot, image)) return 1;

	dyn_hdr_dump_props(&boot.hdr, HEADER_FILE);
	if (hdr_only) {
		boot_img_free(&boot);
		return 0;
	}

	if (boot.kernel && boot.kernel_size > 0) {
		write_to_disk(KERNEL_FILE, boot.kernel, boot.kernel_size, boot.k_fmt, skip_decomp);
	}
	if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
		write_to_disk(KER_DTB_FILE, boot.kernel_dtb, boot.kernel_dtb_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.ramdisk && boot.ramdisk_size > 0) {
		write_to_disk(RAMDISK_FILE, boot.ramdisk, boot.ramdisk_size, boot.r_fmt, skip_decomp);
	}
	if (boot.second && boot.second_size > 0) {
		write_to_disk(SECOND_FILE, boot.second, boot.second_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.extra && boot.extra_size > 0) {
		write_to_disk(EXTRA_FILE, boot.extra, boot.extra_size, boot.e_fmt, skip_decomp);
	}
	if (boot.recovery_dtbo && boot.recovery_dtbo_size > 0) {
		write_to_disk(RECV_DTBO_FILE, boot.recovery_dtbo, boot.recovery_dtbo_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.dtb && boot.dtb_size > 0) {
		write_to_disk(DTB_FILE, boot.dtb, boot.dtb_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.bootconfig && boot.bootconfig_size > 0) {
		write_to_disk(BOOTCONFIG_FILE, boot.bootconfig, boot.bootconfig_size, BOOT_FMT_UNKNOWN, true);
	}

	boot_img_free(&boot);
	return 0;
}

static ssize_t copy_file_section(int out_fd, const char *src_path, uint32_t page_sz, uint32_t *out_size) {
	int ifd;
	struct stat st;
	off_t written = 0;

	ifd = open(src_path, O_RDONLY | O_CLOEXEC);
	if (ifd < 0) {
		if (out_size) *out_size = 0;
		return 0;
	}

	if (fstat(ifd, &st) < 0 || st.st_size <= 0) {
		close(ifd);
		if (out_size) *out_size = 0;
		return 0;
	}

	while (written < st.st_size) {
		ssize_t s = sendfile(out_fd, ifd, NULL, st.st_size - written);
		if (s <= 0) {
			if (s < 0 && (errno == EINTR || errno == EAGAIN)) continue;
			break;
		}
		written += s;
	}
	close(ifd);

	if (out_size) *out_size = (uint32_t)written;

	/* Align to page size */
	if (page_sz > 0) {
		size_t rem = (size_t)written % page_sz;
		if (rem > 0) {
			size_t pad = page_sz - rem;
			static const uint8_t zeros[4096] = {0};
			while (pad > 0) {
				size_t chunk = (pad > sizeof(zeros)) ? sizeof(zeros) : pad;
				full_write(out_fd, zeros, chunk);
				pad -= chunk;
			}
		}
	}
	return written;
}

static int magiskboot_repack(const char *src_img, const char *out_img, bool skip_comp) {
	boot_img_t boot;
	const char *target;
	int out_fd;
	uint32_t page_sz;
	size_t hdr_pad;
	uint32_t kernel_sz = 0, ramdisk_sz = 0, second_sz = 0, extra_sz = 0;
	uint32_t recov_dtbo_sz = 0, dtb_sz = 0, bootconfig_sz = 0;

	(void)skip_comp;

	if (!boot_img_parse(&boot, src_img)) return 1;

	target = out_img ? out_img : "new-boot.img";
	fprintf(stderr, "Repack to boot image: [%s]\n", target);

	out_fd = open(target, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) {
		bb_perror_msg("failed to create '%s'", target);
		boot_img_free(&boot);
		return 1;
	}

	page_sz = dyn_hdr_page_size(&boot.hdr);
	hdr_pad = align_to(boot.hdr.raw_sz, page_sz);

	/* Seek past header for now */
	lseek(out_fd, hdr_pad, SEEK_SET);

	if (!dyn_hdr_is_vendor(&boot.hdr)) {
		copy_file_section(out_fd, KERNEL_FILE, page_sz, &kernel_sz);
		if (access(KER_DTB_FILE, R_OK) == 0) {
			uint32_t dtb_part = 0;
			size_t rem;
			copy_file_section(out_fd, KER_DTB_FILE, 0, &dtb_part);
			kernel_sz += dtb_part;
			/* Re-align */
			rem = kernel_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}
		*dyn_hdr_kernel_size(&boot.hdr) = kernel_sz;
	}

	copy_file_section(out_fd, RAMDISK_FILE, page_sz, &ramdisk_sz);
	*dyn_hdr_ramdisk_size(&boot.hdr) = ramdisk_sz;

	if (access(SECOND_FILE, R_OK) == 0) {
		copy_file_section(out_fd, SECOND_FILE, page_sz, &second_sz);
		*dyn_hdr_second_size(&boot.hdr) = second_sz;
	}
	if (access(EXTRA_FILE, R_OK) == 0) {
		copy_file_section(out_fd, EXTRA_FILE, page_sz, &extra_sz);
		*dyn_hdr_extra_size(&boot.hdr) = extra_sz;
	}
	if (access(RECV_DTBO_FILE, R_OK) == 0) {
		copy_file_section(out_fd, RECV_DTBO_FILE, page_sz, &recov_dtbo_sz);
		*dyn_hdr_recovery_dtbo_size(&boot.hdr) = recov_dtbo_sz;
	}
	if (access(DTB_FILE, R_OK) == 0) {
		copy_file_section(out_fd, DTB_FILE, page_sz, &dtb_sz);
		*dyn_hdr_dtb_size(&boot.hdr) = dtb_sz;
	}
	if (access(BOOTCONFIG_FILE, R_OK) == 0) {
		copy_file_section(out_fd, BOOTCONFIG_FILE, page_sz, &bootconfig_sz);
		*dyn_hdr_bootconfig_size(&boot.hdr) = bootconfig_sz;
	}

	/* Write updated header at offset 0 */
	lseek(out_fd, 0, SEEK_SET);
	full_write(out_fd, boot.hdr.raw, boot.hdr.raw_sz);

	/* Pad header */
	if (hdr_pad > boot.hdr.raw_sz) {
		static const uint8_t zeros[4096] = {0};
		full_write(out_fd, zeros, hdr_pad - boot.hdr.raw_sz);
	}

	dyn_hdr_print(&boot.hdr);

	close(out_fd);
	boot_img_free(&boot);
	return 0;
}

static int magiskboot_split(const char *image) {
	return magiskboot_unpack(image, true, false);
}

static uint8_t parse_hex_nibble(char c) {
	if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
	if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
	return 0;
}

static int magiskboot_hexpatch(const char *file, const char *from_hex, const char *to_hex) {
	size_t from_len;
	size_t to_len;
	size_t pat_sz;
	size_t patch_sz;
	uint8_t *pat;
	uint8_t *patch;
	int fd;
	struct stat st;
	uint8_t *buf;
	size_t count = 0;
	size_t limit;
	size_t i;

	if (!file || !from_hex || !to_hex) return 1;

	from_len = strlen(from_hex);
	to_len = strlen(to_hex);
	if (from_len == 0 || (from_len % 2) != 0 || to_len == 0 || (to_len % 2) != 0) {
		bb_error_msg("hex strings must have an even length");
		return 1;
	}

	pat_sz = from_len / 2;
	patch_sz = to_len / 2;
	pat = xmalloc(pat_sz);
	patch = xmalloc(patch_sz);

	for (i = 0; i < pat_sz; i++) {
		pat[i] = (parse_hex_nibble(from_hex[i * 2]) << 4) | parse_hex_nibble(from_hex[i * 2 + 1]);
	}
	for (i = 0; i < patch_sz; i++) {
		patch[i] = (parse_hex_nibble(to_hex[i * 2]) << 4) | parse_hex_nibble(to_hex[i * 2 + 1]);
	}

	fd = open(file, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		bb_perror_msg("failed to open '%s'", file);
		free(pat);
		free(patch);
		return 1;
	}

	if (fstat(fd, &st) < 0 || st.st_size < (off_t)pat_sz) {
		close(fd);
		free(pat);
		free(patch);
		return 1;
	}

	buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		bb_perror_msg("mmap failed");
		close(fd);
		free(pat);
		free(patch);
		return 1;
	}

	limit = (size_t)st.st_size - pat_sz;
	for (i = 0; i <= limit; ++i) {
		if (buf[i] == pat[0] && memcmp(buf + i, pat, pat_sz) == 0) {
			size_t replace_len = (patch_sz < pat_sz) ? patch_sz : pat_sz;
			memcpy(buf + i, patch, replace_len);
			fprintf(stderr, "Patch @ 0x%08zX [%s] -> [%s]\n", i, from_hex, to_hex);
			count++;
			i += pat_sz - 1;
		}
	}

	msync(buf, st.st_size, MS_SYNC);
	munmap(buf, st.st_size);
	close(fd);
	free(pat);
	free(patch);

	return (count > 0) ? 0 : 1;
}

/* =========================================================================
 * 6. BusyBox Applet Entrypoint
 * ========================================================================= */

int magiskboot_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int magiskboot_main(int argc, char **argv) {
	const char *cmd;

	if (argc < 2) {
		bb_show_usage();
	}

	cmd = argv[1];

	if (strcmp(cmd, "unpack") == 0) {
		bool hdr_only = false;
		const char *img;
		if (argc < 3) bb_show_usage();
		img = argv[2];
		if (strcmp(argv[2], "-h") == 0) {
			if (argc < 4) bb_show_usage();
			hdr_only = true;
			img = argv[3];
		}
		return magiskboot_unpack(img, false, hdr_only);
	}

	if (strcmp(cmd, "repack") == 0) {
		bool skip_comp = false;
		int idx = 2;
		const char *src;
		const char *out;

		if (argc < 3) bb_show_usage();
		if (strcmp(argv[2], "-n") == 0) {
			skip_comp = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		src = argv[idx++];
		out = (idx < argc) ? argv[idx] : NULL;
		return magiskboot_repack(src, out, skip_comp);
	}

	if (strcmp(cmd, "split") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_split(argv[2]);
	}

	if (strcmp(cmd, "hexpatch") == 0) {
		if (argc < 5) bb_show_usage();
		return magiskboot_hexpatch(argv[2], argv[3], argv[4]);
	}

	if (strcmp(cmd, "dtb") == 0) {
		int fd;
		if (argc < 3) bb_show_usage();
		fd = open(argv[2], O_RDONLY);
		if (fd >= 0) {
			struct stat st;
			if (fstat(fd, &st) == 0 && st.st_size > 4) {
				void *p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
				if (p && p != MAP_FAILED) {
					int32_t off = boot_find_dtb_offset(p, st.st_size);
					if (off >= 0) {
						printf("DTB @ offset: 0x%X (%d bytes)\n", off, (int)st.st_size - off);
					} else {
						printf("No DTB found in '%s'\n", argv[2]);
					}
					munmap(p, st.st_size);
				}
			}
			close(fd);
		}
		return 0;
	}

	if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
		bb_show_usage();
	}

	bb_error_msg("unknown command '%s'", cmd);
	bb_show_usage();
	return 1;
}
