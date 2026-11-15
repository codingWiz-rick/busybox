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
//usage:     "\n	unpack [-h|-k] <boot.img>     Unpack boot image components (-k: kernel only)"
//usage:     "\n	repack [-n] <boot.img> [out]  Repack components into new boot image"
//usage:     "\n	extract-kernel <img|rec> [out] Extract kernel from boot/recovery/TWRP image"
//usage:     "\n	extract <image> <comp> [out]  Extract component (kernel, ramdisk, dtb, etc.)"
//usage:     "\n	split <boot.img>              Split boot image without decompressing ramdisk"
//usage:     "\n	hexpatch <file> <from> <to>   In-place hex string patch"
//usage:     "\n	cpio <ramdisk.cpio> [args...] CPIO operations (test, ls, extract, add, mkdir, rm)"
//usage:     "\n	dtb <file> [test|print|patch] Device tree blob inspector and verity patcher"
//usage:     "\n	decompress <in> [out]         Decompress kernel/ramdisk image"
//usage:     "\n	cleanup                       Clean up unpacked temporary files"

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

static int dyn_hdr_load_props(boot_dyn_hdr_t *hdr, const char *path) {
	FILE *fp;
	char *name = NULL;
	char *cmdline = NULL;
	char *extra_cmdline = NULL;
	uint32_t *os_ver_ptr = NULL;
	size_t name_max = 0;
	size_t cmd_max = 0;
	size_t extra_max = 0;
	char line[2048];

	if (!hdr || !hdr->raw || !path) return -1;
	fp = fopen(path, "r");
	if (!fp) return -1;

	switch (hdr->type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2: {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)hdr->raw;
		name = h0->name;
		name_max = sizeof(h0->name);
		cmdline = h0->cmdline;
		cmd_max = sizeof(h0->cmdline);
		extra_cmdline = h0->extra_cmdline;
		extra_max = sizeof(h0->extra_cmdline);
		os_ver_ptr = &h0->os_version;
		break;
	}
	case BOOT_HDR_V3:
	case BOOT_HDR_V4: {
		struct boot_img_hdr_v3 *h3 = (struct boot_img_hdr_v3 *)hdr->raw;
		cmdline = h3->cmdline;
		cmd_max = sizeof(h3->cmdline);
		os_ver_ptr = &h3->os_version;
		break;
	}
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)hdr->raw;
		name = hv->name;
		name_max = sizeof(hv->name);
		cmdline = hv->cmdline;
		cmd_max = sizeof(hv->cmdline);
		break;
	}
	default:
		break;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *p = line;
		char *eq;
		const char *key;
		const char *val;
		size_t vlen;

		while (*p && (*p == ' ' || *p == '\t')) p++;
		if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n') continue;

		line[strcspn(line, "\r\n")] = '\0';
		eq = strchr(p, '=');
		if (!eq) continue;
		*eq = '\0';
		key = p;
		val = eq + 1;
		vlen = strlen(val);

		if (strcmp(key, "name") == 0 && name && name_max > 0) {
			memset(name, 0, name_max);
			strncpy(name, val, name_max - 1);
		} else if (strcmp(key, "cmdline") == 0 && cmdline && cmd_max > 0) {
			memset(cmdline, 0, cmd_max);
			if (extra_cmdline && extra_max > 0) memset(extra_cmdline, 0, extra_max);
			if (vlen >= cmd_max && extra_cmdline && extra_max > 0) {
				strncpy(cmdline, val, cmd_max - 1);
				strncpy(extra_cmdline, val + (cmd_max - 1), extra_max - 1);
			} else {
				strncpy(cmdline, val, cmd_max - 1);
			}
		} else if (strcmp(key, "os_version") == 0 && os_ver_ptr) {
			int a = 0, b = 0, c = 0;
			if (sscanf(val, "%d.%d.%d", &a, &b, &c) >= 1) {
				uint32_t patch = *os_ver_ptr & 0x7ff;
				uint32_t ver = (((uint32_t)(a & 0x7f) << 14) |
				                ((uint32_t)(b & 0x7f) << 7)  |
				                ((uint32_t)(c & 0x7f)));
				*os_ver_ptr = (ver << 11) | patch;
			}
		} else if (strcmp(key, "os_patch_level") == 0 && os_ver_ptr) {
			int y = 0, m = 0;
			if (sscanf(val, "%d-%d", &y, &m) == 2) {
				uint32_t ver = *os_ver_ptr >> 11;
				int year = (y >= 2000) ? (y - 2000) : 0;
				uint32_t patch = (((uint32_t)(year & 0x7f) << 4) | (uint32_t)(m & 0x0f));
				*os_ver_ptr = (ver << 11) | (patch & 0x7ff);
			}
		}
	}

	fclose(fp);
	return 0;
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
		else ret = 0;
	}

	close(in_fd);
	return (ret < 0) ? -1 : 0;
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

static int magiskboot_unpack(const char *image, bool skip_decomp, bool hdr_only, bool kernel_only) {
	boot_img_t boot;
	if (!boot_img_parse(&boot, image)) return 1;

	if (kernel_only) {
		if (boot.kernel && boot.kernel_size > 0) {
			write_to_disk(KERNEL_FILE, boot.kernel, boot.kernel_size, boot.k_fmt, skip_decomp);
			fprintf(stderr, "[+] Extracted kernel -> [%s]\n", KERNEL_FILE);
		}
		if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
			write_to_disk(KER_DTB_FILE, boot.kernel_dtb, boot.kernel_dtb_size, BOOT_FMT_UNKNOWN, true);
			fprintf(stderr, "[+] Extracted kernel_dtb -> [%s]\n", KER_DTB_FILE);
		}
		boot_img_free(&boot);
		return 0;
	}

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

static const char *prepare_ramdisk_for_repack(boot_img_t *boot, bool skip_comp, char *tmp_buf, size_t tmp_sz) {
	if (access("ramdisk.cpio.gz", R_OK) == 0) return "ramdisk.cpio.gz";
	if (access("ramdisk.cpio.xz", R_OK) == 0) return "ramdisk.cpio.xz";
	if (access("ramdisk.cpio.lz4", R_OK) == 0) return "ramdisk.cpio.lz4";
	if (access("ramdisk.cpio.bz2", R_OK) == 0) return "ramdisk.cpio.bz2";

	if (!skip_comp && boot->r_fmt == BOOT_FMT_GZIP && access(RAMDISK_FILE, R_OK) == 0) {
		int in_fd = open(RAMDISK_FILE, O_RDONLY);
		if (in_fd >= 0) {
			uint8_t magic[2];
			ssize_t n = read(in_fd, magic, 2);
			close(in_fd);
			if (n == 2 && magic[0] == 0x1f && magic[1] == 0x8b) {
				return RAMDISK_FILE;
			}
		}
		snprintf(tmp_buf, tmp_sz, "/tmp/mb_ramdisk_%d.gz", (int)getpid());
		{
			int out_tfd = open(tmp_buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (out_tfd >= 0) {
				pid_t pid = fork();
				if (pid == 0) {
					dup2(out_tfd, STDOUT_FILENO);
					close(out_tfd);
					execlp("gzip", "gzip", "-9c", RAMDISK_FILE, (char *)NULL);
					_exit(127);
				}
				close(out_tfd);
				if (pid > 0) {
					int status;
					waitpid(pid, &status, 0);
					if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
						return tmp_buf;
					}
				}
				unlink(tmp_buf);
			}
		}
	}
	return RAMDISK_FILE;
}

static void dyn_hdr_recalc_id(boot_dyn_hdr_t *hdr, int out_fd,
                              size_t hdr_pad, uint32_t page_sz,
                              uint32_t kernel_sz, uint32_t ramdisk_sz,
                              uint32_t second_sz, uint32_t extra_sz,
                              uint32_t recov_dtbo_sz, uint32_t dtb_sz) {
	off_t total_sz;
	uint8_t *p;
	uint32_t ver;
	bool use_sha256;
	uint8_t *id_ptr = NULL;

	if (!hdr || !hdr->raw || out_fd < 0) return;

	ver = dyn_hdr_version(hdr);
	use_sha256 = (ver >= 2);

	if (hdr->type == BOOT_HDR_V0 || hdr->type == BOOT_HDR_V1 || hdr->type == BOOT_HDR_V2) {
		id_ptr = (uint8_t *)((struct boot_img_hdr_v0 *)hdr->raw)->id;
	}
	if (!id_ptr) return;

	total_sz = lseek(out_fd, 0, SEEK_CUR);
	if (total_sz <= (off_t)hdr_pad) return;

	p = (uint8_t *)mmap(NULL, total_sz, PROT_READ, MAP_SHARED, out_fd, 0);
	if (p == MAP_FAILED || !p) return;

	memset(id_ptr, 0, BOOT_ID_SIZE);

	{
		size_t off_k = hdr_pad;
		size_t off_r = off_k + align_to(kernel_sz, page_sz);
		size_t off_s = off_r + align_to(ramdisk_sz, page_sz);
		size_t off_e = off_s + align_to(second_sz, page_sz);
		size_t off_rec = off_e + align_to(extra_sz, page_sz);
		size_t off_dtb = off_rec + align_to(recov_dtbo_sz, page_sz);

		if (use_sha256) {
			sha256_ctx_t ctx;
			sha256_begin(&ctx);
			if (kernel_sz && off_k + kernel_sz <= (size_t)total_sz) {
				sha256_hash(&ctx, p + off_k, kernel_sz);
			}
			sha256_hash(&ctx, &kernel_sz, sizeof(kernel_sz));

			if (ramdisk_sz && off_r + ramdisk_sz <= (size_t)total_sz) {
				sha256_hash(&ctx, p + off_r, ramdisk_sz);
			}
			sha256_hash(&ctx, &ramdisk_sz, sizeof(ramdisk_sz));

			if (second_sz && off_s + second_sz <= (size_t)total_sz) {
				sha256_hash(&ctx, p + off_s, second_sz);
			}
			sha256_hash(&ctx, &second_sz, sizeof(second_sz));

			if (extra_sz && off_e + extra_sz <= (size_t)total_sz) {
				sha256_hash(&ctx, p + off_e, extra_sz);
				sha256_hash(&ctx, &extra_sz, sizeof(extra_sz));
			}

			if (ver >= 1) {
				if (recov_dtbo_sz && off_rec + recov_dtbo_sz <= (size_t)total_sz) {
					sha256_hash(&ctx, p + off_rec, recov_dtbo_sz);
				}
				sha256_hash(&ctx, &recov_dtbo_sz, sizeof(recov_dtbo_sz));
			}

			if (ver >= 2) {
				if (dtb_sz && off_dtb + dtb_sz <= (size_t)total_sz) {
					sha256_hash(&ctx, p + off_dtb, dtb_sz);
				}
				sha256_hash(&ctx, &dtb_sz, sizeof(dtb_sz));
			}

			sha256_end(&ctx, id_ptr);
		} else {
			sha1_ctx_t ctx;
			sha1_begin(&ctx);
			if (kernel_sz && off_k + kernel_sz <= (size_t)total_sz) {
				sha1_hash(&ctx, p + off_k, kernel_sz);
			}
			sha1_hash(&ctx, &kernel_sz, sizeof(kernel_sz));

			if (ramdisk_sz && off_r + ramdisk_sz <= (size_t)total_sz) {
				sha1_hash(&ctx, p + off_r, ramdisk_sz);
			}
			sha1_hash(&ctx, &ramdisk_sz, sizeof(ramdisk_sz));

			if (second_sz && off_s + second_sz <= (size_t)total_sz) {
				sha1_hash(&ctx, p + off_s, second_sz);
			}
			sha1_hash(&ctx, &second_sz, sizeof(second_sz));

			if (extra_sz && off_e + extra_sz <= (size_t)total_sz) {
				sha1_hash(&ctx, p + off_e, extra_sz);
				sha1_hash(&ctx, &extra_sz, sizeof(extra_sz));
			}

			sha1_end(&ctx, id_ptr);
		}
	}

	munmap(p, total_sz);
}

static int magiskboot_repack(const char *src_img, const char *out_img, bool skip_comp) {
	boot_img_t boot;
	const char *target;
	const char *ramdisk_path;
	char tmp_ramdisk[PATH_MAX];
	int out_fd;
	uint32_t page_sz;
	size_t hdr_pad;
	uint32_t kernel_sz = 0, ramdisk_sz = 0, second_sz = 0, extra_sz = 0;
	uint32_t recov_dtbo_sz = 0, dtb_sz = 0, bootconfig_sz = 0;

	tmp_ramdisk[0] = '\0';

	if (!boot_img_parse(&boot, src_img)) return 1;

	/* 1. Reload properties from ./header if present */
	if (access(HEADER_FILE, R_OK) == 0) {
		dyn_hdr_load_props(&boot.hdr, HEADER_FILE);
		fprintf(stderr, "[+] Loaded header properties from '%s'\n", HEADER_FILE);
	}

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

	/* Select ramdisk file (with auto-compression if needed) */
	ramdisk_path = prepare_ramdisk_for_repack(&boot, skip_comp, tmp_ramdisk, sizeof(tmp_ramdisk));
	copy_file_section(out_fd, ramdisk_path, page_sz, &ramdisk_sz);
	*dyn_hdr_ramdisk_size(&boot.hdr) = ramdisk_sz;
	if (tmp_ramdisk[0] != '\0') {
		unlink(tmp_ramdisk);
	}

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

	/* 2. Recalculate header SHA checksum */
	dyn_hdr_recalc_id(&boot.hdr, out_fd, hdr_pad, page_sz,
	                  kernel_sz, ramdisk_sz, second_sz, extra_sz,
	                  recov_dtbo_sz, dtb_sz);

	/* 3. Handle AVB 2.0 footer and vbmeta */
	if ((boot.flags & BOOT_FLAG_AVB) && boot.avb_footer) {
		uint64_t orig_vbmeta_off = __builtin_bswap64(boot.avb_footer->vbmeta_offset);
		uint64_t orig_vbmeta_sz = __builtin_bswap64(boot.avb_footer->vbmeta_size);
		if (orig_vbmeta_sz > 0 && orig_vbmeta_off + orig_vbmeta_sz <= boot.map_sz) {
			struct avb_footer new_footer;
			size_t rem;
			off_t aosp_img_size;
			off_t new_vbmeta_off;

			aosp_img_size = lseek(out_fd, 0, SEEK_CUR);
			rem = (size_t)aosp_img_size % 4096;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, 4096 - rem);
			}
			new_vbmeta_off = lseek(out_fd, 0, SEEK_CUR);

			full_write(out_fd, (const uint8_t *)boot.map_ptr + orig_vbmeta_off, orig_vbmeta_sz);

			rem = (size_t)orig_vbmeta_sz % 4096;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, 4096 - rem);
			}

			memcpy(&new_footer, boot.avb_footer, sizeof(new_footer));
			new_footer.original_image_size = __builtin_bswap64((uint64_t)aosp_img_size);
			new_footer.vbmeta_offset = __builtin_bswap64((uint64_t)new_vbmeta_off);
			new_footer.vbmeta_size = boot.avb_footer->vbmeta_size;
			full_write(out_fd, &new_footer, sizeof(new_footer));
			fprintf(stderr, "[+] Preserved AVB 2.0 footer (original_image_size=%zu, vbmeta_offset=%zu)\n",
			        (size_t)aosp_img_size, (size_t)new_vbmeta_off);
		}
	}

	/* 4. Write updated header at offset 0 */
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
	return magiskboot_unpack(image, true, false, false);
}

static int magiskboot_extract_kernel(const char *image, const char *outfile, bool skip_decomp) {
	boot_img_t boot;
	const char *dest;
	int ret;

	if (!image) return 1;
	if (!boot_img_parse(&boot, image)) return 1;

	if (!boot.kernel || boot.kernel_size == 0) {
		bb_error_msg("no kernel found in '%s' (is this a vendor_boot image?)", image);
		boot_img_free(&boot);
		return 1;
	}

	dest = outfile ? outfile : KERNEL_FILE;
	ret = write_to_disk(dest, boot.kernel, boot.kernel_size, boot.k_fmt, skip_decomp);
	if (ret == 0) {
		fprintf(stderr, "[+] Extracted kernel -> [%s] (%s, %u bytes)\n",
				dest, boot_fmt2name(boot.k_fmt), boot.kernel_size);
		if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
			char *dtb_dest = outfile ? xasprintf("%s.dtb", outfile) : (char *)KER_DTB_FILE;
			write_to_disk(dtb_dest, boot.kernel_dtb, boot.kernel_dtb_size, BOOT_FMT_UNKNOWN, true);
			fprintf(stderr, "[+] Extracted embedded kernel DTB -> [%s] (%zu bytes)\n",
					dtb_dest, boot.kernel_dtb_size);
			if (outfile) free(dtb_dest);
		}
	} else {
		bb_error_msg("failed to write kernel to '%s'", dest);
	}

	boot_img_free(&boot);
	return (ret == 0) ? 0 : 1;
}

static int magiskboot_extract_component(const char *image, const char *comp, const char *outfile, bool skip_decomp) {
	boot_img_t boot;
	const char *dest;
	const void *data = NULL;
	size_t sz = 0;
	uint8_t fmt = BOOT_FMT_UNKNOWN;
	int ret;

	if (!image || !comp) return 1;
	if (!boot_img_parse(&boot, image)) return 1;

	if (strcmp(comp, "kernel") == 0) {
		data = boot.kernel;
		sz = boot.kernel_size;
		fmt = boot.k_fmt;
		dest = outfile ? outfile : KERNEL_FILE;
	} else if (strcmp(comp, "ramdisk") == 0) {
		data = boot.ramdisk;
		sz = boot.ramdisk_size;
		fmt = boot.r_fmt;
		dest = outfile ? outfile : RAMDISK_FILE;
	} else if (strcmp(comp, "dtb") == 0) {
		data = boot.dtb;
		sz = boot.dtb_size;
		dest = outfile ? outfile : DTB_FILE;
	} else if (strcmp(comp, "kernel_dtb") == 0) {
		data = boot.kernel_dtb;
		sz = boot.kernel_dtb_size;
		dest = outfile ? outfile : KER_DTB_FILE;
	} else if (strcmp(comp, "recovery_dtbo") == 0) {
		data = boot.recovery_dtbo;
		sz = boot.recovery_dtbo_size;
		dest = outfile ? outfile : RECV_DTBO_FILE;
	} else if (strcmp(comp, "second") == 0) {
		data = boot.second;
		sz = boot.second_size;
		dest = outfile ? outfile : SECOND_FILE;
	} else if (strcmp(comp, "extra") == 0) {
		data = boot.extra;
		sz = boot.extra_size;
		fmt = boot.e_fmt;
		dest = outfile ? outfile : EXTRA_FILE;
	} else if (strcmp(comp, "bootconfig") == 0) {
		data = boot.bootconfig;
		sz = boot.bootconfig_size;
		dest = outfile ? outfile : BOOTCONFIG_FILE;
	} else {
		bb_error_msg("unknown component '%s' (supported: kernel, ramdisk, dtb, kernel_dtb, recovery_dtbo, second, extra, bootconfig)", comp);
		boot_img_free(&boot);
		return 1;
	}

	if (!data || sz == 0) {
		bb_error_msg("component '%s' not present in '%s'", comp, image);
		boot_img_free(&boot);
		return 1;
	}

	ret = write_to_disk(dest, data, sz, fmt, skip_decomp);
	if (ret == 0) {
		fprintf(stderr, "[+] Component '%s' extracted to [%s] (%zu bytes)\n", comp, dest, sz);
	}
	boot_img_free(&boot);
	return (ret == 0) ? 0 : 1;
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
 * 6. Native CPIO Ramdisk Engine
 * ========================================================================= */

struct cpio_newc_hdr {
	char magic[6];
	char ino[8];
	char mode[8];
	char uid[8];
	char gid[8];
	char nlink[8];
	char mtime[8];
	char filesize[8];
	char maj[8];
	char min[8];
	char rmaj[8];
	char rmin[8];
	char namesize[8];
	char check[8];
};

typedef struct cpio_node {
	struct cpio_node *next;
	char *name;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint32_t nlink;
	uint32_t mtime;
	uint32_t filesize;
	uint32_t ino;
	uint32_t maj;
	uint32_t min;
	uint32_t rmaj;
	uint32_t rmin;
	void *data;
} cpio_node_t;

static uint32_t cpio_hex8_to_u32(const char *s) {
	char buf[9];
	memcpy(buf, s, 8);
	buf[8] = '\0';
	return (uint32_t)strtoul(buf, NULL, 16);
}

static cpio_node_t *cpio_read_all(const char *path) {
	int fd;
	struct stat st;
	uint8_t *map;
	size_t off = 0;
	cpio_node_t *head = NULL;
	cpio_node_t **tail = &head;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return NULL;
	if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(struct cpio_newc_hdr)) {
		close(fd);
		return NULL;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED || !map) return NULL;

	while (off + sizeof(struct cpio_newc_hdr) <= (size_t)st.st_size) {
		const struct cpio_newc_hdr *h = (const struct cpio_newc_hdr *)(map + off);
		uint32_t namesize;
		uint32_t filesize;
		size_t name_pad;
		size_t data_pad;
		cpio_node_t *node;

		if (memcmp(h->magic, "070701", 6) != 0 && memcmp(h->magic, "070702", 6) != 0) {
			break;
		}

		namesize = cpio_hex8_to_u32(h->namesize);
		filesize = cpio_hex8_to_u32(h->filesize);
		off += sizeof(struct cpio_newc_hdr);

		if (off + namesize > (size_t)st.st_size) break;

		node = xzalloc(sizeof(*node));
		node->name = xstrndup((const char *)(map + off), namesize);
		node->mode = cpio_hex8_to_u32(h->mode);
		node->uid = cpio_hex8_to_u32(h->uid);
		node->gid = cpio_hex8_to_u32(h->gid);
		node->nlink = cpio_hex8_to_u32(h->nlink);
		node->mtime = cpio_hex8_to_u32(h->mtime);
		node->filesize = filesize;
		node->ino = cpio_hex8_to_u32(h->ino);
		node->maj = cpio_hex8_to_u32(h->maj);
		node->min = cpio_hex8_to_u32(h->min);
		node->rmaj = cpio_hex8_to_u32(h->rmaj);
		node->rmin = cpio_hex8_to_u32(h->rmin);

		name_pad = ((sizeof(struct cpio_newc_hdr) + namesize + 3) & ~3) - sizeof(struct cpio_newc_hdr);
		off += name_pad;

		if (strcmp(node->name, "TRAILER!!!") == 0) {
			free(node->name);
			free(node);
			break;
		}

		if (filesize > 0) {
			if (off + filesize > (size_t)st.st_size) {
				free(node->name);
				free(node);
				break;
			}
			node->data = xmemdup(map + off, filesize);
			data_pad = (filesize + 3) & ~3;
			off += data_pad;
		}

		*tail = node;
		tail = &node->next;
	}

	munmap(map, st.st_size);
	return head;
}

static void cpio_free_all(cpio_node_t *head) {
	while (head) {
		cpio_node_t *next = head->next;
		free(head->name);
		free(head->data);
		free(head);
		head = next;
	}
}

static int cpio_write_all(const char *path, cpio_node_t *head) {
	char tmp_path[PATH_MAX];
	int fd;
	cpio_node_t *curr;
	static const uint8_t zeros[4] = {0};

	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", path, (int)getpid());
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) return -1;

	for (curr = head; curr; curr = curr->next) {
		struct cpio_newc_hdr h;
		uint32_t namesize = (uint32_t)strlen(curr->name) + 1;
		size_t head_bytes;
		size_t name_pad;
		size_t data_pad;

		memcpy(h.magic, "070701", 6);
		snprintf(h.ino, sizeof(h.ino) + 1, "%08X", curr->ino ? curr->ino : 1);
		snprintf(h.mode, sizeof(h.mode) + 1, "%08X", curr->mode);
		snprintf(h.uid, sizeof(h.uid) + 1, "%08X", curr->uid);
		snprintf(h.gid, sizeof(h.gid) + 1, "%08X", curr->gid);
		snprintf(h.nlink, sizeof(h.nlink) + 1, "%08X", curr->nlink ? curr->nlink : 1);
		snprintf(h.mtime, sizeof(h.mtime) + 1, "%08X", curr->mtime);
		snprintf(h.filesize, sizeof(h.filesize) + 1, "%08X", curr->filesize);
		snprintf(h.maj, sizeof(h.maj) + 1, "%08X", curr->maj);
		snprintf(h.min, sizeof(h.min) + 1, "%08X", curr->min);
		snprintf(h.rmaj, sizeof(h.rmaj) + 1, "%08X", curr->rmaj);
		snprintf(h.rmin, sizeof(h.rmin) + 1, "%08X", curr->rmin);
		snprintf(h.namesize, sizeof(h.namesize) + 1, "%08X", namesize);
		memset(h.check, '0', 8);

		full_write(fd, &h, sizeof(h));
		full_write(fd, curr->name, namesize);

		head_bytes = sizeof(h) + namesize;
		name_pad = ((head_bytes + 3) & ~3) - head_bytes;
		if (name_pad > 0) full_write(fd, zeros, name_pad);

		if (curr->data && curr->filesize > 0) {
			full_write(fd, curr->data, curr->filesize);
			data_pad = ((curr->filesize + 3) & ~3) - curr->filesize;
			if (data_pad > 0) full_write(fd, zeros, data_pad);
		}
	}

	/* Write TRAILER!!! */
	{
		struct cpio_newc_hdr tr;
		static const char trailer_name[] = "TRAILER!!!";
		uint32_t namesize = (uint32_t)sizeof(trailer_name);
		size_t head_bytes;
		size_t pad;

		memset(&tr, '0', sizeof(tr));
		memcpy(tr.magic, "070701", 6);
		snprintf(tr.namesize, sizeof(tr.namesize) + 1, "%08X", namesize);
		full_write(fd, &tr, sizeof(tr));
		full_write(fd, trailer_name, namesize);
		head_bytes = sizeof(tr) + namesize;
		pad = ((head_bytes + 3) & ~3) - head_bytes;
		if (pad > 0) full_write(fd, zeros, pad);
	}

	close(fd);
	if (rename(tmp_path, path) != 0) {
		unlink(tmp_path);
		return -1;
	}
	return 0;
}

static int magiskboot_cpio(int argc, char **argv) {
	const char *cpio_file;
	const char *act;
	cpio_node_t *head;
	cpio_node_t *curr;
	int ret = 0;

	if (argc < 4) bb_show_usage();
	cpio_file = argv[2];
	act = argv[3];

	if (strcmp(act, "test") == 0) {
		int fd = open(cpio_file, O_RDONLY);
		char magic[6];
		ssize_t n;
		if (fd < 0) return 1;
		n = read(fd, magic, 6);
		close(fd);
		if (n == 6 && (memcmp(magic, "070701", 6) == 0 || memcmp(magic, "070702", 6) == 0)) {
			printf("0\n");
			return 0;
		}
		return 1;
	}

	head = cpio_read_all(cpio_file);
	if (!head) {
		bb_error_msg("failed to read cpio '%s'", cpio_file);
		return 1;
	}

	if (strcmp(act, "ls") == 0) {
		for (curr = head; curr; curr = curr->next) {
			printf("%06o %10u %s\n", curr->mode, curr->filesize, curr->name);
		}
	} else if (strcmp(act, "extract") == 0) {
		const char *target_entry = (argc >= 5) ? argv[4] : NULL;
		const char *out_file = (argc >= 6) ? argv[5] : target_entry;

		if (target_entry) {
			bool found = false;
			for (curr = head; curr; curr = curr->next) {
				if (strcmp(curr->name, target_entry) == 0) {
					int out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, curr->mode & 07777);
					if (out_fd >= 0) {
						if (curr->data && curr->filesize > 0) {
							full_write(out_fd, curr->data, curr->filesize);
						}
						close(out_fd);
						chmod(out_file, curr->mode & 07777);
						found = true;
						fprintf(stderr, "[+] Extracted '%s' -> '%s'\n", target_entry, out_file);
					}
					break;
				}
			}
			if (!found) {
				bb_error_msg("entry '%s' not found in '%s'", target_entry, cpio_file);
				ret = 1;
			}
		} else {
			for (curr = head; curr; curr = curr->next) {
				if (S_ISDIR(curr->mode)) {
					bb_make_directory(curr->name, curr->mode & 07777, FILEUTILS_RECUR);
				} else {
					int out_fd;
					char *slash = strrchr(curr->name, '/');
					if (slash) {
						char *d = xstrndup(curr->name, slash - curr->name);
						bb_make_directory(d, 0755, FILEUTILS_RECUR);
						free(d);
					}
					out_fd = open(curr->name, O_WRONLY | O_CREAT | O_TRUNC, curr->mode & 07777);
					if (out_fd >= 0) {
						if (curr->data && curr->filesize > 0) {
							full_write(out_fd, curr->data, curr->filesize);
						}
						close(out_fd);
						chmod(curr->name, curr->mode & 07777);
					}
				}
			}
			fprintf(stderr, "[+] Extracted all cpio entries into current directory\n");
		}
	} else if (strcmp(act, "mkdir") == 0) {
		uint32_t mode;
		const char *path;
		cpio_node_t *node;

		if (argc < 6) bb_show_usage();
		mode = (uint32_t)strtoul(argv[4], NULL, 8) | 0040000;
		path = argv[5];

		node = xzalloc(sizeof(*node));
		node->name = xstrdup(path);
		node->mode = mode;
		node->nlink = 2;
		node->next = head;
		head = node;

		ret = cpio_write_all(cpio_file, head);
		if (ret == 0) fprintf(stderr, "[+] Created directory '%s' (%04o) in '%s'\n", path, mode & 07777, cpio_file);
	} else if (strcmp(act, "add") == 0) {
		uint32_t mode;
		const char *entry_name;
		const char *infile;
		int in_fd;
		struct stat st;
		void *buf = NULL;
		size_t in_sz = 0;
		cpio_node_t *node = NULL;

		if (argc < 7) bb_show_usage();
		mode = (uint32_t)strtoul(argv[4], NULL, 8) | 0100000;
		entry_name = argv[5];
		infile = argv[6];

		in_fd = open(infile, O_RDONLY);
		if (in_fd >= 0 && fstat(in_fd, &st) == 0 && st.st_size > 0) {
			in_sz = (size_t)st.st_size;
			buf = xmalloc(in_sz);
			if (full_read(in_fd, buf, in_sz) != (ssize_t)in_sz) {
				free(buf);
				buf = NULL;
				in_sz = 0;
			}
			close(in_fd);
		} else if (in_fd >= 0) {
			close(in_fd);
		}

		/* Check if entry already exists */
		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				node = curr;
				break;
			}
		}

		if (node) {
			free(node->data);
			node->data = buf;
			node->filesize = (uint32_t)in_sz;
			node->mode = mode;
		} else {
			node = xzalloc(sizeof(*node));
			node->name = xstrdup(entry_name);
			node->mode = mode;
			node->filesize = (uint32_t)in_sz;
			node->data = buf;
			node->nlink = 1;
			node->next = head;
			head = node;
		}

		ret = cpio_write_all(cpio_file, head);
		if (ret == 0) fprintf(stderr, "[+] Added file '%s' (%zu bytes) into '%s'\n", entry_name, in_sz, cpio_file);
	} else if (strcmp(act, "rm") == 0) {
		bool recur = false;
		const char *entry_name;
		int idx = 4;
		cpio_node_t *prev = NULL;

		if (argc < 5) bb_show_usage();
		if (strcmp(argv[idx], "-r") == 0) {
			recur = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		entry_name = argv[idx];

		curr = head;
		while (curr) {
			bool match = (strcmp(curr->name, entry_name) == 0);
			if (!match && recur) {
				size_t elen = strlen(entry_name);
				if (strncmp(curr->name, entry_name, elen) == 0 && curr->name[elen] == '/') {
					match = true;
				}
			}

			if (match) {
				cpio_node_t *to_del = curr;
				if (prev) {
					prev->next = curr->next;
					curr = curr->next;
				} else {
					head = curr->next;
					curr = head;
				}
				free(to_del->name);
				free(to_del->data);
				free(to_del);
			} else {
				prev = curr;
				curr = curr->next;
			}
		}

		ret = cpio_write_all(cpio_file, head);
		if (ret == 0) fprintf(stderr, "[+] Removed '%s' from '%s'\n", entry_name, cpio_file);
	} else {
		bb_error_msg("unknown cpio action '%s' (supported: test, ls, extract, mkdir, add, rm)", act);
		ret = 1;
	}

	cpio_free_all(head);
	return ret;
}

/* =========================================================================
 * 7. Device Tree Blob (DTB) Manipulation Engine
 * ========================================================================= */

static int magiskboot_dtb(int argc, char **argv) {
	const char *dtb_file;
	const char *action;
	int fd;
	struct stat st;
	uint8_t *p;

	if (argc < 3) bb_show_usage();
	dtb_file = argv[2];
	action = (argc >= 4) ? argv[3] : "test";

	fd = open(dtb_file, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		bb_perror_msg("cannot open '%s'", dtb_file);
		return 1;
	}
	if (fstat(fd, &st) < 0 || st.st_size < 16) {
		close(fd);
		return 1;
	}

	p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED || !p) {
		close(fd);
		return 1;
	}

	if (strcmp(action, "test") == 0) {
		int32_t off = boot_find_dtb_offset(p, st.st_size);
		if (off >= 0) {
			printf("Valid DTB @ offset: 0x%X (%zu bytes)\n", off, (size_t)st.st_size - off);
			munmap(p, st.st_size);
			close(fd);
			return 0;
		} else {
			printf("No DTB found in '%s'\n", dtb_file);
			munmap(p, st.st_size);
			close(fd);
			return 1;
		}
	} else if (strcmp(action, "print") == 0 || strcmp(action, "dump") == 0) {
		int32_t off = boot_find_dtb_offset(p, st.st_size);
		if (off >= 0) {
			const uint8_t *dtb = p + off;
			uint32_t dtb_total_sz = ((uint32_t)dtb[4] << 24) | ((uint32_t)dtb[5] << 16) | ((uint32_t)dtb[6] << 8) | (uint32_t)dtb[7];
			uint32_t dtb_ver = ((uint32_t)dtb[20] << 24) | ((uint32_t)dtb[21] << 16) | ((uint32_t)dtb[22] << 8) | (uint32_t)dtb[23];
			printf("DTB Magic: 0x%08X\n", ((uint32_t)dtb[0] << 24) | ((uint32_t)dtb[1] << 16) | ((uint32_t)dtb[2] << 8) | (uint32_t)dtb[3]);
			printf("DTB Total Size: %u bytes\n", dtb_total_sz);
			printf("FDT Version: %u\n", dtb_ver);
		}
	} else if (strcmp(action, "patch") == 0) {
		size_t i;
		int count = 0;
		for (i = 0; i + 8 <= (size_t)st.st_size; i++) {
			if (memcmp(p + i, ",verify", 7) == 0) {
				memset(p + i, 0, 7);
				fprintf(stderr, "[+] Patched fstab verity @ 0x%08zX\n", i);
				count++;
			} else if (memcmp(p + i, ",avb", 4) == 0) {
				memset(p + i, 0, 4);
				fprintf(stderr, "[+] Patched fstab avb @ 0x%08zX\n", i);
				count++;
			}
		}
		msync(p, st.st_size, MS_SYNC);
		fprintf(stderr, "[+] DTB patch complete: %d patches applied\n", count);
	}

	munmap(p, st.st_size);
	close(fd);
	return 0;
}

/* =========================================================================
 * 8. Cleanup & Decompression Helpers
 * ========================================================================= */

static int magiskboot_cleanup(void) {
	static const char *const files[] = {
		KERNEL_FILE, KER_DTB_FILE, RAMDISK_FILE,
		"ramdisk.cpio.gz", "ramdisk.cpio.xz", "ramdisk.cpio.lz4", "ramdisk.cpio.bz2",
		SECOND_FILE, EXTRA_FILE, RECV_DTBO_FILE, DTB_FILE,
		BOOTCONFIG_FILE, HEADER_FILE, "new-boot.img", NULL
	};
	int i;
	int count = 0;
	for (i = 0; files[i]; i++) {
		if (unlink(files[i]) == 0) count++;
	}
	fprintf(stderr, "[+] Cleaned up %d temporary boot files\n", count);
	return 0;
}

static int magiskboot_decompress(const char *infile, const char *outfile) {
	int ifd;
	int ofd;
	struct stat st;
	void *in_map;
	uint8_t fmt;
	int ret;
	char *default_out = NULL;

	if (!infile) return 1;
	ifd = open(infile, O_RDONLY | O_CLOEXEC);
	if (ifd < 0) {
		bb_perror_msg("cannot open '%s'", infile);
		return 1;
	}
	if (fstat(ifd, &st) < 0 || st.st_size <= 0) {
		close(ifd);
		return 1;
	}
	in_map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, ifd, 0);
	close(ifd);
	if (in_map == MAP_FAILED || !in_map) return 1;

	fmt = boot_check_fmt(in_map, st.st_size);
	if (!boot_fmt_compressed(fmt)) {
		bb_error_msg("file '%s' is not in a supported compressed format (%s)", infile, boot_fmt2name(fmt));
		munmap(in_map, st.st_size);
		return 1;
	}

	if (!outfile) {
		char *dot = strrchr(infile, '.');
		if (dot && dot != infile) {
			default_out = xstrndup(infile, dot - infile);
			outfile = default_out;
		} else {
			default_out = xasprintf("%s.out", infile);
			outfile = default_out;
		}
	}

	ofd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (ofd < 0) {
		bb_perror_msg("cannot create '%s'", outfile);
		munmap(in_map, st.st_size);
		free(default_out);
		return 1;
	}

	ret = bb_decompress_data(fmt, in_map, st.st_size, ofd);
	close(ofd);
	munmap(in_map, st.st_size);

	if (ret == 0) {
		fprintf(stderr, "[+] Decompressed [%s] (%s) -> [%s]\n", infile, boot_fmt2name(fmt), outfile);
	} else {
		bb_error_msg("decompression failed for '%s'", infile);
		unlink(outfile);
	}
	free(default_out);
	return (ret == 0) ? 0 : 1;
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
		bool kernel_only = false;
		const char *img;
		int idx = 2;
		if (argc < 3) bb_show_usage();
		while (idx < argc && argv[idx][0] == '-') {
			if (strcmp(argv[idx], "-h") == 0) hdr_only = true;
			else if (strcmp(argv[idx], "-k") == 0) kernel_only = true;
			idx++;
		}
		if (idx >= argc) bb_show_usage();
		img = argv[idx];
		return magiskboot_unpack(img, false, hdr_only, kernel_only);
	}

	if (strcmp(cmd, "extract-kernel") == 0) {
		const char *img;
		const char *out = NULL;
		bool skip_decomp = false;
		int idx = 2;
		if (argc < 3) bb_show_usage();
		if (strcmp(argv[idx], "-n") == 0) {
			skip_decomp = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		img = argv[idx++];
		if (idx < argc) out = argv[idx];
		return magiskboot_extract_kernel(img, out, skip_decomp);
	}

	if (strcmp(cmd, "extract") == 0) {
		const char *img;
		const char *comp;
		const char *out = NULL;
		bool skip_decomp = false;
		int idx = 2;
		if (argc < 4) bb_show_usage();
		if (strcmp(argv[idx], "-n") == 0) {
			skip_decomp = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		img = argv[idx++];
		comp = argv[idx++];
		if (idx < argc) out = argv[idx];
		return magiskboot_extract_component(img, comp, out, skip_decomp);
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

	if (strcmp(cmd, "cleanup") == 0) {
		return magiskboot_cleanup();
	}

	if (strcmp(cmd, "decompress") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_decompress(argv[2], (argc >= 4) ? argv[3] : NULL);
	}

	if (strcmp(cmd, "dtb") == 0) {
		return magiskboot_dtb(argc, argv);
	}

	if (strcmp(cmd, "cpio") == 0) {
		return magiskboot_cpio(argc, argv);
	}

	if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
		bb_show_usage();
	}

	bb_error_msg("unknown command '%s'", cmd);
	bb_show_usage();
	return 1;
}
