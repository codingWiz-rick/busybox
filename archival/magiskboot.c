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
//usage:     "\n	init <boot.img> <action> [...] In-place init tool (status, extract, replace, wrap, unwrap, rm)"
//usage:     "\n	kernel <img|rec> <act> [...]  Kernel tool (status, patch, sigenforce, cfi, de-enforce, permissive, rkp, hexpatch, cfi-hash)"
//usage:     "\n	de-enforce <img|rec> [out]    Neutralize module signature enforcement & CFI in boot/kernel image"
//usage:     "\n	patch-sigenforce <img|rec> [out] Neutralize kernel module signature enforcement (CONFIG_MODULE_SIG_FORCE)"
//usage:     "\n	patch-cfi <img|rec> [out]     Neutralize Clang Control Flow Integrity (KCFI & Forward-Edge CFI)"
//usage:     "\n	dtb <file> [test|print|patch] Device tree blob inspector and verity patcher"
//usage:     "\n	module <act> <mod.ko> [...]   Kernel module toolkit (info, check, audit, strip, patch, load, finit, unload)"
//usage:     "\n	patch-vermagic <mod.ko> [opts] Patch module vermagic, altinstructions, and CFI stubs"
//usage:     "\n	dist [opts...] <out.zip>      Create universal Magisk/AnyKernel recovery flashable ZIP"
//usage:     "\n	zip <file.zip> <act> [...]    ZIP archive toolkit (create, list, extract)"
//usage:     "\n	fstab <file> <print|patch...> In-place fstab configuration tool"
//usage:     "\n	cmdline <file> <print|patch|add|rm...> Kernel cmdline tool"
//usage:     "\n	vbmeta <file> [status|disable|restore] VBMeta AVB 2.0 flags inspector and verity disabler"
//usage:     "\n	decompress <in> [out]         Decompress kernel/ramdisk image"
//usage:     "\n	cleanup                       Clean up unpacked temporary files"

#include "libbb.h"
#include "bb_archive.h"
#include "magiskboot.h"

#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

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
	if (len >= 4 && *(const uint32_t *)b == SWAP_LE32(0x58881688)) return BOOT_FMT_MTK;

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
	case BOOT_FMT_MTK:         return "mtk";
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
			if (img->k_fmt == BOOT_FMT_MTK && img->kernel_size > sizeof(struct mtk_hdr)) {
				img->flags |= BOOT_FLAG_MTK_KERNEL;
				img->kernel = (const uint8_t *)img->kernel + sizeof(struct mtk_hdr);
				img->kernel_size -= sizeof(struct mtk_hdr);
				img->k_fmt = boot_check_fmt(img->kernel, img->kernel_size);
				fprintf(stderr, "%-*s [MTK-KERNEL]\n", PADDING, "MTK_HEADER");
			}
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
		if (img->r_fmt == BOOT_FMT_MTK && img->ramdisk_size > sizeof(struct mtk_hdr)) {
			img->flags |= BOOT_FLAG_MTK_RAMDISK;
			img->ramdisk = (const uint8_t *)img->ramdisk + sizeof(struct mtk_hdr);
			img->ramdisk_size -= sizeof(struct mtk_hdr);
			img->r_fmt = boot_check_fmt(img->ramdisk, img->ramdisk_size);
			fprintf(stderr, "%-*s [MTK-RAMDISK]\n", PADDING, "MTK_HEADER");
		}
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

static int compress_file_format(const char *src, const char *dst, uint8_t fmt) {
	int out_tfd;
	const char *prog = "gzip";
	const char *arg = "-9c";
	pid_t pid;

	if (fmt == BOOT_FMT_XZ || fmt == BOOT_FMT_LZMA) {
		prog = "xz";
		arg = "-c";
	} else if (fmt == BOOT_FMT_LZ4 || fmt == BOOT_FMT_LZ4_LEGACY || fmt == BOOT_FMT_LZ4_LG) {
		prog = "lz4";
		arg = "-c";
	} else if (fmt == BOOT_FMT_BZIP2) {
		prog = "bzip2";
		arg = "-c";
	}

	out_tfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_tfd < 0) return -1;

	pid = fork();
	if (pid == 0) {
		dup2(out_tfd, STDOUT_FILENO);
		close(out_tfd);
		execlp(prog, prog, arg, src, (char *)NULL);
		_exit(127);
	}
	close(out_tfd);
	if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
	}
	unlink(dst);
	return -1;
}

static const char *prepare_ramdisk_for_repack(boot_img_t *boot, bool skip_comp, char *tmp_buf, size_t tmp_sz) {
	if (access("ramdisk.cpio.gz", R_OK) == 0) return "ramdisk.cpio.gz";
	if (access("ramdisk.cpio.xz", R_OK) == 0) return "ramdisk.cpio.xz";
	if (access("ramdisk.cpio.lz4", R_OK) == 0) return "ramdisk.cpio.lz4";
	if (access("ramdisk.cpio.bz2", R_OK) == 0) return "ramdisk.cpio.bz2";

	if (!skip_comp && boot_fmt_compressed(boot->r_fmt) && access(RAMDISK_FILE, R_OK) == 0) {
		int in_fd = open(RAMDISK_FILE, O_RDONLY);
		if (in_fd >= 0) {
			uint8_t magic[2];
			ssize_t n = read(in_fd, magic, 2);
			close(in_fd);
			if (n == 2 && magic[0] == 0x1f && magic[1] == 0x8b) {
				return RAMDISK_FILE;
			}
		}
		snprintf(tmp_buf, tmp_sz, "/tmp/mb_ramdisk_%d.comp", (int)getpid());
		if (compress_file_format(RAMDISK_FILE, tmp_buf, boot->r_fmt) == 0) {
			return tmp_buf;
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
		if (boot.flags & BOOT_FLAG_MTK_KERNEL) {
			struct stat kst;
			if (stat(KERNEL_FILE, &kst) == 0) {
				struct mtk_hdr mtk;
				uint32_t kraw_sz = 0;
				size_t rem;
				memset(&mtk, 0, sizeof(mtk));
				mtk.magic = SWAP_LE32(0x58881688);
				mtk.size = SWAP_LE32((uint32_t)kst.st_size);
				strncpy(mtk.name, "KERNEL", sizeof(mtk.name) - 1);
				full_write(out_fd, &mtk, sizeof(mtk));
				copy_file_section(out_fd, KERNEL_FILE, 0, &kraw_sz);
				kernel_sz = kraw_sz + sizeof(mtk);
				rem = kernel_sz % page_sz;
				if (rem > 0) {
					static const uint8_t zeros[4096] = {0};
					full_write(out_fd, zeros, page_sz - rem);
				}
			} else {
				copy_file_section(out_fd, KERNEL_FILE, page_sz, &kernel_sz);
			}
		} else {
			copy_file_section(out_fd, KERNEL_FILE, page_sz, &kernel_sz);
		}
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
	if (boot.flags & BOOT_FLAG_MTK_RAMDISK) {
		struct stat rst;
		if (stat(ramdisk_path, &rst) == 0) {
			struct mtk_hdr mtk;
			uint32_t rraw_sz = 0;
			size_t rem;
			memset(&mtk, 0, sizeof(mtk));
			mtk.magic = SWAP_LE32(0x58881688);
			mtk.size = SWAP_LE32((uint32_t)rst.st_size);
			strncpy(mtk.name, "ROOTFS", sizeof(mtk.name) - 1);
			full_write(out_fd, &mtk, sizeof(mtk));
			copy_file_section(out_fd, ramdisk_path, 0, &rraw_sz);
			ramdisk_sz = rraw_sz + sizeof(mtk);
			rem = ramdisk_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		} else {
			copy_file_section(out_fd, ramdisk_path, page_sz, &ramdisk_sz);
		}
	} else {
		copy_file_section(out_fd, ramdisk_path, page_sz, &ramdisk_sz);
	}
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

static bool hexpatch_buffer(uint8_t *buf, size_t size, const char *from_hex, const char *to_hex) {
	size_t from_len, to_len, pat_sz, patch_sz;
	uint8_t *pat, *patch;
	size_t count = 0;
	size_t limit, i;

	if (!buf || !from_hex || !to_hex) return false;

	from_len = strlen(from_hex);
	to_len = strlen(to_hex);
	if (from_len == 0 || (from_len % 2) != 0 || to_len == 0 || (to_len % 2) != 0) {
		bb_error_msg("hex strings must have an even length");
		return false;
	}

	pat_sz = from_len / 2;
	patch_sz = to_len / 2;
	if (size < pat_sz) return false;

	pat = xmalloc(pat_sz);
	patch = xmalloc(patch_sz);

	for (i = 0; i < pat_sz; i++) {
		pat[i] = (parse_hex_nibble(from_hex[i * 2]) << 4) | parse_hex_nibble(from_hex[i * 2 + 1]);
	}
	for (i = 0; i < patch_sz; i++) {
		patch[i] = (parse_hex_nibble(to_hex[i * 2]) << 4) | parse_hex_nibble(to_hex[i * 2 + 1]);
	}

	limit = size - pat_sz;
	for (i = 0; i <= limit; ++i) {
		if (buf[i] == pat[0] && memcmp(buf + i, pat, pat_sz) == 0) {
			size_t replace_len = (patch_sz < pat_sz) ? patch_sz : pat_sz;
			memcpy(buf + i, patch, replace_len);
			fprintf(stderr, "[+] Hex patch @ 0x%08zX [%s] -> [%s]\n", i, from_hex, to_hex);
			count++;
			i += pat_sz - 1;
		}
	}

	free(pat);
	free(patch);
	return (count > 0);
}

static int magiskboot_hexpatch(const char *file, const char *from_hex, const char *to_hex) {
	int fd;
	struct stat st;
	uint8_t *buf;
	bool ok;

	if (!file || !from_hex || !to_hex) return 1;

	fd = open(file, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		bb_perror_msg("failed to open '%s'", file);
		return 1;
	}

	if (fstat(fd, &st) < 0 || st.st_size <= 0) {
		close(fd);
		return 1;
	}

	buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		bb_perror_msg("mmap failed");
		close(fd);
		return 1;
	}

	ok = hexpatch_buffer(buf, st.st_size, from_hex, to_hex);

	msync(buf, st.st_size, MS_SYNC);
	munmap(buf, st.st_size);
	close(fd);

	return ok ? 0 : 1;
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
		const char *dot = strrchr(infile, '.');
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
 * 9. Direct Boot Image Init Manipulation Engine
 * ========================================================================= */

static int magiskboot_init_op(const char *image, const char *action, const char *arg, const char *outfile) {
	boot_img_t boot;
	char tmp_cpio[PATH_MAX];
	int c_fd;
	cpio_node_t *head;
	cpio_node_t *curr;
	bool modified = false;
	int ret = 0;

	if (!image || !action) return 1;

	/* Actions unwrap, restore, rm, remove do not take an input binary; any extra arg is outfile */
	if (strcmp(action, "unwrap") == 0 || strcmp(action, "restore") == 0 ||
	    strcmp(action, "rm") == 0 || strcmp(action, "remove") == 0) {
		if (!outfile && arg) {
			outfile = arg;
			arg = NULL;
		}
	}

	if (!boot_img_parse(&boot, image)) return 1;

	if (!boot.ramdisk || boot.ramdisk_size == 0) {
		bb_error_msg("no ramdisk found in '%s' (is this a vendor_boot or system-as-root image?)", image);
		boot_img_free(&boot);
		return 1;
	}

	snprintf(tmp_cpio, sizeof(tmp_cpio), "/tmp/mb_init_%d.cpio", (int)getpid());
	c_fd = open(tmp_cpio, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (c_fd < 0) {
		bb_perror_msg("failed to create temporary cpio file");
		boot_img_free(&boot);
		return 1;
	}

	if (boot_fmt_compressed(boot.r_fmt)) {
		bb_decompress_data(boot.r_fmt, boot.ramdisk, boot.ramdisk_size, c_fd);
	} else {
		full_write(c_fd, boot.ramdisk, boot.ramdisk_size);
	}
	close(c_fd);

	head = cpio_read_all(tmp_cpio);
	unlink(tmp_cpio);

	if (!head) {
		bb_error_msg("failed to parse ramdisk CPIO archive from '%s'", image);
		boot_img_free(&boot);
		return 1;
	}

	if (strcmp(action, "extract") == 0 || strcmp(action, "get") == 0 || strcmp(action, "dump") == 0) {
		cpio_node_t *init_node = NULL;
		const char *dest;
		int ofd;

		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				init_node = curr;
				break;
			}
		}
		if (!init_node) {
			for (curr = head; curr; curr = curr->next) {
				if (strcmp(curr->name, "init.real") == 0) {
					init_node = curr;
					break;
				}
			}
		}

		if (!init_node) {
			bb_error_msg("no /init entry found in ramdisk of '%s'", image);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		dest = arg ? arg : "init";
		ofd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
		if (ofd < 0) {
			bb_perror_msg("failed to create '%s'", dest);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		if (init_node->data && init_node->filesize > 0) {
			full_write(ofd, init_node->data, init_node->filesize);
		}
		close(ofd);
		chmod(dest, 0755);
		fprintf(stderr, "[+] Extracted '%s' from '%s' -> '%s' (%u bytes)\n",
		        init_node->name, image, dest, init_node->filesize);
		cpio_free_all(head);
		boot_img_free(&boot);
		return 0;
	} else if (strcmp(action, "status") == 0 || strcmp(action, "info") == 0 || strcmp(action, "test") == 0) {
		bool has_init = false;
		bool has_real = false;
		uint32_t init_sz = 0;
		uint32_t real_sz = 0;
		int count = 0;

		for (curr = head; curr; curr = curr->next) {
			count++;
			if (strcmp(curr->name, "init") == 0) {
				has_init = true;
				init_sz = curr->filesize;
			} else if (strcmp(curr->name, "init.real") == 0) {
				has_real = true;
				real_sz = curr->filesize;
			}
		}
		printf("Image:           %s\n", image);
		printf("Ramdisk Entries: %d\n", count);
		printf("Ramdisk Format:  %s\n", boot_fmt2name(boot.r_fmt));
		printf("/init:           %s (%u bytes)\n", has_init ? "PRESENT" : "MISSING", init_sz);
		if (has_real) {
			printf("/init.real:      PRESENT (%u bytes, wrapped PID 1 chainloader)\n", real_sz);
		} else {
			printf("/init.real:      ABSENT (stock init)\n");
		}
		cpio_free_all(head);
		boot_img_free(&boot);
		return 0;
	} else if (strcmp(action, "replace") == 0 || strcmp(action, "add") == 0 || strcmp(action, "set") == 0) {
		int in_fd;
		struct stat st;
		void *new_data;
		cpio_node_t *node = NULL;

		if (!arg) {
			bb_error_msg("missing new init binary argument");
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		in_fd = open(arg, O_RDONLY);
		if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size <= 0) {
			bb_perror_msg("cannot read new init binary '%s'", arg);
			if (in_fd >= 0) close(in_fd);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}
		new_data = xmalloc(st.st_size);
		if (full_read(in_fd, new_data, st.st_size) != (ssize_t)st.st_size) {
			free(new_data);
			close(in_fd);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}
		close(in_fd);

		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				node = curr;
				break;
			}
		}
		if (node) {
			free(node->data);
			node->data = new_data;
			node->filesize = (uint32_t)st.st_size;
			node->mode = 0100755;
		} else {
			node = xzalloc(sizeof(*node));
			node->name = xstrdup("init");
			node->mode = 0100755;
			node->filesize = (uint32_t)st.st_size;
			node->data = new_data;
			node->nlink = 1;
			node->next = head;
			head = node;
		}
		fprintf(stderr, "[+] Injected new init '%s' (%zu bytes)\n", arg, (size_t)st.st_size);
		modified = true;
	} else if (strcmp(action, "wrap") == 0 || strcmp(action, "inject-wrapper") == 0) {
		int in_fd;
		struct stat st;
		void *wrap_data;
		cpio_node_t *init_node = NULL;
		cpio_node_t *real_node = NULL;
		cpio_node_t *new_init;

		if (!arg) {
			bb_error_msg("missing wrapper binary argument");
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		in_fd = open(arg, O_RDONLY);
		if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size <= 0) {
			bb_perror_msg("cannot read wrapper binary '%s'", arg);
			if (in_fd >= 0) close(in_fd);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}
		wrap_data = xmalloc(st.st_size);
		if (full_read(in_fd, wrap_data, st.st_size) != (ssize_t)st.st_size) {
			free(wrap_data);
			close(in_fd);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}
		close(in_fd);

		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) init_node = curr;
			if (strcmp(curr->name, "init.real") == 0) real_node = curr;
		}

		if (init_node && !real_node) {
			free(init_node->name);
			init_node->name = xstrdup("init.real");
			init_node->mode = 0100755;
			fprintf(stderr, "[+] Preserved original /init -> /init.real (%u bytes)\n", init_node->filesize);
		}

		new_init = xzalloc(sizeof(*new_init));
		new_init->name = xstrdup("init");
		new_init->mode = 0100755;
		new_init->filesize = (uint32_t)st.st_size;
		new_init->data = wrap_data;
		new_init->nlink = 1;
		new_init->next = head;
		head = new_init;

		fprintf(stderr, "[+] Installed wrapper binary as /init (%zu bytes)\n", (size_t)st.st_size);
		modified = true;
	} else if (strcmp(action, "unwrap") == 0 || strcmp(action, "restore") == 0) {
		cpio_node_t *prev = NULL;
		cpio_node_t *init_prev = NULL;
		cpio_node_t *init_node = NULL;
		cpio_node_t *real_node = NULL;

		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				init_node = curr;
				init_prev = prev;
			} else if (strcmp(curr->name, "init.real") == 0) {
				real_node = curr;
			}
			prev = curr;
		}

		if (!real_node) {
			bb_error_msg("no /init.real found in '%s' to restore", image);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		if (init_node) {
			if (init_prev) init_prev->next = init_node->next;
			else head = init_node->next;
			free(init_node->name);
			free(init_node->data);
			free(init_node);
		}

		free(real_node->name);
		real_node->name = xstrdup("init");
		real_node->mode = 0100755;
		fprintf(stderr, "[+] Restored /init.real -> /init (%u bytes)\n", real_node->filesize);
		modified = true;
	} else if (strcmp(action, "rm") == 0 || strcmp(action, "remove") == 0) {
		cpio_node_t *prev = NULL;
		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				if (prev) prev->next = curr->next;
				else head = curr->next;
				free(curr->name);
				free(curr->data);
				free(curr);
				fprintf(stderr, "[+] Removed /init from ramdisk\n");
				modified = true;
				break;
			}
			prev = curr;
		}
		if (!modified) {
			bb_error_msg("no /init entry found to remove in '%s'", image);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}
	} else {
		bb_error_msg("unknown init action '%s' (supported: extract, replace, wrap, unwrap, rm, status)", action);
		cpio_free_all(head);
		boot_img_free(&boot);
		return 1;
	}

	if (modified) {
		char tmp_new_cpio[PATH_MAX];
		char tmp_new_rd[PATH_MAX];
		char final_target[PATH_MAX];
		char tmp_out_boot[PATH_MAX + 64];
		int out_fd;
		uint32_t page_sz;
		size_t hdr_pad;
		uint32_t kernel_sz = 0;
		uint32_t ramdisk_sz = 0;
		uint32_t second_sz;
		uint32_t extra_sz;
		uint32_t recov_dtbo_sz;
		uint32_t dtb_sz;
		uint32_t bootconfig_sz;

		snprintf(tmp_new_cpio, sizeof(tmp_new_cpio), "/tmp/mb_new_cpio_%d.cpio", (int)getpid());
		cpio_write_all(tmp_new_cpio, head);
		cpio_free_all(head);

		if (boot_fmt_compressed(boot.r_fmt)) {
			snprintf(tmp_new_rd, sizeof(tmp_new_rd), "/tmp/mb_new_rd_%d.comp", (int)getpid());
			if (compress_file_format(tmp_new_cpio, tmp_new_rd, boot.r_fmt) != 0) {
				bb_error_msg("failed to compress ramdisk (format: %s)", boot_fmt2name(boot.r_fmt));
				unlink(tmp_new_cpio);
				cpio_free_all(head);
				boot_img_free(&boot);
				return 1;
			}
			unlink(tmp_new_cpio);
		} else {
			strncpy(tmp_new_rd, tmp_new_cpio, sizeof(tmp_new_rd) - 1);
			tmp_new_rd[sizeof(tmp_new_rd) - 1] = '\0';
		}

		if (outfile && outfile[0] != '\0') {
			strncpy(final_target, outfile, sizeof(final_target) - 1);
			final_target[sizeof(final_target) - 1] = '\0';
		} else {
			strncpy(final_target, image, sizeof(final_target) - 1);
			final_target[sizeof(final_target) - 1] = '\0';
		}

		snprintf(tmp_out_boot, sizeof(tmp_out_boot), "%s.tmp.%d", final_target, (int)getpid());

		out_fd = open(tmp_out_boot, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
		if (out_fd < 0) {
			bb_perror_msg("failed to create output boot image '%s'", tmp_out_boot);
			unlink(tmp_new_rd);
			boot_img_free(&boot);
			return 1;
		}

		page_sz = dyn_hdr_page_size(&boot.hdr);
		hdr_pad = align_to(boot.hdr.raw_sz, page_sz);
		lseek(out_fd, hdr_pad, SEEK_SET);

		/* 1. Write kernel section */
		if (!dyn_hdr_is_vendor(&boot.hdr) && boot.kernel && boot.kernel_size > 0) {
			size_t rem;
			kernel_sz = (uint32_t)boot.kernel_size;
			full_write(out_fd, boot.kernel, kernel_sz);
			if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
				full_write(out_fd, boot.kernel_dtb, boot.kernel_dtb_size);
				kernel_sz += (uint32_t)boot.kernel_dtb_size;
			}
			rem = kernel_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
			*dyn_hdr_kernel_size(&boot.hdr) = kernel_sz;
		}

		/* 2. Write new ramdisk */
		copy_file_section(out_fd, tmp_new_rd, page_sz, &ramdisk_sz);
		*dyn_hdr_ramdisk_size(&boot.hdr) = ramdisk_sz;
		unlink(tmp_new_rd);

		/* 3. Write remaining sections from memory */
		second_sz = (uint32_t)boot.second_size;
		if (boot.second && second_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.second, second_sz);
			rem = second_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		extra_sz = (uint32_t)boot.extra_size;
		if (boot.extra && extra_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.extra, extra_sz);
			rem = extra_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		recov_dtbo_sz = (uint32_t)boot.recovery_dtbo_size;
		if (boot.recovery_dtbo && recov_dtbo_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.recovery_dtbo, recov_dtbo_sz);
			rem = recov_dtbo_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		dtb_sz = (uint32_t)boot.dtb_size;
		if (boot.dtb && dtb_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.dtb, dtb_sz);
			rem = dtb_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		bootconfig_sz = (uint32_t)boot.bootconfig_size;
		if (boot.bootconfig && bootconfig_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.bootconfig, bootconfig_sz);
			rem = bootconfig_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		/* 4. Recalculate SHA ID */
		dyn_hdr_recalc_id(&boot.hdr, out_fd, hdr_pad, page_sz,
		                  kernel_sz, ramdisk_sz, second_sz, extra_sz,
		                  recov_dtbo_sz, dtb_sz);

		/* 5. Handle AVB footer */
		if ((boot.flags & BOOT_FLAG_AVB) && boot.avb_footer) {
			uint64_t orig_vbmeta_off = __builtin_bswap64(boot.avb_footer->vbmeta_offset);
			uint64_t orig_vbmeta_sz = __builtin_bswap64(boot.avb_footer->vbmeta_size);
			if (orig_vbmeta_sz > 0 && orig_vbmeta_off + orig_vbmeta_sz <= boot.map_sz) {
				struct avb_footer new_footer;
				size_t rem;
				off_t aosp_img_size = lseek(out_fd, 0, SEEK_CUR);
				off_t new_vbmeta_off;

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
			}
		}

		/* 6. Write finalized header at offset 0 */
		lseek(out_fd, 0, SEEK_SET);
		full_write(out_fd, boot.hdr.raw, boot.hdr.raw_sz);

		if (hdr_pad > boot.hdr.raw_sz) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, hdr_pad - boot.hdr.raw_sz);
		}

		close(out_fd);
		boot_img_free(&boot);

		if (rename(tmp_out_boot, final_target) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}

		fprintf(stderr, "[+] Successfully updated boot image init -> '%s'\n", final_target);
		return 0;
	}

	cpio_free_all(head);
	boot_img_free(&boot);
	return ret;
}

/* =========================================================================
 * 10. Direct Kernel Security & Manipulation Engine
 * ========================================================================= */

static inline uint32_t arm64_read_u32(const uint8_t *buf, size_t off) {
	return (uint32_t)buf[off] |
	       ((uint32_t)buf[off + 1] << 8) |
	       ((uint32_t)buf[off + 2] << 16) |
	       ((uint32_t)buf[off + 3] << 24);
}

static inline void arm64_write_u32(uint8_t *buf, size_t off, uint32_t val) {
	buf[off]     = (uint8_t)(val & 0xff);
	buf[off + 1] = (uint8_t)((val >> 8) & 0xff);
	buf[off + 2] = (uint8_t)((val >> 16) & 0xff);
	buf[off + 3] = (uint8_t)((val >> 24) & 0xff);
}

static bool arm64_decode_adrp(uint32_t insn, uint64_t pc, int *rd, uint64_t *page_addr) {
	int64_t immlo;
	int64_t immhi;
	int64_t imm;

	if ((insn & ARM64_ADRP_MASK) != ARM64_ADRP_VAL)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);

	immlo = (int64_t)((insn >> 29) & 0x3U);
	immhi = (int64_t)((insn >> 5) & 0x7ffffU);
	imm = (immhi << 2) | immlo;
	if (imm & (1LL << 20)) imm -= (1LL << 21);

	if (page_addr) {
		*page_addr = (pc & ~0xfffULL) + (uint64_t)(imm << 12);
	}
	return true;
}

static bool arm64_decode_mov_wide(uint32_t insn, int *rd, uint16_t *imm16, int *shift, int *opc) {
	if ((insn & 0x1f800000U) != 0x12800000U)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);
	if (imm16) *imm16 = (uint16_t)((insn >> 5) & 0xffffU);
	if (shift) *shift = (int)(((insn >> 21) & 0x3U) * 16);
	if (opc) *opc = (int)((insn >> 29) & 0x3U);
	return true;
}

static bool arm64_decode_add_sub_imm(uint32_t insn, int *rd, int *rn, uint32_t *imm, bool *is_sub) {
	uint32_t val;
	if ((insn & 0x1f000000U) != 0x11000000U)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);
	if (rn) *rn = (int)((insn >> 5) & 0x1fU);
	if (is_sub) *is_sub = ((insn & (1U << 30)) != 0);

	val = (insn >> 10) & 0xfffU;
	if (insn & (1U << 22)) val <<= 12;
	if (imm) *imm = val;
	return true;
}

static bool patch_sigenforce_buf(uint8_t *buf, size_t size, int *out_checks, int *out_setters) {
	size_t sig_enforce_offset = (size_t)-1;
	int patched_checks = 0;
	int neutralized_setters = 0;
	size_t limit;
	size_t i, j, k;
	uint8_t old_val;
	uint64_t target_page;
	uint32_t target_off;

	if (!buf || size < 64) return false;

	limit = size - 16;
	for (i = 0; i < limit; i += 4) {
		uint32_t inst3 = arm64_read_u32(buf, i + 12);
		int mov_rd, mov_shift, mov_opc;
		uint16_t mov_imm;
		bool is_errno_mov = false;

		if (arm64_decode_mov_wide(inst3, &mov_rd, &mov_imm, &mov_shift, &mov_opc) &&
		    mov_opc == 0 && mov_shift == 0) {
			if (mov_imm == 125 || mov_imm == 128) is_errno_mov = true;
		}
		if (!is_errno_mov && (inst3 & 0x7fffffe0U) == 0x12800fa0U) {
			is_errno_mov = true;
		}
		if (!is_errno_mov) continue;

		{
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			int cbz_reg;
			uint32_t inst1;
			int ldr_rt, ldr_rn;
			uint32_t inst0;
			int adrp_rd;
			uint64_t page_addr;
			size_t target_addr;

			if ((inst2 & ARM64_CBZ_MASK) != ARM64_CBZ_VAL) continue;
			cbz_reg = (int)(inst2 & 0x1fU);

			inst1 = arm64_read_u32(buf, i + 4);
			if ((inst1 & ARM64_LDRB_IMM_MASK) != ARM64_LDRB_IMM_VAL) continue;
			ldr_rt = (int)(inst1 & 0x1fU);
			ldr_rn = (int)((inst1 >> 5) & 0x1fU);
			if (ldr_rt != cbz_reg) continue;

			inst0 = arm64_read_u32(buf, i);
			if (!arm64_decode_adrp(inst0, (uint64_t)i, &adrp_rd, &page_addr) || adrp_rd != ldr_rn)
				continue;

			target_addr = (size_t)(page_addr + (((inst1 >> 10) & 0xfffU)));
			if (target_addr < size) {
				uint32_t mov_wzr = ARM64_MOV_W0_WZR_OPCODE | (uint32_t)cbz_reg;
				sig_enforce_offset = target_addr;
				arm64_write_u32(buf, i + 4, mov_wzr);
				fprintf(stderr, "[+] Found inlined module_sig_check @ 0x%08zX (sig_enforce @ 0x%08zX)\n", i, target_addr);
				fprintf(stderr, "[+] Patched check @ 0x%08zX to MOV w%d, wzr (0x%08X)\n", i + 4, cbz_reg, mov_wzr);
				patched_checks++;
				break;
			}
		}
	}

	if (sig_enforce_offset == (size_t)-1) {
		for (i = 0; i + 20 <= size; i++) {
			if (memcmp(buf + i, "module.sig_enforce=1", 20) == 0) {
				buf[i + 19] = '0';
				fprintf(stderr, "[+] Patched 'module.sig_enforce=1' -> '0' @ 0x%08zX\n", i);
				patched_checks++;
			}
		}
		if (out_checks) *out_checks = patched_checks;
		if (out_setters) *out_setters = 0;
		return (patched_checks > 0);
	}

	old_val = buf[sig_enforce_offset];
	buf[sig_enforce_offset] = 0x00;
	fprintf(stderr, "[+] Cleared sig_enforce variable in .data: 0x%02X -> 0x00\n", old_val);

	target_page = (uint64_t)(sig_enforce_offset & ~0xfffULL);
	target_off = (uint32_t)(sig_enforce_offset & 0xfffULL);

	for (i = 0; i < limit; i += 4) {
		uint32_t inst0 = arm64_read_u32(buf, i);
		int adrp_rd;
		uint64_t page_addr;

		if (!arm64_decode_adrp(inst0, (uint64_t)i, &adrp_rd, &page_addr) || page_addr != target_page)
			continue;

		for (j = 1; j <= 4; j++) {
			uint32_t inst1;
			int str_rn;
			uint32_t str_off;
			int add_rd, add_rn;
			uint32_t add_imm;
			bool is_sub;

			if (i + j * 4 >= size) break;
			inst1 = arm64_read_u32(buf, i + j * 4);

			if ((inst1 & ARM64_STRB_IMM_MASK) == ARM64_STRB_IMM_VAL) {
				str_rn = (int)((inst1 >> 5) & 0x1fU);
				str_off = (inst1 >> 10) & 0xfffU;
				if (str_rn == adrp_rd && str_off == target_off) {
					arm64_write_u32(buf, i + j * 4, ARM64_NOP_OPCODE);
					fprintf(stderr, "[+] Neutralized runtime setter (STRB) @ 0x%08zX -> NOP\n", i + j * 4);
					neutralized_setters++;
				}
			}

			if (arm64_decode_add_sub_imm(inst1, &add_rd, &add_rn, &add_imm, &is_sub) &&
			    !is_sub && add_rn == adrp_rd && add_imm == target_off) {
				for (k = j + 1; k <= j + 3; k++) {
					uint32_t inst2;
					int s2_rn;
					uint32_t s2_off;
					if (i + k * 4 >= size) break;
					inst2 = arm64_read_u32(buf, i + k * 4);
					if ((inst2 & ARM64_STRB_IMM_MASK) == ARM64_STRB_IMM_VAL) {
						s2_rn = (int)((inst2 >> 5) & 0x1fU);
						s2_off = (inst2 >> 10) & 0xfffU;
						if (s2_rn == add_rd && s2_off == 0) {
							arm64_write_u32(buf, i + k * 4, ARM64_NOP_OPCODE);
							fprintf(stderr, "[+] Neutralized runtime setter (ADD+STRB) @ 0x%08zX -> NOP\n", i + k * 4);
							neutralized_setters++;
						}
					}
				}
			}
		}
	}

	for (i = 0; i + 20 <= size; i++) {
		if (memcmp(buf + i, "module.sig_enforce=1", 20) == 0) {
			buf[i + 19] = '0';
			fprintf(stderr, "[+] Patched 'module.sig_enforce=1' -> '0' @ 0x%08zX\n", i);
		}
	}

	if (out_checks) *out_checks = patched_checks;
	if (out_setters) *out_setters = neutralized_setters;
	return true;
}

static bool patch_cfi_buf(uint8_t *buf, size_t size, int *out_kcfi, int *out_legacy) {
	int kcfi_count = 0;
	int legacy_count = 0;
	size_t limit;
	size_t i, j, p;

	if (!buf || size < 32) return false;

	/* Phase 1: KCFI Detection & Neutralization (Linux 6.1, 6.6, Mainline) */
	limit = size - 16;
	for (i = 0; i < limit; i += 4) {
		uint32_t inst0 = arm64_read_u32(buf, i);
		if (inst0 == ARM64_CMP_W0_1) {
			uint32_t inst1 = arm64_read_u32(buf, i + 4);
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			uint32_t inst3 = arm64_read_u32(buf, i + 12);

			if (inst1 == ARM64_B_EQ_40 && inst2 == ARM64_CMP_W0_2) {
				if (inst3 == ARM64_B_TO_SKIP) {
					fprintf(stderr, "[*] KCFI cfi_handler @ 0x%08zX already neutralized\n", i);
					kcfi_count++;
				} else if (inst3 == ARM64_B_EQ_12) {
					arm64_write_u32(buf, i + 12, ARM64_B_TO_SKIP);
					fprintf(stderr, "[+] Neutralized KCFI die branch @ 0x%08zX: B.EQ -> B +32 (skip faulting instruction)\n", i + 12);
					kcfi_count++;
				}
			}
		}
	}

	/* Phase 2: Legacy Forward-Edge CFI Detection & Neutralization (Linux 4.19, 5.10) */
	for (j = 0; j < limit; j += 4) {
		uint32_t inst_brk = arm64_read_u32(buf, j + 12);
		if (inst_brk == ARM64_BRK_800 || inst_brk == ARM64_NOP_OPCODE) {
			uint32_t inst_bl = arm64_read_u32(buf, j + 8);
			uint32_t inst_mov = arm64_read_u32(buf, j + 4);

			if ((inst_bl & ARM64_BL_MASK) == ARM64_BL_VAL && inst_mov == ARM64_MOV_X1_X19) {
				bool is_cfi_context = false;
				for (p = 1; p <= 8; p++) {
					size_t pc_off = p * 4;
					if (j >= pc_off) {
						uint32_t prev = arm64_read_u32(buf, j - pc_off);
						int rd;
						uint64_t target_page;
						if (arm64_decode_adrp(prev, (uint64_t)(j - pc_off), &rd, &target_page)) {
							if (target_page < size) {
								size_t chk_end = (target_page + 4096 < size) ? (target_page + 4096) : size;
								size_t s;
								for (s = target_page; s + 11 <= chk_end; s++) {
									if (memcmp(buf + s, "CFI failure", 11) == 0 ||
									    memcmp(buf + s, "cfi_failure", 11) == 0) {
										is_cfi_context = true;
										break;
									}
								}
								if (is_cfi_context) break;
							}
						}
					}
				}

				if (is_cfi_context) {
					if (inst_brk == ARM64_NOP_OPCODE) {
						fprintf(stderr, "[*] Legacy CFI BUG trap @ 0x%08zX already neutralized\n", j + 12);
						legacy_count++;
					} else {
						arm64_write_u32(buf, j + 12, ARM64_NOP_OPCODE);
						fprintf(stderr, "[+] Neutralized Legacy Forward-Edge CFI BUG trap @ 0x%08zX: BRK #0x800 -> NOP\n", j + 12);
						legacy_count++;
					}
				}
			}
		}
	}

	if (out_kcfi) *out_kcfi = kcfi_count;
	if (out_legacy) *out_legacy = legacy_count;
	return (kcfi_count + legacy_count > 0);
}

static bool patch_selinux_permissive(uint8_t *buf, size_t size) {
	bool modified = false;
	size_t i;
	static const char p1_from[] = "androidboot.selinux=enforcing";
	static const char p1_to[]   = "androidboot.selinux=permissive";
	static const char p2_from[] = "selinux_enforcing=1";
	static const char p2_to[]   = "selinux_enforcing=0";

	for (i = 0; i + sizeof(p1_from) - 1 <= size; i++) {
		if (memcmp(buf + i, p1_from, sizeof(p1_from) - 1) == 0) {
			memcpy(buf + i, p1_to, sizeof(p1_to) - 1);
			buf[i + sizeof(p1_to) - 1] = '\0';
			fprintf(stderr, "[+] Patched 'androidboot.selinux=enforcing' -> 'permissive' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	for (i = 0; i + sizeof(p2_from) - 1 <= size; i++) {
		if (memcmp(buf + i, p2_from, sizeof(p2_from) - 1) == 0) {
			memcpy(buf + i, p2_to, sizeof(p2_to) - 1);
			fprintf(stderr, "[+] Patched 'selinux_enforcing=1' -> '0' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	return modified;
}

static bool patch_samsung_rkp(uint8_t *buf, size_t size) {
	bool modified = false;
	size_t i;
	for (i = 0; i + 8 <= size; i++) {
		if (memcmp(buf + i, "rkp_init", 8) == 0) {
			memcpy(buf + i, "rkp_skip", 8);
			fprintf(stderr, "[+] Patched Samsung RKP 'rkp_init' -> 'rkp_skip' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	return modified;
}

static void scan_kcfi_hashes(const uint8_t *buf, size_t size) {
	size_t count = 0;
	size_t i, step;

	if (!buf || size < 16) return;

	printf("====================================================\n");
	printf("  ARM64 KCFI Call Site & Type Hash Inspector\n");
	printf("====================================================\n");

	for (i = 0; i + 4 <= size; i += 4) {
		uint32_t inst = arm64_read_u32(buf, i);
		if ((inst & 0xffe0001fU) == 0xd4200000U) {
			uint32_t imm16 = (inst >> 5) & 0xffffU;
			if ((imm16 & 0x8000U) == 0x8000U) {
				uint8_t target_reg = (uint8_t)(imm16 & 0x1fU);
				uint8_t type_reg = (uint8_t)((imm16 >> 5) & 0x1fU);
				uint16_t low_imm = 0, high_imm = 0;
				bool has_low = false, has_high = false;
				size_t scan_steps = (i / 4 < 16) ? (i / 4) : 16;

				for (step = 1; step <= scan_steps; step++) {
					uint32_t pinst = arm64_read_u32(buf, i - step * 4);
					int mrd, mshift, mopc;
					uint16_t mimm;
					if (arm64_decode_mov_wide(pinst, &mrd, &mimm, &mshift, &mopc)) {
						if ((uint8_t)mrd == type_reg && (mopc == 2 || mopc == 3)) {
							if (mshift == 0) { low_imm = mimm; has_low = true; }
							else if (mshift == 16) { high_imm = mimm; has_high = true; }
						}
					}
					if (has_low && has_high) break;
				}

				if (has_low && has_high) {
					uint32_t hash = ((uint32_t)high_imm << 16) | (uint32_t)low_imm;
					printf("  [+] Call site @ 0x%08zX: KCFI hash 0x%08x (type=w%u, target=x%u)\n",
					       i, hash, type_reg, target_reg);
					count++;
				}
			}
		}
	}
	printf("====================================================\n");
	printf("[+] Total KCFI call sites discovered: %zu\n", count);
}

static void kernel_status_buf(const uint8_t *buf, size_t size, const char *name) {
	const char *banner = NULL;
	size_t i;
	int kcfi_count = 0;
	bool has_sig_check = false;
	bool sig_neutralized = false;
	bool selinux_permissive = false;
	bool rkp_patched = false;

	printf("====================================================\n");
	printf("  Kernel Security & Image Status: %s\n", name);
	printf("====================================================\n");
	printf("Kernel Payload Size: %zu bytes (%.2f MB)\n", size, (double)size / (1024.0 * 1024.0));

	if (size >= sizeof(struct arm64_image_header)) {
		const struct arm64_image_header *hdr = (const struct arm64_image_header *)buf;
		if (hdr->magic == ARM64_IMAGE_MAGIC) {
			printf("Architecture:        ARM64 (magic 'ARM\\x64')\n");
			printf("Text Offset:         0x%lx\n", (unsigned long)hdr->text_offset);
			printf("Image Size:          0x%lx (%lu bytes)\n", (unsigned long)hdr->image_size, (unsigned long)hdr->image_size);
			printf("Flags:               0x%lx\n", (unsigned long)hdr->flags);
		}
	}

	for (i = 0; i + 14 <= size; i++) {
		if (memcmp(buf + i, "Linux version ", 14) == 0) {
			banner = (const char *)(buf + i);
			break;
		}
	}
	if (banner) {
		char bstr[128];
		size_t blen = 0;
		while (blen < sizeof(bstr) - 1 && banner[blen] && banner[blen] != '\n' && banner[blen] != '\r') blen++;
		memcpy(bstr, banner, blen);
		bstr[blen] = '\0';
		printf("Kernel Banner:       %s\n", bstr);
	}

	for (i = 0; i + 16 <= size; i += 4) {
		uint32_t inst3 = arm64_read_u32(buf, i + 12);
		if ((inst3 & 0x7fffffe0U) == 0x12800fa0U) {
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			if ((inst2 & ARM64_CBZ_MASK) == ARM64_CBZ_VAL) {
				uint32_t inst1 = arm64_read_u32(buf, i + 4);
				has_sig_check = true;
				if ((inst1 & 0xffffffe0U) == ARM64_MOV_W0_WZR_OPCODE) {
					sig_neutralized = true;
				}
				break;
			}
		}
	}
	if (has_sig_check) {
		printf("Module Sig Enforce:  %s\n", sig_neutralized ? "NEUTRALIZED (MOV wzr)" : "ACTIVE (enforcing)");
	} else {
		printf("Module Sig Enforce:  NOT PRESENT / INACTIVE\n");
	}

	for (i = 0; i + 16 <= size; i += 4) {
		uint32_t inst0 = arm64_read_u32(buf, i);
		if (inst0 == ARM64_CMP_W0_1) {
			uint32_t inst1 = arm64_read_u32(buf, i + 4);
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			uint32_t inst3 = arm64_read_u32(buf, i + 12);
			if (inst1 == ARM64_B_EQ_40 && inst2 == ARM64_CMP_W0_2) {
				if (inst3 == ARM64_B_TO_SKIP) kcfi_count++;
			}
		}
	}
	printf("KCFI Skip Status:    %s\n", (kcfi_count > 0) ? "NEUTRALIZED (B to skip)" : "STANDARD (or N/A)");

	for (i = 0; i + 30 <= size; i++) {
		if (memcmp(buf + i, "androidboot.selinux=permissive", 30) == 0) {
			selinux_permissive = true;
			break;
		}
	}
	printf("SELinux Default:     %s\n", selinux_permissive ? "PERMISSIVE" : "ENFORCING");

	for (i = 0; i + 8 <= size; i++) {
		if (memcmp(buf + i, "rkp_skip", 8) == 0) {
			rkp_patched = true;
			break;
		}
	}
	if (rkp_patched) {
		printf("Samsung RKP:         NEUTRALIZED (rkp_skip)\n");
	}
	printf("====================================================\n");
}

static int magiskboot_kernel_op(const char *image, const char *action, int argc, char **argv) {
	boot_img_t boot;
	bool is_boot_img = false;
	uint8_t *k_data = NULL;
	size_t k_size = 0;
	uint8_t k_fmt = BOOT_FMT_UNKNOWN;
	char tmp_kdecomp[PATH_MAX];
	int kd_fd = -1;
	struct stat kd_st;
	bool modified = false;
	const char *outfile = NULL;
	char final_target[PATH_MAX];
	char tmp_out_boot[PATH_MAX + 64];

	bool do_sigenforce = false;
	bool do_cfi = false;
	bool do_permissive = false;
	bool do_rkp = false;
	const char *hex_from = NULL;
	const char *hex_to = NULL;
	bool do_hash_scan = false;

	if (!image || !action) return 1;

	/* Parse subcommand & options */
	if (strcmp(action, "status") == 0 || strcmp(action, "info") == 0) {
		/* read-only status */
	} else if (strcmp(action, "sigenforce") == 0 || strcmp(action, "patch-sigenforce") == 0 ||
	           strcmp(action, "nosig") == 0) {
		do_sigenforce = true;
		if (argc >= 4 && strcmp(argv[1], "patch-sigenforce") == 0) {
			if (argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
	} else if (strcmp(action, "cfi") == 0 || strcmp(action, "patch-cfi") == 0) {
		do_cfi = true;
		if (argc >= 4 && strcmp(argv[1], "patch-cfi") == 0) {
			if (argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
	} else if (strcmp(action, "de-enforce") == 0) {
		do_sigenforce = true;
		do_cfi = true;
		if (argc >= 4 && strcmp(argv[1], "de-enforce") == 0) {
			if (argc >= 4 && argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
	} else if (strcmp(action, "permissive") == 0) {
		do_permissive = true;
		if (argc >= 5 && argv[4][0] != '-') outfile = argv[4];
	} else if (strcmp(action, "disable-rkp") == 0 || strcmp(action, "rkp") == 0) {
		do_rkp = true;
		if (argc >= 5 && argv[4][0] != '-') outfile = argv[4];
	} else if (strcmp(action, "cfi-hash") == 0) {
		do_hash_scan = true;
	} else if (strcmp(action, "hexpatch") == 0) {
		if (argc < 6) {
			bb_error_msg("usage: magiskboot kernel <image> hexpatch <from_hex> <to_hex> [out]");
			return 1;
		}
		hex_from = argv[4];
		hex_to = argv[5];
		if (argc >= 7 && argv[6][0] != '-') outfile = argv[6];
	} else if (strcmp(action, "patch") == 0 || strcmp(action, "patch-all") == 0) {
		int i;
		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--sigenforce") == 0 || strcmp(argv[i], "--no-module-verify") == 0 ||
			    strcmp(argv[i], "--de-enforce") == 0) {
				do_sigenforce = true;
			} else if (strcmp(argv[i], "--cfi") == 0) {
				do_cfi = true;
			} else if (strcmp(argv[i], "--permissive") == 0) {
				do_permissive = true;
			} else if (strcmp(argv[i], "--disable-rkp") == 0 || strcmp(argv[i], "--rkp") == 0) {
				do_rkp = true;
			} else if (strcmp(argv[i], "--all") == 0) {
				do_sigenforce = true;
				do_cfi = true;
				do_permissive = true;
				do_rkp = true;
			} else if (strcmp(argv[i], "--hex") == 0) {
				if (i + 2 < argc) {
					hex_from = argv[i + 1];
					hex_to = argv[i + 2];
					i += 2;
				} else {
					bb_error_msg("--hex requires <from_hex> <to_hex>");
					return 1;
				}
			} else if (argv[i][0] != '-' && !outfile) {
				outfile = argv[i];
			}
		}
		if (strcmp(action, "patch-all") == 0) {
			do_sigenforce = true;
			do_cfi = true;
			do_permissive = true;
			do_rkp = true;
		}
	} else {
		bb_error_msg("unknown kernel action '%s' (supported: status, patch, sigenforce, cfi, de-enforce, permissive, rkp, hexpatch, cfi-hash)", action);
		return 1;
	}

	/* Try opening image as Android Boot Image */
	if (boot_img_parse(&boot, image)) {
		is_boot_img = true;
		if (!boot.kernel || boot.kernel_size == 0) {
			bb_error_msg("no kernel section found in boot image '%s'", image);
			boot_img_free(&boot);
			return 1;
		}
		k_fmt = boot.k_fmt;
		snprintf(tmp_kdecomp, sizeof(tmp_kdecomp), "/tmp/mb_kraw_%d.raw", (int)getpid());
		kd_fd = open(tmp_kdecomp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (kd_fd < 0) {
			bb_perror_msg("failed to create temporary kernel file");
			boot_img_free(&boot);
			return 1;
		}
		if (boot_fmt_compressed(k_fmt)) {
			bb_decompress_data(k_fmt, boot.kernel, boot.kernel_size, kd_fd);
		} else {
			full_write(kd_fd, boot.kernel, boot.kernel_size);
		}
	} else {
		int in_fd = open(image, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *in_map;

		if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size < 16) {
			bb_perror_msg("cannot open kernel image '%s'", image);
			if (in_fd >= 0) close(in_fd);
			return 1;
		}
		in_map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, in_fd, 0);
		close(in_fd);
		if (in_map == MAP_FAILED) {
			bb_perror_msg("mmap failed");
			return 1;
		}
		k_fmt = boot_check_fmt(in_map, st.st_size);

		snprintf(tmp_kdecomp, sizeof(tmp_kdecomp), "/tmp/mb_kraw_%d.raw", (int)getpid());
		kd_fd = open(tmp_kdecomp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (kd_fd < 0) {
			munmap(in_map, st.st_size);
			bb_perror_msg("failed to create temporary file");
			return 1;
		}
		if (boot_fmt_compressed(k_fmt)) {
			bb_decompress_data(k_fmt, in_map, st.st_size, kd_fd);
		} else {
			full_write(kd_fd, in_map, st.st_size);
		}
		munmap(in_map, st.st_size);
	}

	if (fstat(kd_fd, &kd_st) < 0 || kd_st.st_size <= 0) {
		bb_error_msg("failed to obtain kernel payload from '%s'", image);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 1;
	}
	k_size = (size_t)kd_st.st_size;

	k_data = mmap(NULL, k_size, PROT_READ | PROT_WRITE, MAP_SHARED, kd_fd, 0);
	if (k_data == MAP_FAILED) {
		bb_perror_msg("mmap failed for kernel payload");
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 1;
	}

	/* Read-only inspections */
	if (strcmp(action, "status") == 0 || strcmp(action, "info") == 0) {
		kernel_status_buf(k_data, k_size, image);
		munmap(k_data, k_size);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	if (do_hash_scan) {
		scan_kcfi_hashes(k_data, k_size);
		munmap(k_data, k_size);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	/* Apply patches */
	if (do_sigenforce) {
		int chks = 0, sets = 0;
		if (patch_sigenforce_buf(k_data, k_size, &chks, &sets)) {
			fprintf(stderr, "[+] Signature enforcement neutralized (checks: %d, setters: %d)\n", chks, sets);
			modified = true;
		}
	}

	if (do_cfi) {
		int kcfi = 0, leg = 0;
		if (patch_cfi_buf(k_data, k_size, &kcfi, &leg)) {
			fprintf(stderr, "[+] Control Flow Integrity neutralized (KCFI: %d, Legacy: %d)\n", kcfi, leg);
			modified = true;
		}
	}

	if (do_permissive) {
		if (patch_selinux_permissive(k_data, k_size)) {
			modified = true;
		}
	}

	if (do_rkp) {
		if (patch_samsung_rkp(k_data, k_size)) {
			modified = true;
		}
	}

	if (hex_from && hex_to) {
		if (hexpatch_buffer(k_data, k_size, hex_from, hex_to)) {
			modified = true;
		}
	}

	msync(k_data, k_size, MS_SYNC);
	munmap(k_data, k_size);
	close(kd_fd);

	if (!modified) {
		fprintf(stderr, "[!] No kernel modifications were required or matched\n");
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	/* Determine destination */
	if (outfile && outfile[0] != '\0') {
		strncpy(final_target, outfile, sizeof(final_target) - 1);
		final_target[sizeof(final_target) - 1] = '\0';
	} else {
		strncpy(final_target, image, sizeof(final_target) - 1);
		final_target[sizeof(final_target) - 1] = '\0';
	}

	snprintf(tmp_out_boot, sizeof(tmp_out_boot), "%s.tmp.%d", final_target, (int)getpid());

	if (is_boot_img) {
		char tmp_new_k[PATH_MAX];
		const char *k_payload_path = tmp_kdecomp;
		int out_fd;
		uint32_t page_sz;
		size_t hdr_pad;
		uint32_t kernel_sz = 0;
		uint32_t ramdisk_sz = 0;
		uint32_t second_sz, extra_sz, recov_dtbo_sz, dtb_sz, bootconfig_sz;

		if (boot_fmt_compressed(k_fmt)) {
			snprintf(tmp_new_k, sizeof(tmp_new_k), "/tmp/mb_kcomp_%d.comp", (int)getpid());
			if (compress_file_format(tmp_kdecomp, tmp_new_k, k_fmt) != 0) {
				bb_error_msg("failed to recompress kernel payload");
				unlink(tmp_kdecomp);
				boot_img_free(&boot);
				return 1;
			}
			k_payload_path = tmp_new_k;
		}

		out_fd = open(tmp_out_boot, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
		if (out_fd < 0) {
			bb_perror_msg("failed to create '%s'", tmp_out_boot);
			unlink(tmp_kdecomp);
			if (k_payload_path == tmp_new_k) unlink(tmp_new_k);
			boot_img_free(&boot);
			return 1;
		}

		page_sz = dyn_hdr_page_size(&boot.hdr);
		hdr_pad = align_to(boot.hdr.raw_sz, page_sz);
		lseek(out_fd, hdr_pad, SEEK_SET);

		/* 1. Write kernel section */
		copy_file_section(out_fd, k_payload_path, page_sz, &kernel_sz);
		if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
			size_t rem;
			full_write(out_fd, boot.kernel_dtb, boot.kernel_dtb_size);
			kernel_sz += (uint32_t)boot.kernel_dtb_size;
			rem = kernel_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}
		*dyn_hdr_kernel_size(&boot.hdr) = kernel_sz;
		unlink(tmp_kdecomp);
		if (k_payload_path == tmp_new_k) unlink(tmp_new_k);

		/* 2. Write ramdisk section */
		ramdisk_sz = (uint32_t)boot.ramdisk_size;
		if (boot.ramdisk && ramdisk_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.ramdisk, ramdisk_sz);
			rem = ramdisk_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}
		*dyn_hdr_ramdisk_size(&boot.hdr) = ramdisk_sz;

		/* 3. Write remaining sections from memory */
		second_sz = (uint32_t)boot.second_size;
		if (boot.second && second_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.second, second_sz);
			rem = second_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		extra_sz = (uint32_t)boot.extra_size;
		if (boot.extra && extra_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.extra, extra_sz);
			rem = extra_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		recov_dtbo_sz = (uint32_t)boot.recovery_dtbo_size;
		if (boot.recovery_dtbo && recov_dtbo_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.recovery_dtbo, recov_dtbo_sz);
			rem = recov_dtbo_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		dtb_sz = (uint32_t)boot.dtb_size;
		if (boot.dtb && dtb_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.dtb, dtb_sz);
			rem = dtb_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		bootconfig_sz = (uint32_t)boot.bootconfig_size;
		if (boot.bootconfig && bootconfig_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.bootconfig, bootconfig_sz);
			rem = bootconfig_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		/* 4. Recalculate SHA ID */
		dyn_hdr_recalc_id(&boot.hdr, out_fd, hdr_pad, page_sz,
		                  kernel_sz, ramdisk_sz, second_sz, extra_sz,
		                  recov_dtbo_sz, dtb_sz);

		/* 5. Handle AVB footer */
		if ((boot.flags & BOOT_FLAG_AVB) && boot.avb_footer) {
			uint64_t orig_vbmeta_off = __builtin_bswap64(boot.avb_footer->vbmeta_offset);
			uint64_t orig_vbmeta_sz = __builtin_bswap64(boot.avb_footer->vbmeta_size);
			if (orig_vbmeta_sz > 0 && orig_vbmeta_off + orig_vbmeta_sz <= boot.map_sz) {
				struct avb_footer new_footer;
				size_t rem;
				off_t aosp_img_size = lseek(out_fd, 0, SEEK_CUR);
				off_t new_vbmeta_off;

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
			}
		}

		/* 6. Write finalized header at offset 0 */
		lseek(out_fd, 0, SEEK_SET);
		full_write(out_fd, boot.hdr.raw, boot.hdr.raw_sz);
		if (hdr_pad > boot.hdr.raw_sz) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, hdr_pad - boot.hdr.raw_sz);
		}

		close(out_fd);
		boot_img_free(&boot);

		if (rename(tmp_out_boot, final_target) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}

		fprintf(stderr, "[+] Successfully updated boot image kernel -> '%s'\n", final_target);
		return 0;
	} else {
		/* Standalone kernel output */
		if (boot_fmt_compressed(k_fmt)) {
			if (compress_file_format(tmp_kdecomp, tmp_out_boot, k_fmt) != 0) {
				bb_error_msg("failed to recompress kernel payload");
				unlink(tmp_kdecomp);
				return 1;
			}
			unlink(tmp_kdecomp);
		} else {
			if (rename(tmp_kdecomp, tmp_out_boot) != 0) {
				bb_perror_msg("failed to create '%s'", tmp_out_boot);
				unlink(tmp_kdecomp);
				return 1;
			}
		}

		if (rename(tmp_out_boot, final_target) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}

		fprintf(stderr, "[+] Successfully updated kernel -> '%s'\n", final_target);
		return 0;
	}
}

/* =========================================================================
 * 11. Direct ELF Kernel Module Manipulation & Lifecycle Engine
 * ========================================================================= */

static bool elf_init_ctx(struct elf_ctx *ctx, uint8_t *buf, size_t size) {
	Elf64_Shdr *str_sh;
	if (!ctx || !buf || size < sizeof(Elf64_Ehdr)) return false;
	memset(ctx, 0, sizeof(*ctx));
	ctx->buf = buf;
	ctx->size = size;

	if (memcmp(buf, ELFMAG, SELFMAG) != 0) return false;

	if (buf[EI_CLASS] == ELFCLASS64) {
		ctx->is_64 = true;
	} else {
		return false;
	}

	ctx->is_le = (buf[EI_DATA] == ELFDATA2LSB);
	ctx->ehdr64 = (Elf64_Ehdr *)buf;
	ctx->machine = ctx->ehdr64->e_machine;

	if (ctx->ehdr64->e_shoff >= size ||
	    ctx->ehdr64->e_shoff + (size_t)ctx->ehdr64->e_shnum * sizeof(Elf64_Shdr) > size) {
		return false;
	}

	ctx->shdrs64 = (Elf64_Shdr *)(buf + ctx->ehdr64->e_shoff);
	ctx->shnum = ctx->ehdr64->e_shnum;

	if (ctx->ehdr64->e_shstrndx >= ctx->shnum) return false;

	str_sh = &ctx->shdrs64[ctx->ehdr64->e_shstrndx];
	if (str_sh->sh_offset >= size || str_sh->sh_offset + str_sh->sh_size > size) {
		return false;
	}

	ctx->shstrtab = (const char *)(buf + str_sh->sh_offset);
	return true;
}

static Elf64_Shdr *elf_find_shdr(struct elf_ctx *ctx, const char *name, size_t *out_idx) {
	size_t i;
	if (!ctx || !ctx->shdrs64 || !ctx->shstrtab || !name) return NULL;
	for (i = 0; i < ctx->shnum; i++) {
		const char *sec_name = ctx->shstrtab + ctx->shdrs64[i].sh_name;
		if (strcmp(sec_name, name) == 0) {
			if (out_idx) *out_idx = i;
			return &ctx->shdrs64[i];
		}
	}
	return NULL;
}

static bool elf_get_build_id(struct elf_ctx *ctx, char *out_hex, size_t max_len) {
	Elf64_Shdr *shdr;
	const uint8_t *note_buf;
	size_t offset = 0;

	if (!ctx || !out_hex || max_len < 3) return false;
	out_hex[0] = '\0';

	shdr = elf_find_shdr(ctx, ".note.gnu.build-id", NULL);
	if (!shdr || shdr->sh_type != SHT_NOTE || shdr->sh_offset + shdr->sh_size > ctx->size)
		return false;

	note_buf = ctx->buf + shdr->sh_offset;
	while (offset + 12 <= shdr->sh_size) {
		uint32_t namesz = *(const uint32_t *)(note_buf + offset);
		uint32_t descsz = *(const uint32_t *)(note_buf + offset + 4);
		uint32_t type   = *(const uint32_t *)(note_buf + offset + 8);
		size_t name_aligned = (namesz + 3) & ~3U;
		size_t desc_aligned = (descsz + 3) & ~3U;
		offset += 12;

		if (offset + name_aligned + descsz > shdr->sh_size) break;
		if (type == 3 && namesz == 4 && memcmp(note_buf + offset, "GNU", 3) == 0) {
			const uint8_t *desc = note_buf + offset + name_aligned;
			size_t hex_len = 0;
			size_t b;
			for (b = 0; b < descsz && hex_len + 3 <= max_len; b++) {
				hex_len += snprintf(out_hex + hex_len, max_len - hex_len, "%02x", desc[b]);
			}
			out_hex[hex_len] = '\0';
			return true;
		}
		offset += name_aligned + desc_aligned;
	}
	return false;
}

static void elf_list_modinfo(struct elf_ctx *ctx) {
	Elf64_Shdr *shdr = elf_find_shdr(ctx, ".modinfo", NULL);
	const char *buf;
	size_t len, pos = 0;
	int count = 0;

	if (!shdr || shdr->sh_offset + shdr->sh_size > ctx->size) {
		printf("  <none>\n");
		return;
	}

	buf = (const char *)(ctx->buf + shdr->sh_offset);
	len = shdr->sh_size;

	while (pos < len) {
		const char *entry = buf + pos;
		size_t elen = strnlen(entry, len - pos);
		if (elen > 0) {
			const char *eq = strchr(entry, '=');
			if (eq) {
				char key[128];
				size_t klen = (size_t)(eq - entry);
				if (klen >= sizeof(key)) klen = sizeof(key) - 1;
				memcpy(key, entry, klen);
				key[klen] = '\0';
				printf("  %-20s = %s\n", key, eq + 1);
			} else {
				printf("  %-20s\n", entry);
			}
			count++;
		}
		pos += elen + 1;
	}
	if (count == 0) printf("  <none>\n");
}

static bool elf_get_modinfo_entry(struct elf_ctx *ctx, const char *key, char *out_val, size_t max_len) {
	Elf64_Shdr *shdr = elf_find_shdr(ctx, ".modinfo", NULL);
	const char *buf;
	size_t len, pos = 0;
	size_t klen;

	if (!shdr || !key || !out_val || max_len == 0 || shdr->sh_offset + shdr->sh_size > ctx->size)
		return false;

	buf = (const char *)(ctx->buf + shdr->sh_offset);
	len = shdr->sh_size;
	klen = strlen(key);

	while (pos < len) {
		const char *entry = buf + pos;
		size_t elen = strnlen(entry, len - pos);
		if (elen > klen && strncmp(entry, key, klen) == 0 && entry[klen] == '=') {
			strncpy(out_val, entry + klen + 1, max_len - 1);
			out_val[max_len - 1] = '\0';
			return true;
		}
		pos += elen + 1;
	}
	return false;
}

static bool detect_running_vermagic(char *out_magic, size_t max_len) {
	struct utsname uts;
	bool has_smp = false, has_preempt = false;
	bool has_mod_unload = true, has_modversions = false;
	FILE *vf, *kf;
	char line[512];

	if (!out_magic || max_len < 16) return false;
	if (uname(&uts) != 0) return false;

	/* 1. Check /proc/version */
	vf = fopen("/proc/version", "r");
	if (vf) {
		if (fgets(line, sizeof(line), vf)) {
			has_smp = (strstr(line, "SMP") != NULL);
			has_preempt = (strstr(line, "PREEMPT") != NULL);
		}
		fclose(vf);
	}

	/* 2. Check /proc/kallsyms for modversions */
	kf = fopen("/proc/kallsyms", "r");
	if (kf) {
		while (fgets(line, sizeof(line), kf)) {
			if (strstr(line, "module_layout") != NULL) {
				has_modversions = true;
				break;
			}
		}
		fclose(kf);
	}

	snprintf(out_magic, max_len, "%s%s%s%s%s aarch64",
	         uts.release,
	         has_smp ? " SMP" : "",
	         has_preempt ? " preempt" : "",
	         has_mod_unload ? " mod_unload" : "",
	         has_modversions ? " modversions" : "");
	return true;
}

static bool extract_vermagic_from_kernel_buf(const uint8_t *buf, size_t size, char *out_magic, size_t max_len) {
	const char *needle = "aarch64";
	size_t nlen = 7;
	size_t i;

	if (!buf || size < 64 || !out_magic || max_len < 16) return false;

	for (i = 0; i + nlen <= size; i++) {
		if (memcmp(buf + i, needle, nlen) == 0) {
			size_t start = i;
			size_t end = i + nlen;
			while (start > 0 && buf[start - 1] >= 0x20 && buf[start - 1] <= 0x7E) {
				start--;
			}
			if (end - start >= 20) {
				const char *cand = (const char *)(buf + start);
				size_t clen = end - start;
				if (cand[0] >= '2' && cand[0] <= '9' && memchr(cand, '.', clen) != NULL) {
					if (memmem(cand, clen, " SMP ", 5) || memmem(cand, clen, " preempt ", 9) ||
					    memmem(cand, clen, " mod_unload ", 12)) {
						size_t cpy = (clen < max_len - 1) ? clen : (max_len - 1);
						memcpy(out_magic, cand, cpy);
						out_magic[cpy] = '\0';
						return true;
					}
				}
			}
		}
	}
	return false;
}

static bool extract_vermagic_from_path(const char *path, char *out_magic, size_t max_len) {
	boot_img_t boot;
	int fd;
	struct stat st;
	uint8_t *map;
	bool found = false;

	if (!path || !out_magic) return false;

	/* If boot image */
	if (boot_img_parse(&boot, path)) {
		if (boot.kernel && boot.kernel_size > 0) {
			if (boot_fmt_compressed(boot.k_fmt)) {
				char tmp_k[PATH_MAX];
				int kd_fd;
				snprintf(tmp_k, sizeof(tmp_k), "/tmp/mb_vmgk_%d.raw", (int)getpid());
				kd_fd = open(tmp_k, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
				if (kd_fd >= 0) {
					bb_decompress_data(boot.k_fmt, boot.kernel, boot.kernel_size, kd_fd);
					if (fstat(kd_fd, &st) == 0 && st.st_size > 64) {
						uint8_t *kmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, kd_fd, 0);
						if (kmap != MAP_FAILED) {
							found = extract_vermagic_from_kernel_buf(kmap, st.st_size, out_magic, max_len);
							munmap(kmap, st.st_size);
						}
					}
					close(kd_fd);
					unlink(tmp_k);
				}
			} else {
				found = extract_vermagic_from_kernel_buf(boot.kernel, boot.kernel_size, out_magic, max_len);
			}
		}
		boot_img_free(&boot);
		return found;
	}

	/* Loose kernel file */
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return false;
	if (fstat(fd, &st) < 0 || st.st_size < 64) { close(fd); return false; }
	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map != MAP_FAILED) {
		uint8_t fmt = boot_check_fmt(map, st.st_size);
		if (boot_fmt_compressed(fmt)) {
			char tmp_k[PATH_MAX];
			int kd_fd;
			struct stat kst;
			snprintf(tmp_k, sizeof(tmp_k), "/tmp/mb_vmgk_%d.raw", (int)getpid());
			kd_fd = open(tmp_k, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
			if (kd_fd >= 0) {
				bb_decompress_data(fmt, map, st.st_size, kd_fd);
				if (fstat(kd_fd, &kst) == 0 && kst.st_size > 64) {
					uint8_t *kmap = mmap(NULL, kst.st_size, PROT_READ, MAP_SHARED, kd_fd, 0);
					if (kmap != MAP_FAILED) {
						found = extract_vermagic_from_kernel_buf(kmap, kst.st_size, out_magic, max_len);
						munmap(kmap, kst.st_size);
					}
				}
				close(kd_fd);
				unlink(tmp_k);
			}
		} else {
			found = extract_vermagic_from_kernel_buf(map, st.st_size, out_magic, max_len);
		}
		munmap(map, st.st_size);
	}
	close(fd);
	return found;
}

static bool patch_vermagic_buf(struct elf_ctx *ctx, const char *new_vermagic) {
	Elf64_Shdr *shdr = elf_find_shdr(ctx, ".modinfo", NULL);
	char *buf;
	size_t len, pos = 0;
	size_t new_len, old_len;

	if (!shdr || !new_vermagic || shdr->sh_offset + shdr->sh_size > ctx->size)
		return false;

	buf = (char *)(ctx->buf + shdr->sh_offset);
	len = shdr->sh_size;
	new_len = strlen(new_vermagic);

	while (pos < len) {
		char *entry = buf + pos;
		size_t elen = strnlen(entry, len - pos);
		if (elen > 9 && strncmp(entry, "vermagic=", 9) == 0) {
			old_len = elen - 9;
			if (new_len <= old_len) {
				memcpy(entry + 9, new_vermagic, new_len);
				memset(entry + 9 + new_len, 0, old_len - new_len);
				fprintf(stderr, "[+] Patched vermagic in-place: \"%s\" (padded: %zu bytes)\n", new_vermagic, old_len - new_len);
				return true;
			} else {
				size_t extra = new_len - old_len;
				if (len - (pos + elen + 1) >= extra) {
					memmove(entry + 9 + new_len + 1, entry + 9 + old_len + 1, len - (pos + 9 + old_len + 1 + extra));
					memcpy(entry + 9, new_vermagic, new_len);
					entry[9 + new_len] = '\0';
					fprintf(stderr, "[+] Patched expanded vermagic in-place: \"%s\"\n", new_vermagic);
					return true;
				}
				memcpy(entry + 9, new_vermagic, old_len);
				fprintf(stderr, "[!] Warning: Truncated vermagic to fit in-place .modinfo slot: \"%s\"\n", entry + 9);
				return true;
			}
		}
		pos += elen + 1;
	}
	return false;
}

static int patch_module_relocations_and_cfi(struct elf_ctx *ctx) {
	int modified = 0;
	Elf64_Shdr *shdr;
	size_t i;

	/* 1. Neutralize .altinstructions and .rela.altinstructions */
	shdr = elf_find_shdr(ctx, ".altinstructions", NULL);
	if (shdr && shdr->sh_type != SHT_NOBITS) {
		shdr->sh_type = SHT_NOBITS;
		shdr->sh_size = 0;
		modified++;
		fprintf(stderr, "[+] Neutralized .altinstructions (converted to SHT_NOBITS)\n");
	}
	shdr = elf_find_shdr(ctx, ".rela.altinstructions", NULL);
	if (shdr && shdr->sh_type != SHT_NOBITS) {
		shdr->sh_type = SHT_NOBITS;
		shdr->sh_size = 0;
		modified++;
		fprintf(stderr, "[+] Neutralized .rela.altinstructions (converted to SHT_NOBITS)\n");
	}

	/* 2. Sanitize .gnu.linkonce.this_module */
	shdr = elf_find_shdr(ctx, ".gnu.linkonce.this_module", NULL);
	if (shdr && shdr->sh_size > 80 && shdr->sh_offset + shdr->sh_size <= ctx->size) {
		size_t zero_bytes = shdr->sh_size - 80;
		memset(ctx->buf + shdr->sh_offset + 80, 0, zero_bytes);
		modified++;
		fprintf(stderr, "[+] Sanitized .gnu.linkonce.this_module: preserved 80-byte header, zeroed %zu trailing bytes\n", zero_bytes);
	}

	/* 3. Neutralize synthesized Cross-DSO __cfi_check stub */
	shdr = elf_find_shdr(ctx, ".symtab", NULL);
	if (shdr && shdr->sh_type == SHT_SYMTAB && shdr->sh_offset + shdr->sh_size <= ctx->size) {
		Elf64_Shdr *strtab_sh = &ctx->shdrs64[shdr->sh_link];
		if (shdr->sh_link < ctx->shnum && strtab_sh->sh_offset + strtab_sh->sh_size <= ctx->size) {
			const char *strtab = (const char *)(ctx->buf + strtab_sh->sh_offset);
			Elf64_Sym *syms = (Elf64_Sym *)(ctx->buf + shdr->sh_offset);
			size_t nsyms = shdr->sh_size / sizeof(Elf64_Sym);
			for (i = 0; i < nsyms; i++) {
				if (syms[i].st_name && strcmp(strtab + syms[i].st_name, "__cfi_check") == 0) {
					if (syms[i].st_shndx < ctx->shnum) {
						Elf64_Shdr *t_sh = &ctx->shdrs64[syms[i].st_shndx];
						if (t_sh->sh_offset + syms[i].st_value + 4 <= ctx->size) {
							uint32_t *p_insn = (uint32_t *)(ctx->buf + t_sh->sh_offset + syms[i].st_value);
							if (*p_insn != ARM64_RET_OPCODE) {
								*p_insn = ARM64_RET_OPCODE;
								modified++;
								fprintf(stderr, "[+] Neutralized synthesized __cfi_check stub -> RET (0x%08X)\n", ARM64_RET_OPCODE);
							}
						}
					}
					break;
				}
			}
		}
	}

	return modified;
}

static int strip_module_sections(struct elf_ctx *ctx) {
	int stripped = 0;
	size_t i;
	for (i = 1; i < ctx->shnum; i++) {
		const char *name = ctx->shstrtab + ctx->shdrs64[i].sh_name;
		bool do_strip = false;
		if (strncmp(name, ".debug_", 7) == 0 ||
		    strcmp(name, ".comment") == 0 ||
		    strcmp(name, ".note.GNU-stack") == 0) {
			do_strip = true;
		}
		if (do_strip && ctx->shdrs64[i].sh_type != SHT_NOBITS && ctx->shdrs64[i].sh_size > 0) {
			ctx->shdrs64[i].sh_type = SHT_NOBITS;
			ctx->shdrs64[i].sh_size = 0;
			stripped++;
		}
	}
	return stripped;
}

static int audit_module_symbols(struct elf_ctx *ctx, const char *kallsyms_file) {
	Elf64_Shdr *shdr = elf_find_shdr(ctx, ".symtab", NULL);
	const char *strtab;
	Elf64_Sym *syms;
	size_t nsyms, i, idx;
	size_t total_undef = 0, missing_strong = 0, missing_weak = 0, resolved_cnt = 0;
	FILE *kf;
	char line[512];
	char **undef_names = NULL;
	bool *is_weak_arr = NULL;
	bool *is_res_arr = NULL;

	if (!shdr || shdr->sh_type != SHT_SYMTAB || shdr->sh_offset + shdr->sh_size > ctx->size) {
		fprintf(stderr, "[-] No symbol table found in module\n");
		return 1;
	}

	strtab = (const char *)(ctx->buf + ctx->shdrs64[shdr->sh_link].sh_offset);
	syms = (Elf64_Sym *)(ctx->buf + shdr->sh_offset);
	nsyms = shdr->sh_size / sizeof(Elf64_Sym);

	for (i = 1; i < nsyms; i++) {
		if (syms[i].st_shndx == SHN_UNDEF && syms[i].st_name) {
			const char *sname = strtab + syms[i].st_name;
			if (sname[0] && ELF64_ST_BIND(syms[i].st_info) != STB_LOCAL) {
				total_undef++;
			}
		}
	}

	if (total_undef == 0) {
		printf("[+] Pre-flight audit: Zero unresolved external dependencies (self-contained module).\n");
		return 0;
	}

	undef_names = xzalloc(total_undef * sizeof(char *));
	is_weak_arr = xzalloc(total_undef * sizeof(bool));
	is_res_arr = xzalloc(total_undef * sizeof(bool));

	idx = 0;
	for (i = 1; i < nsyms; i++) {
		if (syms[i].st_shndx == SHN_UNDEF && syms[i].st_name) {
			const char *sname = strtab + syms[i].st_name;
			if (sname[0] && ELF64_ST_BIND(syms[i].st_info) != STB_LOCAL) {
				undef_names[idx] = xstrdup(sname);
				is_weak_arr[idx] = (ELF64_ST_BIND(syms[i].st_info) == STB_WEAK);
				is_res_arr[idx] = false;
				idx++;
			}
		}
	}

	printf("[*] Pre-flight audit: Checking %zu external symbol(s) against %s...\n",
	       total_undef, kallsyms_file ? kallsyms_file : "/proc/kallsyms");

	kf = fopen(kallsyms_file ? kallsyms_file : "/proc/kallsyms", "r");
	if (!kf) {
		fprintf(stderr, "[!] Warning: Cannot open %s for live verification.\n", kallsyms_file ? kallsyms_file : "/proc/kallsyms");
		for (i = 0; i < total_undef; i++) {
			printf("  [%s] %s\n", is_weak_arr[i] ? "WEAK" : "GLOBAL", undef_names[i]);
			free(undef_names[i]);
		}
		free(undef_names);
		free(is_weak_arr);
		free(is_res_arr);
		return 0;
	}

	while (fgets(line, sizeof(line), kf)) {
		char *p = strrchr(line, ' ');
		size_t slen;
		if (!p) p = strrchr(line, '\t');
		if (!p) continue;
		p++;
		slen = strlen(p);
		while (slen > 0 && (p[slen - 1] == '\n' || p[slen - 1] == '\r')) p[--slen] = '\0';

		for (i = 0; i < total_undef; i++) {
			if (!is_res_arr[i] && strcmp(undef_names[i], p) == 0) {
				is_res_arr[i] = true;
			}
		}
	}
	fclose(kf);

	for (i = 0; i < total_undef; i++) {
		if (is_res_arr[i]) {
			resolved_cnt++;
		} else if (is_weak_arr[i]) {
			missing_weak++;
			printf("[?] Unresolved WEAK symbol  : %s\n", undef_names[i]);
		} else {
			missing_strong++;
			fprintf(stderr, "[-] UNRESOLVED GLOBAL symbol: %s\n", undef_names[i]);
		}
		free(undef_names[i]);
	}
	free(undef_names);
	free(is_weak_arr);
	free(is_res_arr);

	printf("[*] Audit Summary: %zu resolved, %zu missing strong, %zu missing weak\n",
	       resolved_cnt, missing_strong, missing_weak);
	if (missing_strong > 0) {
		fprintf(stderr, "[-] PRE-FLIGHT AUDIT FAILED: %zu required kernel symbol(s) missing!\n", missing_strong);
		return 2;
	}

	printf("[+] PRE-FLIGHT AUDIT PASSED: All required external kernel symbols resolved.\n");
	return 0;
}

static void log_kmsg_msg(const char *msg) {
	int fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (fd >= 0) {
		full_write(fd, msg, strlen(msg));
		close(fd);
	}
}

static int module_info_file(const char *file) {
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	uint8_t *map;
	struct elf_ctx ctx;
	char build_id[128];

	if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < sizeof(Elf64_Ehdr)) {
		bb_perror_msg("cannot open module file '%s'", file);
		if (fd >= 0) close(fd);
		return 1;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		bb_perror_msg("failed to mmap '%s'", file);
		return 1;
	}

	if (!elf_init_ctx(&ctx, map, st.st_size)) {
		bb_error_msg("'%s' is not a valid 64-bit ELF kernel module", file);
		munmap(map, st.st_size);
		return 1;
	}

	printf("======================================================================\n");
	printf("  Kernel Module Inspection: %s\n", file);
	printf("======================================================================\n");
	printf("[*] Architecture    : %s (0x%04x)\n",
	       (ctx.machine == EM_AARCH64) ? "AArch64 (ARM64)" : (ctx.machine == EM_X86_64 ? "x86_64" : "Other"),
	       ctx.machine);
	printf("[*] ELF Class       : %s\n", ctx.is_64 ? "64-bit" : "32-bit");
	printf("[*] Data Encoding   : %s\n", ctx.is_le ? "2's complement, little endian" : "big endian");
	printf("[*] Section Count   : %u\n", (unsigned int)ctx.shnum);

	if (elf_get_build_id(&ctx, build_id, sizeof(build_id))) {
		printf("[*] GNU Build-ID    : %s\n", build_id);
	} else {
		printf("[*] GNU Build-ID    : <none / stripped>\n");
	}

	printf("\n[*] Module Info (.modinfo):\n");
	elf_list_modinfo(&ctx);
	printf("======================================================================\n");

	munmap(map, st.st_size);
	return 0;
}

static int module_check_file(const char *file) {
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	uint8_t *map;
	struct elf_ctx ctx;
	char mod_ver[256] = {0};
	char run_ver[256] = {0};
	bool found;

	if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < sizeof(Elf64_Ehdr)) {
		bb_perror_msg("cannot open module file '%s'", file);
		if (fd >= 0) close(fd);
		return 1;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		bb_perror_msg("failed to mmap '%s'", file);
		return 1;
	}

	if (!elf_init_ctx(&ctx, map, st.st_size)) {
		bb_error_msg("'%s' is not a valid 64-bit ELF kernel module", file);
		munmap(map, st.st_size);
		return 1;
	}

	found = elf_get_modinfo_entry(&ctx, "vermagic", mod_ver, sizeof(mod_ver));
	detect_running_vermagic(run_ver, sizeof(run_ver));

	printf("======================================================================\n");
	printf("  Module Path    : %s\n", file);
	printf("  Module Vermagic: %s\n", found ? mod_ver : "(not found)");
	printf("  Running Kernel : %s\n", run_ver);
	printf("======================================================================\n");

	if (found && strcmp(mod_ver, run_ver) == 0) {
		printf("[✓] Status: 100%% EXACT MATCH — loads natively via insmod/modprobe.\n");
		munmap(map, st.st_size);
		return 0;
	} else {
		printf("[!] Status: MISMATCH — requires vermagic alignment / patch-vermagic.\n");
		munmap(map, st.st_size);
		return 1;
	}
}

static int module_strip_file(const char *in_file, const char *out_file) {
	int in_fd = open(in_file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	uint8_t *buf;
	struct elf_ctx ctx;
	int stripped;
	int out_fd;
	const char *dest;

	if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size < sizeof(Elf64_Ehdr)) {
		bb_perror_msg("cannot open module '%s'", in_file);
		if (in_fd >= 0) close(in_fd);
		return 1;
	}

	buf = xmalloc(st.st_size);
	if (full_read(in_fd, buf, st.st_size) != st.st_size) {
		bb_perror_msg("failed to read '%s'", in_file);
		close(in_fd);
		free(buf);
		return 1;
	}
	close(in_fd);

	if (!elf_init_ctx(&ctx, buf, st.st_size)) {
		bb_error_msg("'%s' is not a valid 64-bit ELF kernel module", in_file);
		free(buf);
		return 1;
	}

	stripped = strip_module_sections(&ctx);
	fprintf(stderr, "[+] Neutralized %d unneeded/debug section(s)\n", stripped);

	dest = (out_file && out_file[0]) ? out_file : in_file;
	out_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) {
		bb_perror_msg("cannot write '%s'", dest);
		free(buf);
		return 1;
	}
	full_write(out_fd, buf, st.st_size);
	close(out_fd);
	free(buf);
	fprintf(stderr, "[✓] SUCCESS: Module '%s' stripped.\n", dest);
	return 0;
}

static int module_patch_file(const char *in_file, const char *out_file, const char *custom_vermagic,
                            const char *boot_path, bool do_strip) {
	int in_fd = open(in_file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	uint8_t *buf;
	struct elf_ctx ctx;
	char target_magic[256] = {0};
	char old_magic[256] = {0};
	int out_fd;
	int stripped;
	const char *dest;

	if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size < sizeof(Elf64_Ehdr)) {
		bb_perror_msg("cannot open module '%s'", in_file);
		if (in_fd >= 0) close(in_fd);
		return 1;
	}

	buf = xmalloc(st.st_size + 16384);
	if (full_read(in_fd, buf, st.st_size) != st.st_size) {
		bb_perror_msg("failed to read '%s'", in_file);
		close(in_fd);
		free(buf);
		return 1;
	}
	close(in_fd);

	if (!elf_init_ctx(&ctx, buf, st.st_size)) {
		bb_error_msg("'%s' is not a valid 64-bit ELF kernel module", in_file);
		free(buf);
		return 1;
	}

	if (custom_vermagic && custom_vermagic[0] != '\0') {
		strncpy(target_magic, custom_vermagic, sizeof(target_magic) - 1);
	} else if (boot_path) {
		if (!extract_vermagic_from_path(boot_path, target_magic, sizeof(target_magic))) {
			bb_error_msg("could not extract vermagic from boot/kernel '%s'", boot_path);
			free(buf);
			return 1;
		}
		fprintf(stderr, "[+] Autodetected vermagic from %s: \"%s\"\n", boot_path, target_magic);
	} else {
		if (!detect_running_vermagic(target_magic, sizeof(target_magic))) {
			bb_error_msg("cannot determine target vermagic");
			free(buf);
			return 1;
		}
	}

	if (elf_get_modinfo_entry(&ctx, "vermagic", old_magic, sizeof(old_magic))) {
		fprintf(stderr, "[*] Original vermagic : \"%s\" (len=%zu)\n", old_magic, strlen(old_magic));
	}
	fprintf(stderr, "[*] Target vermagic   : \"%s\" (len=%zu)\n", target_magic, strlen(target_magic));

	if (do_strip) {
		stripped = strip_module_sections(&ctx);
		fprintf(stderr, "[+] Neutralized / stripped %d unneeded/debug section(s)\n", stripped);
	}

	patch_vermagic_buf(&ctx, target_magic);
	patch_module_relocations_and_cfi(&ctx);

	dest = (out_file && out_file[0]) ? out_file : in_file;
	out_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) {
		bb_perror_msg("cannot write '%s'", dest);
		free(buf);
		return 1;
	}
	full_write(out_fd, buf, st.st_size);
	close(out_fd);
	free(buf);

	fprintf(stderr, "[✓] SUCCESS: Module '%s' vermagic dynamically patched to \"%s\"!\n", dest, target_magic);
	return 0;
}

static int module_load_file(const char *file, const char *args) {
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	struct stat st;
	uint8_t *buf;
	struct elf_ctx ctx;
	char target_magic[256];
	long ret;
	char msg[512];

	if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < sizeof(Elf64_Ehdr)) {
		bb_perror_msg("cannot open module '%s'", file);
		if (fd >= 0) close(fd);
		return 1;
	}

	buf = xmalloc(st.st_size + 16384);
	if (full_read(fd, buf, st.st_size) != st.st_size) {
		bb_perror_msg("failed to read '%s'", file);
		close(fd);
		free(buf);
		return 1;
	}
	close(fd);

	detect_running_vermagic(target_magic, sizeof(target_magic));
	if (elf_init_ctx(&ctx, buf, st.st_size)) {
		patch_vermagic_buf(&ctx, target_magic);
		patch_module_relocations_and_cfi(&ctx);
	}

	fprintf(stderr, "[+] Calling SYS_init_module(size=%zu, args=\"%s\")...\n", (size_t)st.st_size, args ? args : "");
	ret = syscall(SYS_init_module, buf, st.st_size, args ? args : "");
	if (ret == 0) {
		fprintf(stderr, "[✓] SUCCESS: Module '%s' loaded into kernel!\n", file);
		snprintf(msg, sizeof(msg), "<6>magiskboot: Module '%s' loaded successfully with vermagic '%s'\n", file, target_magic);
		log_kmsg_msg(msg);
		free(buf);
		return 0;
	}

	if (errno == EEXIST) {
		fprintf(stderr, "[!] Module already resident in kernel.\n");
		free(buf);
		return 0;
	}

	if (errno == ENOKEY || errno == EKEYREJECTED) {
		fprintf(stderr, "[-] ERROR: Kernel module signature enforcement is ACTIVE (CONFIG_MODULE_SIG_FORCE=y).\n");
		fprintf(stderr, "[-] Run 'magiskboot de-enforce <boot.img>' to neutralize kernel signature enforcement.\n");
	} else {
		bb_perror_msg("init_module failed");
	}
	free(buf);
	return 1;
}

static int module_finit_file(const char *file, const char *args) {
	int fd = open(file, O_RDONLY | O_CLOEXEC);
	long ret;
	char msg[256];

	if (fd < 0) {
		bb_perror_msg("cannot open module '%s'", file);
		return 1;
	}

	fprintf(stderr, "[+] Calling SYS_finit_module(fd=%d, args=\"%s\")...\n", fd, args ? args : "");
	ret = syscall(SYS_finit_module, fd, args ? args : "", 0);
	close(fd);

	if (ret == 0) {
		fprintf(stderr, "[✓] SUCCESS: Module '%s' loaded via SYS_finit_module!\n", file);
		snprintf(msg, sizeof(msg), "<6>magiskboot: Module '%s' loaded via sys_finit_module\n", file);
		log_kmsg_msg(msg);
		return 0;
	}

	if (errno == EEXIST) {
		fprintf(stderr, "[!] Module already resident in kernel.\n");
		return 0;
	}

	fprintf(stderr, "[!] sys_finit_module returned %ld (errno=%d). Falling back to in-memory vermagic alignment...\n",
	        ret, errno);
	return module_load_file(file, args);
}

static int module_unload_name(const char *name) {
	const char *n = (name && name[0]) ? name : "kroot";
	long ret;
	char msg[256];

	fprintf(stderr, "[+] Unloading module '%s'...\n", n);
	ret = syscall(SYS_delete_module, n, O_NONBLOCK);
	if (ret != 0 && strcmp(n, "kroot") == 0) {
		ret = syscall(SYS_delete_module, "compat_modern_kernel", O_NONBLOCK);
	}

	if (ret == 0) {
		fprintf(stderr, "[✓] SUCCESS: Module '%s' unloaded.\n", n);
		snprintf(msg, sizeof(msg), "<6>magiskboot: Module '%s' unloaded\n", n);
		log_kmsg_msg(msg);
		return 0;
	}

	bb_perror_msg("delete_module failed");
	return 1;
}

static int magiskboot_patch_vermagic_op(int argc, char **argv) {
	const char *filepath = NULL;
	char target_magic[256] = {0};
	const char *boot_img_path = NULL;
	const char *outfile = NULL;
	bool mode_strip = false;
	bool mode_info = false;
	bool mode_audit = false;
	int i;

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--cfi") == 0 || strcmp(argv[i], "--non-cfi") == 0) {
			/* handled portably */
		} else if (strcmp(argv[i], "--boot") == 0 && i + 1 < argc) {
			boot_img_path = argv[++i];
		} else if (strcmp(argv[i], "--info") == 0 || strcmp(argv[i], "-i") == 0) {
			mode_info = true;
		} else if (strcmp(argv[i], "--audit") == 0 || strcmp(argv[i], "-a") == 0) {
			mode_audit = true;
		} else if (strcmp(argv[i], "--strip") == 0 || strcmp(argv[i], "-s") == 0) {
			mode_strip = true;
		} else if (argv[i][0] != '-') {
			if (!filepath) {
				filepath = argv[i];
			} else if (!boot_img_path && target_magic[0] == '\0' && !strstr(argv[i], ".ko")) {
				strncpy(target_magic, argv[i], sizeof(target_magic) - 1);
			} else if (!outfile) {
				outfile = argv[i];
			}
		}
	}

	if (!filepath) {
		bb_error_msg("usage: magiskboot patch-vermagic <module.ko> [target_vermagic] [out.ko] [options]");
		return 1;
	}

	if (mode_info) return module_info_file(filepath);
	if (mode_audit) {
		int fd = open(filepath, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *map;
		struct elf_ctx ctx;
		int res;
		if (fd < 0 || fstat(fd, &st) < 0) { bb_perror_msg("cannot open '%s'", filepath); if (fd >= 0) close(fd); return 1; }
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;
		if (!elf_init_ctx(&ctx, map, st.st_size)) { munmap(map, st.st_size); return 1; }
		res = audit_module_symbols(&ctx, NULL);
		munmap(map, st.st_size);
		return res;
	}
	if (mode_strip && target_magic[0] == '\0' && !boot_img_path) {
		return module_strip_file(filepath, outfile);
	}

	return module_patch_file(filepath, outfile, (target_magic[0] != '\0') ? target_magic : NULL, boot_img_path, mode_strip);
}

static int magiskboot_module_op(int argc, char **argv) {
	const char *action;
	const char *file = NULL;
	const char *arg1 = NULL;
	const char *arg2 = NULL;
	int idx = 2;

	if (argc < 3) {
		bb_show_usage();
	}

	action = argv[idx++];
	if (idx < argc) file = argv[idx++];
	if (idx < argc) arg1 = argv[idx++];
	if (idx < argc) arg2 = argv[idx++];

	if (strcmp(action, "info") == 0) {
		if (!file) bb_show_usage();
		return module_info_file(file);
	}
	if (strcmp(action, "check") == 0) {
		if (!file) bb_show_usage();
		return module_check_file(file);
	}
	if (strcmp(action, "audit") == 0) {
		int fd;
		struct stat st;
		uint8_t *map;
		struct elf_ctx ctx;
		int res;
		if (!file) bb_show_usage();
		fd = open(file, O_RDONLY | O_CLOEXEC);
		if (fd < 0 || fstat(fd, &st) < 0) { bb_perror_msg("cannot open '%s'", file); if (fd >= 0) close(fd); return 1; }
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;
		if (!elf_init_ctx(&ctx, map, st.st_size)) { munmap(map, st.st_size); return 1; }
		res = audit_module_symbols(&ctx, arg1);
		munmap(map, st.st_size);
		return res;
	}
	if (strcmp(action, "strip") == 0) {
		if (!file) bb_show_usage();
		return module_strip_file(file, arg1);
	}
	if (strcmp(action, "patch") == 0 || strcmp(action, "patch-vermagic") == 0) {
		if (!file) bb_show_usage();
		return module_patch_file(file, arg2, arg1, NULL, false);
	}
	if (strcmp(action, "load") == 0) {
		if (!file) file = "/data/adb/modules/kcompat/compat_modern_kernel.ko";
		return module_load_file(file, arg1 ? arg1 : "");
	}
	if (strcmp(action, "finit") == 0) {
		if (!file) file = "/data/adb/modules/kcompat/compat_modern_kernel.ko";
		return module_finit_file(file, arg1 ? arg1 : "");
	}
	if (strcmp(action, "unload") == 0) {
		return module_unload_name(file ? file : "kroot");
	}

	bb_error_msg("unknown module action '%s' (supported: info, check, audit, strip, patch, load, finit, unload)", action);
	return 1;
}

/* =========================================================================
 * 12. Universal Recovery Flashable ZIP Packaging & ZIP Archive Engine
 * ========================================================================= */

static uint32_t zip_calc_crc32(const void *buf, size_t len) {
	if (!global_crc32_table) {
		global_crc32_new_table_le();
	}
	return crc32_block_endian0(0xffffffff, buf, len, global_crc32_table) ^ 0xffffffff;
}

static bool zip_compress_deflate(const void *in_buf, size_t in_sz, void **out_buf, size_t *out_sz, uint32_t *out_crc) {
	char tmp_in[PATH_MAX], tmp_out[PATH_MAX];
	int ifd, ofd, status;
	pid_t pid;
	struct stat st;
	uint8_t *gz_map;
	size_t gz_sz, hdr_len, payload_len;
	uint8_t flg;
	uint32_t crc;
	void *def_buf;

	if (in_sz < 64) return false;

	snprintf(tmp_in, sizeof(tmp_in), "/tmp/mb_zin_%d_%d.tmp", (int)getpid(), (int)rand());
	snprintf(tmp_out, sizeof(tmp_out), "/tmp/mb_zout_%d_%d.gz", (int)getpid(), (int)rand());

	ifd = open(tmp_in, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (ifd < 0) return false;
	if (full_write(ifd, in_buf, in_sz) != in_sz) {
		close(ifd);
		unlink(tmp_in);
		return false;
	}
	close(ifd);

	ofd = open(tmp_out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (ofd < 0) {
		unlink(tmp_in);
		return false;
	}

	pid = fork();
	if (pid == 0) {
		dup2(ofd, STDOUT_FILENO);
		close(ofd);
		execlp("gzip", "gzip", "-9c", tmp_in, (char *)NULL);
		_exit(127);
	}
	close(ofd);

	if (pid < 0) {
		unlink(tmp_in);
		unlink(tmp_out);
		return false;
	}
	waitpid(pid, &status, 0);
	unlink(tmp_in);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		unlink(tmp_out);
		return false;
	}

	ofd = open(tmp_out, O_RDONLY | O_CLOEXEC);
	if (ofd < 0 || fstat(ofd, &st) < 0 || st.st_size < 18) {
		if (ofd >= 0) close(ofd);
		unlink(tmp_out);
		return false;
	}

	gz_sz = st.st_size;
	gz_map = xmalloc(gz_sz);
	if (full_read(ofd, gz_map, gz_sz) != gz_sz) {
		close(ofd);
		free(gz_map);
		unlink(tmp_out);
		return false;
	}
	close(ofd);
	unlink(tmp_out);

	if (gz_map[0] != 0x1f || gz_map[1] != 0x8b || gz_map[2] != 0x08) {
		free(gz_map);
		return false;
	}

	hdr_len = 10;
	flg = gz_map[3];
	if (flg & 0x04) {
		uint16_t xlen;
		if (hdr_len + 2 > gz_sz) { free(gz_map); return false; }
		xlen = (uint16_t)gz_map[hdr_len] | ((uint16_t)gz_map[hdr_len + 1] << 8);
		hdr_len += 2 + xlen;
	}
	if (flg & 0x08) {
		while (hdr_len < gz_sz && gz_map[hdr_len] != '\0') hdr_len++;
		hdr_len++;
	}
	if (flg & 0x10) {
		while (hdr_len < gz_sz && gz_map[hdr_len] != '\0') hdr_len++;
		hdr_len++;
	}
	if (flg & 0x02) {
		hdr_len += 2;
	}

	if (hdr_len + 8 >= gz_sz) {
		free(gz_map);
		return false;
	}

	payload_len = gz_sz - hdr_len - 8;
	if (payload_len >= in_sz) {
		free(gz_map);
		return false;
	}

	crc = (uint32_t)gz_map[gz_sz - 8] |
	      ((uint32_t)gz_map[gz_sz - 7] << 8) |
	      ((uint32_t)gz_map[gz_sz - 6] << 16) |
	      ((uint32_t)gz_map[gz_sz - 5] << 24);

	def_buf = xmalloc(payload_len);
	memcpy(def_buf, gz_map + hdr_len, payload_len);
	free(gz_map);

	*out_buf = def_buf;
	*out_sz = payload_len;
	*out_crc = crc;
	return true;
}

static bool zip_writer_init(struct zip_writer *zw, const char *out_path) {
	if (!zw || !out_path) return false;
	memset(zw, 0, sizeof(*zw));
	zw->fp = fopen(out_path, "wb");
	if (!zw->fp) {
		bb_perror_msg("cannot create '%s'", out_path);
		return false;
	}
	zw->capacity = 64;
	zw->entries = xzalloc(zw->capacity * sizeof(struct zip_entry_info));
	zw->num_entries = 0;
	zw->current_offset = 0;
	return true;
}

static bool zip_writer_add_mem(struct zip_writer *zw, const char *zip_name, const void *data, size_t data_len, mode_t mode) {
	struct zip_local_hdr lhdr;
	size_t name_len;
	uint16_t method = 0;
	void *comp_buf = NULL;
	size_t comp_sz = data_len;
	uint32_t crc;
	bool can_deflate = true;
	const char *ext;

	if (!zw || !zw->fp || !zip_name) return false;

	name_len = strlen(zip_name);
	ext = strrchr(zip_name, '.');
	if (ext && (strcasecmp(ext, ".apk") == 0 ||
	            strcasecmp(ext, ".zip") == 0 ||
	            strcasecmp(ext, ".gz") == 0 ||
	            strcasecmp(ext, ".xz") == 0 ||
	            strcasecmp(ext, ".bz2") == 0 ||
	            strcasecmp(ext, ".lz4") == 0)) {
		can_deflate = false;
	}

	if (data_len == 0 || (name_len > 0 && zip_name[name_len - 1] == '/')) {
		can_deflate = false;
	}

	if (can_deflate && zip_compress_deflate(data, data_len, &comp_buf, &comp_sz, &crc)) {
		method = 8;
	} else {
		method = 0;
		comp_sz = data_len;
		comp_buf = (void *)data;
		crc = zip_calc_crc32(data, data_len);
	}

	memset(&lhdr, 0, sizeof(lhdr));
	lhdr.signature = SWAP_LE32(ZIP_LOCAL_HDR_MAGIC);
	lhdr.version_needed = SWAP_LE16(20);
	lhdr.flags = 0;
	lhdr.compression = SWAP_LE16(method);
	lhdr.mod_time = 0;
	lhdr.mod_date = SWAP_LE16(0x5421);
	lhdr.crc32 = SWAP_LE32(crc);
	lhdr.comp_size = SWAP_LE32((uint32_t)comp_sz);
	lhdr.uncomp_size = SWAP_LE32((uint32_t)data_len);
	lhdr.filename_len = SWAP_LE16((uint16_t)name_len);
	lhdr.extra_len = 0;

	if (fwrite(&lhdr, 1, sizeof(lhdr), zw->fp) != sizeof(lhdr) ||
	    fwrite(zip_name, 1, name_len, zw->fp) != name_len) {
		if (method == 8 && comp_buf) free(comp_buf);
		return false;
	}

	if (comp_sz > 0 && fwrite(comp_buf, 1, comp_sz, zw->fp) != comp_sz) {
		if (method == 8 && comp_buf) free(comp_buf);
		return false;
	}

	if (zw->num_entries >= zw->capacity) {
		zw->capacity *= 2;
		zw->entries = xrealloc(zw->entries, zw->capacity * sizeof(struct zip_entry_info));
	}

	zw->entries[zw->num_entries].name = xstrdup(zip_name);
	zw->entries[zw->num_entries].crc32 = crc;
	zw->entries[zw->num_entries].comp_size = (uint32_t)comp_sz;
	zw->entries[zw->num_entries].uncomp_size = (uint32_t)data_len;
	zw->entries[zw->num_entries].local_hdr_offset = zw->current_offset;
	zw->entries[zw->num_entries].comp_method = method;
	zw->entries[zw->num_entries].external_attr = ((uint32_t)mode) << 16;
	zw->num_entries++;

	zw->current_offset += (uint32_t)(sizeof(lhdr) + name_len + comp_sz);

	if (method == 8 && comp_buf) free(comp_buf);
	return true;
}

static bool zip_writer_add_file(struct zip_writer *zw, const char *zip_name, const char *disk_path, mode_t mode_override) {
	int fd;
	struct stat st;
	uint8_t *buf;
	mode_t m;
	bool res;

	fd = open(disk_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		bb_perror_msg("cannot open '%s'", disk_path);
		if (fd >= 0) close(fd);
		return false;
	}

	m = (mode_override != 0) ? mode_override : st.st_mode;

	buf = NULL;
	if (st.st_size > 0) {
		buf = xmalloc(st.st_size);
		if (full_read(fd, buf, st.st_size) != st.st_size) {
			bb_perror_msg("failed to read '%s'", disk_path);
			close(fd);
			free(buf);
			return false;
		}
	}
	close(fd);

	res = zip_writer_add_mem(zw, zip_name, buf ? (const void *)buf : "", st.st_size, m);
	if (buf) free(buf);
	return res;
}

static bool zip_writer_add_dir_recursive(struct zip_writer *zw, const char *zip_prefix, const char *disk_dir) {
	DIR *dir;
	struct dirent *de;
	char sub_disk[PATH_MAX];
	char sub_zip[PATH_MAX];
	struct stat st;
	char dir_zip_entry[PATH_MAX + 1];
	mode_t m;

	dir = opendir(disk_dir);
	if (!dir) return false;

	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		snprintf(sub_disk, sizeof(sub_disk), "%s/%s", disk_dir, de->d_name);
		if (zip_prefix && zip_prefix[0] != '\0') {
			snprintf(sub_zip, sizeof(sub_zip), "%s/%s", zip_prefix, de->d_name);
		} else {
			snprintf(sub_zip, sizeof(sub_zip), "%s", de->d_name);
		}

		if (stat(sub_disk, &st) != 0) continue;

		if (S_ISDIR(st.st_mode)) {
			snprintf(dir_zip_entry, sizeof(dir_zip_entry), "%s/", sub_zip);
			zip_writer_add_mem(zw, dir_zip_entry, "", 0, S_IFDIR | 0755);
			zip_writer_add_dir_recursive(zw, sub_zip, sub_disk);
		} else if (S_ISREG(st.st_mode)) {
			m = (st.st_mode & 0111) ? (S_IFREG | 0755) : (S_IFREG | 0644);
			zip_writer_add_file(zw, sub_zip, sub_disk, m);
		}
	}
	closedir(dir);
	return true;
}

static bool zip_writer_finish(struct zip_writer *zw) {
	uint32_t cd_offset;
	uint32_t cd_size = 0;
	size_t i;
	struct zip_eocd_record eocd;

	if (!zw || !zw->fp) return false;

	cd_offset = zw->current_offset;

	for (i = 0; i < zw->num_entries; i++) {
		struct zip_entry_info *e = &zw->entries[i];
		struct zip_central_dir_hdr cd;
		size_t nlen = strlen(e->name);

		memset(&cd, 0, sizeof(cd));
		cd.signature = SWAP_LE32(ZIP_CENTRAL_DIR_MAGIC);
		cd.version_made_by = SWAP_LE16(0x031e); /* UNIX 3.0 */
		cd.version_needed = SWAP_LE16(20);
		cd.flags = 0;
		cd.compression = SWAP_LE16(e->comp_method);
		cd.mod_time = 0;
		cd.mod_date = SWAP_LE16(0x5421);
		cd.crc32 = SWAP_LE32(e->crc32);
		cd.comp_size = SWAP_LE32(e->comp_size);
		cd.uncomp_size = SWAP_LE32(e->uncomp_size);
		cd.filename_len = SWAP_LE16((uint16_t)nlen);
		cd.extra_len = 0;
		cd.comment_len = 0;
		cd.disk_num_start = 0;
		cd.internal_attr = 0;
		cd.external_attr = SWAP_LE32(e->external_attr);
		cd.local_hdr_offset = SWAP_LE32(e->local_hdr_offset);

		if (fwrite(&cd, 1, sizeof(cd), zw->fp) != sizeof(cd) ||
		    fwrite(e->name, 1, nlen, zw->fp) != nlen) {
			fclose(zw->fp);
			return false;
		}

		cd_size += (uint32_t)(sizeof(cd) + nlen);
		free(e->name);
	}

	memset(&eocd, 0, sizeof(eocd));
	eocd.signature = SWAP_LE32(ZIP_EOCD_MAGIC);
	eocd.disk_num = 0;
	eocd.cd_disk_num = 0;
	eocd.total_entries_disk = SWAP_LE16((uint16_t)zw->num_entries);
	eocd.total_entries = SWAP_LE16((uint16_t)zw->num_entries);
	eocd.cd_size = SWAP_LE32(cd_size);
	eocd.cd_offset = SWAP_LE32(cd_offset);
	eocd.comment_len = 0;

	if (fwrite(&eocd, 1, sizeof(eocd), zw->fp) != sizeof(eocd)) {
		fclose(zw->fp);
		return false;
	}

	fclose(zw->fp);
	zw->fp = NULL;
	free(zw->entries);
	zw->entries = NULL;
	return true;
}

static char *resolve_magiskboot_binary(const char *custom) {
	if (custom && access(custom, R_OK) == 0) {
		return xstrdup(custom);
	}
	if (access("/home/rick/open-source/busybox/busybox", R_OK) == 0) {
		return xstrdup("/home/rick/open-source/busybox/busybox");
	}
	if (access("/proc/self/exe", R_OK) == 0) {
		return xstrdup("/proc/self/exe");
	}
	if (access("/home/rick/open-source/magiskboot/magiskboot-aarch64", R_OK) == 0) {
		return xstrdup("/home/rick/open-source/magiskboot/magiskboot-aarch64");
	}
	if (access("/home/rick/open-source/magiskboot/build/aarch64/magiskboot-aarch64", R_OK) == 0) {
		return xstrdup("/home/rick/open-source/magiskboot/build/aarch64/magiskboot-aarch64");
	}
	if (access("/home/rick/open-source/magiskboot/build/aarch64/magiskboot", R_OK) == 0) {
		return xstrdup("/home/rick/open-source/magiskboot/build/aarch64/magiskboot");
	}
	return NULL;
}

static char *generate_universal_update_binary(const char *banner, const char *dev_check,
                                              const char *supported_versions, const char *supported_patchlevels,
                                              bool has_init_boot, bool has_vendor_boot,
                                              bool has_vendor_dlkm, bool has_system_dlkm,
                                              bool patch_vbmeta) {
	char dev_block[1024];
	char ver_block[1024];
	char level_block[1024];
	char *script;
	const char *banner_text = (banner && banner[0]) ? banner : "Universal Kernel & Root Engine";

	dev_block[0] = '\0';
	if (dev_check && dev_check[0]) {
		snprintf(dev_block, sizeof(dev_block),
			"\n# Target Device Guardrail Check\n"
			"CURRENT_DEV=$(getprop ro.product.device 2>/dev/null)\n"
			"[ -z \"$CURRENT_DEV\" ] && CURRENT_DEV=$(getprop ro.build.product 2>/dev/null)\n"
			"[ -z \"$CURRENT_DEV\" ] && CURRENT_DEV=$(getprop ro.product.model 2>/dev/null)\n"
			"ui_print \"- Target device detected: $CURRENT_DEV\"\n"
			"DEV_MATCH=0\n"
			"for d in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_DEV\" = \"$d\" ]; then DEV_MATCH=1; break; fi\n"
			"done\n"
			"if [ $DEV_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Error: Unsupported device '$CURRENT_DEV'!\"\n"
			"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
			"fi\n",
			dev_check);
	}

	ver_block[0] = '\0';
	if (supported_versions && supported_versions[0]) {
		snprintf(ver_block, sizeof(ver_block),
			"\n# Android OS Version Compatibility Gate\n"
			"CURRENT_VER=$(getprop ro.build.version.release 2>/dev/null)\n"
			"[ -z \"$CURRENT_VER\" ] && CURRENT_VER=$(getprop ro.build.version.sdk 2>/dev/null)\n"
			"ui_print \"- Android version detected: $CURRENT_VER\"\n"
			"VER_MATCH=0\n"
			"for v in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_VER\" = \"$v\" ]; then VER_MATCH=1; break; fi\n"
			"done\n"
			"if [ $VER_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Error: Unsupported Android version '$CURRENT_VER'! (Supported: %s)\"\n"
			"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
			"fi\n",
			supported_versions, supported_versions);
	}

	level_block[0] = '\0';
	if (supported_patchlevels && supported_patchlevels[0]) {
		snprintf(level_block, sizeof(level_block),
			"\n# Security Patch Level Compatibility Gate\n"
			"CURRENT_SPL=$(getprop ro.build.version.security_patch 2>/dev/null)\n"
			"ui_print \"- Security patch level detected: $CURRENT_SPL\"\n"
			"SPL_MATCH=0\n"
			"for l in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_SPL\" = \"$l\" ]; then SPL_MATCH=1; break; fi\n"
			"done\n"
			"if [ $SPL_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Warning: Security patch level '$CURRENT_SPL' differs from target (%s)\"\n"
			"fi\n",
			supported_patchlevels, supported_patchlevels);
	}

	script = xasprintf(
		"#!/sbin/sh\n"
		"# SPDX-License-Identifier: GPL-2.0-or-later\n"
		"# Universal MagiskBoot & AnyKernel3 Recovery Flashable Installer\n\n"
		"OUTFD=$2\n"
		"ZIPFILE=\"$3\"\n\n"
		"ui_print() {\n"
		"  echo \"ui_print $1\" >> /proc/self/fd/$OUTFD\n"
		"  echo \"ui_print\" >> /proc/self/fd/$OUTFD\n"
		"}\n\n"
		"ui_print \"********************************************************\"\n"
		"ui_print \"* %-52s *\"\n"
		"ui_print \"*            Universal Recovery Live-Patcher           *\"\n"
		"ui_print \"********************************************************\"\n\n"
		"TMPDIR=\"/tmp/installer_$$\"\n"
		"mkdir -p \"$TMPDIR\"\n"
		"cd \"$TMPDIR\"\n\n"
		"ui_print \"- Extracting installer payload...\"\n"
		"unzip -o \"$ZIPFILE\" >/dev/null 2>&1\n\n"
		"MB=\"$TMPDIR/tools/magiskboot\"\n"
		"if [ ! -f \"$MB\" ]; then\n"
		"  ui_print \"! Error: Embedded magiskboot missing!\"\n"
		"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
		"fi\n"
		"chmod 755 \"$MB\"\n"
		"%s%s%s\n"
		"find_slot() {\n"
		"  local slot=$(getprop ro.boot.slot_suffix 2>/dev/null)\n"
		"  [ -z \"$slot\" ] && slot=$(grep -o 'androidboot.slot_suffix=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2)\n"
		"  [ -z \"$slot\" ] && slot=$(getprop ro.boot.slot 2>/dev/null)\n"
		"  [ -n \"$slot\" ] && [ \"${slot#_}\" = \"$slot\" ] && slot=\"_$slot\"\n"
		"  [ \"$slot\" = \"normal\" ] && slot=\"\"\n"
		"  # Virtual A/B OTA Background Snapshot Target Inversion\n"
		"  if [ -d /postinstall/tmp ] && [ -n \"$slot\" ]; then\n"
		"    case \"$slot\" in\n"
		"      _a) slot=\"_b\";;\n"
		"      _b) slot=\"_a\";;\n"
		"    esac\n"
		"  fi\n"
		"  [ -n \"$slot\" ] && echo \"$slot\"\n"
		"}\n\n"
		"find_part() {\n"
		"  local p=\"$1\"\n"
		"  local slot=$(find_slot)\n"
		"  for d in /dev/block/bootdevice/by-name /dev/block/by-name /dev/block/platform/*/by-name /dev/block/platform/*/*/by-name /dev/block/mapper; do\n"
		"    if [ -e \"$d/$p$slot\" ]; then echo \"$d/$p$slot\"; return 0; fi\n"
		"    if [ -e \"$d/$p\" ]; then echo \"$d/$p\"; return 0; fi\n"
		"  done\n"
		"  return 1\n"
		"}\n\n"
		"# Full AnyKernel3 Ramdisk & Configuration Modification DSL\n"
		"backup_file() { [ ! -f \"$1~\" ] && cp -fp \"$1\" \"$1~\"; }\n"
		"restore_file() { [ -f \"$1~\" ] && cp -fp \"$1~\" \"$1\"; rm -f \"$1~\"; }\n\n"
		"replace_string() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local orig=\"$3\"; local repl=\"$4\"\n"
		"  [ -z \"$orig\" ] && orig=\"$s\"; [ -z \"$repl\" ] && repl=\"$3\"\n"
		"  if [ -f \"$f\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    sed -i \"s|$orig|$repl|g\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"replace_section() {\n"
		"  local f=\"$1\"; local b=\"$2\"; local e=\"$3\"; local r=\"$4\"\n"
		"  local begin=$(grep -n -m1 \"$b\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  if [ -n \"$begin\" ]; then\n"
		"    [ -z \"$e\" ] && e='^[[:space:]]*$'\n"
		"    local last=$(wc -l < \"$f\" 2>/dev/null)\n"
		"    for end in $(grep -n \"$e\" \"$f\" 2>/dev/null | cut -d: -f1) $last; do\n"
		"      if [ \"$end\" -gt \"$begin\" ]; then\n"
		"        sed -i \"${begin},${end}d\" \"$f\" 2>/dev/null\n"
		"        [ \"$end\" -eq \"$last\" ] && echo \"\" >> \"$f\"\n"
		"        sed -i \"${begin}s|^|${r}\\n|\" \"$f\" 2>/dev/null\n"
		"        break\n"
		"      fi\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"remove_section() {\n"
		"  local f=\"$1\"; local b=\"$2\"; local e=\"$3\"\n"
		"  local begin=$(grep -n -m1 \"$b\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  if [ -n \"$begin\" ]; then\n"
		"    [ -z \"$e\" ] && e='^[[:space:]]*$'\n"
		"    local last=$(wc -l < \"$f\" 2>/dev/null)\n"
		"    for end in $(grep -n \"$e\" \"$f\" 2>/dev/null | cut -d: -f1) $last; do\n"
		"      if [ \"$end\" -gt \"$begin\" ]; then\n"
		"        sed -i \"${begin},${end}d\" \"$f\" 2>/dev/null\n"
		"        break\n"
		"      fi\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"insert_line() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local loc=\"$3\"; local m=\"$4\"; local l=\"$5\"\n"
		"  if [ -f \"$f\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local off=1; [ \"$loc\" = \"before\" ] && off=0\n"
		"    local lnum=$(( $(grep -n -m1 \"$m\" \"$f\" 2>/dev/null | cut -d: -f1) + off ))\n"
		"    if [ \"$(wc -l < \"$f\")\" -lt \"$lnum\" ]; then\n"
		"      echo \"$l\" >> \"$f\"\n"
		"    else\n"
		"      sed -i \"${lnum}s|^|${l}\\n|\" \"$f\" 2>/dev/null\n"
		"    fi\n"
		"  fi\n"
		"}\n\n"
		"replace_line() {\n"
		"  local f=\"$1\"; local m=\"$2\"; local r=\"$3\"; local sc=\"$4\"\n"
		"  if [ -f \"$f\" ] && grep -q \"$m\" \"$f\" 2>/dev/null; then\n"
		"    local lines=$(grep -n \"$m\" \"$f\" 2>/dev/null | cut -d: -f1 | sort -nr)\n"
		"    [ \"$sc\" != \"global\" ] && lines=$(echo \"$lines\" | tail -n1)\n"
		"    for line in $lines; do\n"
		"      sed -i \"${line}s|.*|${r}|\" \"$f\" 2>/dev/null\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"remove_line() {\n"
		"  local f=\"$1\"; local m=\"$2\"; local sc=\"$3\"\n"
		"  if [ -f \"$f\" ] && grep -q \"$m\" \"$f\" 2>/dev/null; then\n"
		"    local lines=$(grep -n \"$m\" \"$f\" 2>/dev/null | cut -d: -f1 | sort -nr)\n"
		"    [ \"$sc\" != \"global\" ] && lines=$(echo \"$lines\" | tail -n1)\n"
		"    for line in $lines; do\n"
		"      sed -i \"${line}d\" \"$f\" 2>/dev/null\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"insert_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local loc=\"$3\"; local m=\"$4\"; local p=\"$5\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local off=1; [ \"$loc\" = \"before\" ] && off=0\n"
		"    local lnum=$(( $(grep -n -m1 \"$m\" \"$f\" 2>/dev/null | cut -d: -f1) + off ))\n"
		"    sed -i \"${lnum}s|^|\\n|\" \"$f\" 2>/dev/null\n"
		"    sed -i \"$((lnum - 1))r $p\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"prepend_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local p=\"$3\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local tmp=\"$TMPDIR/prep_$$\"\n"
		"    cat \"$p\" \"$f\" > \"$tmp\" && mv -f \"$tmp\" \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"append_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local p=\"$3\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    echo \"\" >> \"$f\"\n"
		"    cat \"$p\" >> \"$f\"\n"
		"    echo \"\" >> \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"replace_file() {\n"
		"  if [ -f \"$3\" ]; then\n"
		"    cp -pf \"$3\" \"$1\" && chmod \"$2\" \"$1\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_prop() {\n"
		"  local f=\"$1\"; local k=\"$2\"; local v=\"$3\"\n"
		"  [ -f \"$f\" ] || return 1\n"
		"  if ! grep -q \"^$k=\" \"$f\" 2>/dev/null; then\n"
		"    echo \"$k=$v\" >> \"$f\"\n"
		"  else\n"
		"    local line=$(grep -n -m1 \"^$k=\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"    sed -i \"${line}s|.*|${k}=${v}|\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_ueventd() {\n"
		"  local f=\"$1\"; local d=\"$2\"; local p=\"$3\"; local u=\"$4\"; shift 4; local g=\"$*\"\n"
		"  [ -f \"$f\" ] || return 1\n"
		"  local line=$(grep -n -m1 \"$d\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  local entry=\"$d   $p   $u   $g\"\n"
		"  if [ -n \"$line\" ]; then\n"
		"    sed -i \"${line}s|.*|${entry}|\" \"$f\" 2>/dev/null\n"
		"  else\n"
		"    echo \"$entry\" >> \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"patch_fstab() {\n"
		"  local f=\"$1\"; local mnt=\"$2\"; local old=\"$3\"; local new=\"$4\"\n"
		"  if [ -f \"$f\" ]; then\n"
		"    \"$MB\" fstab \"$f\" patch \"$mnt\" \"$old\" \"$new\" 2>/dev/null || sed -i \"s|$old|$new|g\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_cmdline() {\n"
		"  local f=\"$1\"; local key=\"$2\"; local val=\"$3\"\n"
		"  if [ -f \"$f\" ]; then\n"
		"    \"$MB\" cmdline \"$f\" patch \"$key\" \"$val\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"# Dynamic Partition & Super Volume Flash Engine\n"
		"flash_generic() {\n"
		"  local p=\"$1\"\n"
		"  local img=\"\"\n"
		"  for f in \"$TMPDIR/$p\" \"$TMPDIR/$p.img\"; do\n"
		"    if [ -f \"$f\" ]; then img=\"$f\"; break; fi\n"
		"  done\n"
		"  [ -z \"$img\" ] && return 0\n"
		"  local part=$(find_part \"$p\")\n"
		"  if [ -z \"$part\" ]; then\n"
		"    ui_print \"! Notice: Partition $p not found on device, skipping\"\n"
		"    return 0\n"
		"  fi\n"
		"  ui_print \"- Flashing $p -> $part...\"\n"
		"  blockdev --setrw \"$part\" 2>/dev/null\n"
		"  if [ -d /postinstall/tmp ] && which snapshotupdater_static >/dev/null 2>&1; then\n"
		"    local imgsz=$(wc -c < \"$img\")\n"
		"    snapshotupdater_static update \"$p\" \"$imgsz\" 2>/dev/null || true\n"
		"  fi\n"
		"  case \"$part\" in\n"
		"    /dev/block/mapper/*)\n"
		"      if which lptools_static >/dev/null 2>&1; then\n"
		"        local imgsz=$(wc -c < \"$img\")\n"
		"        lptools_static resize \"$p$(find_slot)\" \"$imgsz\" 2>/dev/null || true\n"
		"      fi\n"
		"      ;;\n"
		"  esac\n"
		"  dd if=\"$img\" of=\"$part\" bs=1048576 2>/dev/null || cat \"$img\" > \"$part\"\n"
		"  local ret=$?\n"
		"  if [ $ret -eq 0 ]; then\n"
		"    ui_print \"- Successfully flashed $p\"\n"
		"  else\n"
		"    ui_print \"! Error flashing $p (code $ret)\"\n"
		"  fi\n"
		"  return $ret\n"
		"}\n\n"
		"# AVB 2.0 VBMeta dm-verity Neutralization Engine\n"
		"patch_vbmeta_device() {\n"
		"  for vbname in vbmeta vbmeta_system vbmeta_vendor; do\n"
		"    local vb=$(find_part \"$vbname\")\n"
		"    if [ -n \"$vb\" ]; then\n"
		"      ui_print \"- Neutralizing dm-verity on $vb ($vbname)...\"\n"
		"      blockdev --setrw \"$vb\" 2>/dev/null\n"
		"      \"$MB\" vbmeta \"$vb\" disable 2>/dev/null || true\n"
		"    fi\n"
		"  done\n"
		"}\n\n"
		"PATCH_VBMETA=%d\n"
		"if [ \"$PATCH_VBMETA\" = \"1\" ]; then\n"
		"  patch_vbmeta_device\n"
		"fi\n\n"
		"HAS_INIT_BOOT=%d\n"
		"if [ \"$HAS_INIT_BOOT\" = \"0\" ]; then\n"
		"  if find_part \"init_boot\" >/dev/null 2>&1; then HAS_INIT_BOOT=1; fi\n"
		"fi\n"
		"RD_PART=\"boot\"\n"
		"if [ \"$HAS_INIT_BOOT\" = \"1\" ]; then\n"
		"  RD_PART=\"init_boot\"\n"
		"  ui_print \"- GKI 2.0 multi-partition device detected: ramdisk in init_boot\"\n"
		"fi\n\n"
		"HAS_VENDOR_BOOT=%d\n"
		"if [ -f \"$TMPDIR/vendor_boot.img\" ] || [ \"$HAS_VENDOR_BOOT\" = \"1\" ]; then\n"
		"  VNDR_PART=$(find_part \"vendor_boot\")\n"
		"  if [ -n \"$VNDR_PART\" ] && [ -f \"$TMPDIR/vendor_boot.img\" ]; then\n"
		"    ui_print \"- Flashing vendor_boot image to $VNDR_PART...\"\n"
		"    dd if=\"$TMPDIR/vendor_boot.img\" of=\"$VNDR_PART\" bs=1048576 2>/dev/null || cat \"$TMPDIR/vendor_boot.img\" > \"$VNDR_PART\"\n"
		"  fi\n"
		"fi\n\n"
		"MODULES=\"\"\n"
		"[ -d \"$TMPDIR/modules\" ] && MODULES=\"$TMPDIR/modules\"\n\n"
		"KERNEL=\"\"\n"
		"if [ -f \"$TMPDIR/kernel\" ]; then KERNEL=\"$TMPDIR/kernel\";\n"
		"elif [ -f \"$TMPDIR/Image\" ]; then KERNEL=\"$TMPDIR/Image\";\n"
		"elif [ -f \"$TMPDIR/Image.gz\" ]; then KERNEL=\"$TMPDIR/Image.gz\"; fi\n\n"
		"ui_print \"- Live patching active hardware partitions via magiskboot...\"\n"
		"RET=0\n\n"
		"if [ -n \"$KERNEL\" ]; then\n"
		"  ui_print \"- Replacing kernel image...\"\n"
		"  CMD=\"kernel boot patch --kernel $KERNEL\"\n"
		"  [ -f \"$TMPDIR/dtb\" ] && CMD=\"$CMD --dtb $TMPDIR/dtb\"\n"
		"  [ -f \"$TMPDIR/dtbo.img\" ] && CMD=\"$CMD --dtbo $TMPDIR/dtbo.img\"\n"
		"  eval \"\\\"$MB\\\" $CMD\"\n"
		"  RET=$?\n"
		"fi\n\n"
		"if [ -n \"$MODULES\" ]; then\n"
		"  for ko in \"$MODULES\"/*.ko; do\n"
		"    if [ -f \"$ko\" ]; then\n"
		"      ui_print \"- Injecting module $(basename \"$ko\") into $RD_PART ramdisk...\"\n"
		"      \"$MB\" add-module --live -p \"$RD_PART\" --install \"$ko\"\n"
		"      RET=$?\n"
		"      if [ $RET -ne 0 ]; then ui_print \"! Failed to inject module $(basename \"$ko\")\"; break; fi\n"
		"    fi\n"
		"  done\n"
		"fi\n\n"
		"# Flash Dynamic / Logical Partitions (vendor_dlkm, system_dlkm, dtbo)\n"
		"HAS_VENDOR_DLKM=%d\n"
		"if [ \"$HAS_VENDOR_DLKM\" = \"1\" ] || [ -f \"$TMPDIR/vendor_dlkm.img\" ]; then\n"
		"  flash_generic \"vendor_dlkm\"\n"
		"fi\n\n"
		"HAS_SYSTEM_DLKM=%d\n"
		"if [ \"$HAS_SYSTEM_DLKM\" = \"1\" ] || [ -f \"$TMPDIR/system_dlkm.img\" ]; then\n"
		"  flash_generic \"system_dlkm\"\n"
		"fi\n\n"
		"if [ -f \"$TMPDIR/dtbo.img\" ]; then\n"
		"  flash_generic \"dtbo\"\n"
		"fi\n\n"
		"APK_PATH=\"\"\n"
		"if [ -d \"$TMPDIR/app\" ]; then\n"
		"  for a in \"$TMPDIR/app\"/*.apk; do if [ -f \"$a\" ]; then APK_PATH=\"$a\"; break; fi; done\n"
		"fi\n"
		"if [ $RET -eq 0 ] && [ -n \"$APK_PATH\" ]; then\n"
		"  if [ \"$(getprop sys.boot_completed 2>/dev/null)\" = \"1\" ] && which pm >/dev/null 2>&1; then\n"
		"    ui_print \"- Live Android: installing manager APK via pm...\"\n"
		"    pm install -g -r \"$APK_PATH\" >/dev/null 2>&1\n"
		"  else\n"
		"    [ ! -d /data/system ] && mount /data >/dev/null 2>&1\n"
		"    if [ -d /data ]; then\n"
		"      mkdir -p /data/system/kroot\n"
		"      cp -f \"$APK_PATH\" /data/system/kroot/kroot.apk\n"
		"      chmod 644 /data/system/kroot/kroot.apk 2>/dev/null\n"
		"      ui_print \"- Staged manager APK to /data/system/kroot\"\n"
		"    fi\n"
		"  fi\n"
		"fi\n\n"
		"cd /; rm -rf \"$TMPDIR\"\n"
		"if [ $RET -eq 0 ]; then\n"
		"  ui_print \"********************************************************\"\n"
		"  ui_print \"* Flash complete! Reboot to activate.                  *\"\n"
		"  ui_print \"********************************************************\"\n"
		"  exit 0\n"
		"else\n"
		"  ui_print \"! Installation failed with code $RET\"\n"
		"  exit $RET\n"
		"fi\n",
		banner_text,
		dev_block,
		ver_block,
		level_block,
		patch_vbmeta ? 1 : 0,
		has_init_boot ? 1 : 0,
		has_vendor_boot ? 1 : 0,
		has_vendor_dlkm ? 1 : 0,
		has_system_dlkm ? 1 : 0
	);

	return script;
}

static int package_dist_zip(struct dist_package_options *opts) {
	struct zip_writer zw;
	char *update_bin_script;
	char *mb_bin;
	size_t i;
	struct stat st;

	if (!opts || !opts->out_zip) {
		bb_error_msg("missing output zip file");
		return 1;
	}

	fprintf(stderr, "======================================================================\n");
	fprintf(stderr, "  Packaging Universal Recovery Flashable ZIP: %s\n", opts->out_zip);
	fprintf(stderr, "======================================================================\n");

	if (!zip_writer_init(&zw, opts->out_zip)) {
		return 1;
	}

	/* 1. META-INF/com/google/android/updater-script (#MAGISK) */
	zip_writer_add_mem(&zw, "META-INF/com/google/android/updater-script", "#MAGISK\n", 8, S_IFREG | 0644);

	/* 2. META-INF/com/google/android/update-binary */
	if (opts->update_binary_script && access(opts->update_binary_script, R_OK) == 0) {
		zip_writer_add_file(&zw, "META-INF/com/google/android/update-binary", opts->update_binary_script, S_IFREG | 0755);
		fprintf(stderr, "[+] Bundled custom update-binary from '%s'\n", opts->update_binary_script);
	} else {
		update_bin_script = generate_universal_update_binary(
			opts->banner,
			opts->device_check,
			opts->supported_versions,
			opts->supported_patchlevels,
			opts->target_init_boot,
			(opts->vendor_boot_path != NULL),
			(opts->vendor_dlkm_path != NULL),
			(opts->system_dlkm_path != NULL),
			opts->patch_vbmeta
		);
		zip_writer_add_mem(&zw, "META-INF/com/google/android/update-binary", update_bin_script, strlen(update_bin_script), S_IFREG | 0755);
		free(update_bin_script);
		fprintf(stderr, "[+] Bundled universal recovery live-patcher update-binary\n");
	}

	/* 3. tools/magiskboot */
	mb_bin = resolve_magiskboot_binary(opts->magiskboot_bin);
	if (mb_bin && access(mb_bin, R_OK) == 0) {
		zip_writer_add_file(&zw, "tools/magiskboot", mb_bin, S_IFREG | 0755);
		fprintf(stderr, "[+] Bundled tools/magiskboot from '%s'\n", mb_bin);
		free(mb_bin);
	} else {
		fprintf(stderr, "[!] Warning: No compiled target magiskboot found to embed into tools/magiskboot\n");
	}

	/* 4. Modules into modules/ (*.ko) */
	for (i = 0; i < opts->num_modules; i++) {
		const char *mpath = opts->modules[i];
		if (stat(mpath, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				DIR *mdir = opendir(mpath);
				if (mdir) {
					struct dirent *de;
					while ((de = readdir(mdir)) != NULL) {
						if (strstr(de->d_name, ".ko")) {
							char full_m[PATH_MAX];
							char zip_m[PATH_MAX];
							snprintf(full_m, sizeof(full_m), "%s/%s", mpath, de->d_name);
							snprintf(zip_m, sizeof(zip_m), "modules/%s", de->d_name);
							zip_writer_add_file(&zw, zip_m, full_m, S_IFREG | 0644);
							fprintf(stderr, "[+] Bundled module: %s\n", zip_m);
						}
					}
					closedir(mdir);
				}
			} else if (S_ISREG(st.st_mode)) {
				const char *bname = bb_basename(mpath);
				char zip_m[PATH_MAX];
				snprintf(zip_m, sizeof(zip_m), "modules/%s", bname);
				zip_writer_add_file(&zw, zip_m, mpath, S_IFREG | 0644);
				fprintf(stderr, "[+] Bundled module: %s\n", zip_m);
			}
		}
	}

	/* 5. Kernel image */
	if (opts->kernel_path && access(opts->kernel_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "kernel", opts->kernel_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled kernel payload: '%s'\n", opts->kernel_path);
	}

	/* 6. DTB */
	if (opts->dtb_path && access(opts->dtb_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "dtb", opts->dtb_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled DTB payload: '%s'\n", opts->dtb_path);
	}

	/* 7. DTBO */
	if (opts->dtbo_path && access(opts->dtbo_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "dtbo.img", opts->dtbo_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled DTBO payload: '%s'\n", opts->dtbo_path);
	}

	/* 7b. Vendor Boot */
	if (opts->vendor_boot_path && access(opts->vendor_boot_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "vendor_boot.img", opts->vendor_boot_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled vendor_boot payload: '%s'\n", opts->vendor_boot_path);
	}

	/* 7c. Vendor DLKM */
	if (opts->vendor_dlkm_path && access(opts->vendor_dlkm_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "vendor_dlkm.img", opts->vendor_dlkm_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled vendor_dlkm payload: '%s'\n", opts->vendor_dlkm_path);
	}

	/* 7d. System DLKM */
	if (opts->system_dlkm_path && access(opts->system_dlkm_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "system_dlkm.img", opts->system_dlkm_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled system_dlkm payload: '%s'\n", opts->system_dlkm_path);
	}

	/* 8. Manager APK */
	if (opts->app_path && access(opts->app_path, R_OK) == 0) {
		const char *bname = bb_basename(opts->app_path);
		char zip_app[PATH_MAX];
		snprintf(zip_app, sizeof(zip_app), "app/%s", bname);
		zip_writer_add_file(&zw, zip_app, opts->app_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled manager APK: %s\n", zip_app);
	}

	/* 9. overlay.d/ */
	if (opts->overlay_dir && stat(opts->overlay_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
		zip_writer_add_dir_recursive(&zw, "overlay.d", opts->overlay_dir);
		fprintf(stderr, "[+] Bundled overlay tree from '%s'\n", opts->overlay_dir);
	}

	if (!zip_writer_finish(&zw)) {
		bb_error_msg("failed to finalize zip archive");
		return 1;
	}

	if (stat(opts->out_zip, &st) == 0) {
		fprintf(stderr, "[✓] SUCCESS: Universal recovery flashable ZIP generated: '%s' (%zu bytes)\n",
		        opts->out_zip, (size_t)st.st_size);
	}
	fprintf(stderr, "======================================================================\n");
	return 0;
}

static int zip_list_file(const char *zip_path) {
	int fd;
	struct stat st;
	uint8_t *map;
	size_t search_len, i;
	uint32_t eocd_pos = 0;
	bool found_eocd = false;
	struct zip_eocd_record *eocd;
	uint32_t cd_offset, cd_size;
	uint16_t total_entries;
	size_t pos, count;

	fd = open(zip_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < sizeof(struct zip_eocd_record)) {
		bb_perror_msg("cannot open '%s'", zip_path);
		if (fd >= 0) close(fd);
		return 1;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	search_len = (st.st_size > 65536 + sizeof(struct zip_eocd_record)) ?
	             (65536 + sizeof(struct zip_eocd_record)) : st.st_size;

	for (i = 0; i + sizeof(struct zip_eocd_record) <= search_len; i++) {
		size_t off = st.st_size - sizeof(struct zip_eocd_record) - i;
		if (*(uint32_t *)(map + off) == SWAP_LE32(ZIP_EOCD_MAGIC)) {
			eocd_pos = (uint32_t)off;
			found_eocd = true;
			break;
		}
	}

	if (!found_eocd) {
		bb_error_msg("'%s' is not a valid ZIP archive (EOCD magic not found)", zip_path);
		munmap(map, st.st_size);
		return 1;
	}

	eocd = (struct zip_eocd_record *)(map + eocd_pos);
	cd_offset = SWAP_LE32(eocd->cd_offset);
	cd_size = SWAP_LE32(eocd->cd_size);
	total_entries = SWAP_LE16(eocd->total_entries);

	printf("======================================================================\n");
	printf("  ZIP Archive Inspection: %s\n", zip_path);
	printf("  Total Entries: %u, Central Directory Size: %u bytes\n", total_entries, cd_size);
	printf("======================================================================\n");
	printf("  Mode      Method    CompSize    UncompSize  Name\n");
	printf("  --------  --------  ----------  ----------  ------------------------\n");

	pos = cd_offset;
	count = 0;
	while (pos + sizeof(struct zip_central_dir_hdr) <= st.st_size && count < total_entries) {
		struct zip_central_dir_hdr *cd = (struct zip_central_dir_hdr *)(map + pos);
		uint16_t nlen, xlen, clen, comp_m;
		uint32_t comp_sz, uncomp_sz, ext_attr;
		char name_buf[PATH_MAX];

		if (SWAP_LE32(cd->signature) != ZIP_CENTRAL_DIR_MAGIC) break;

		nlen = SWAP_LE16(cd->filename_len);
		xlen = SWAP_LE16(cd->extra_len);
		clen = SWAP_LE16(cd->comment_len);
		comp_m = SWAP_LE16(cd->compression);
		comp_sz = SWAP_LE32(cd->comp_size);
		uncomp_sz = SWAP_LE32(cd->uncomp_size);
		ext_attr = SWAP_LE32(cd->external_attr);

		if (pos + sizeof(*cd) + nlen > st.st_size) break;
		if (nlen >= sizeof(name_buf)) nlen = sizeof(name_buf) - 1;
		memcpy(name_buf, map + pos + sizeof(*cd), nlen);
		name_buf[nlen] = '\0';

		printf("  %06o    %-8s  %10u  %10u  %s\n",
		       (ext_attr >> 16) & 07777,
		       (comp_m == 8) ? "Deflate" : (comp_m == 0 ? "Stored" : "Other"),
		       comp_sz, uncomp_sz, name_buf);

		pos += sizeof(*cd) + SWAP_LE16(cd->filename_len) + xlen + clen;
		count++;
	}

	printf("======================================================================\n");
	munmap(map, st.st_size);
	return 0;
}

static int zip_extract_file(const char *zip_path, const char *target_entry, const char *dest_dir) {
	int fd;
	struct stat st;
	uint8_t *map;
	size_t search_len, i;
	uint32_t eocd_pos = 0;
	bool found_eocd = false;
	struct zip_eocd_record *eocd;
	uint32_t cd_offset;
	uint16_t total_entries;
	size_t pos, count;
	int extracted = 0;
	const char *dst_root = (dest_dir && dest_dir[0]) ? dest_dir : ".";

	fd = open(zip_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0 || st.st_size < sizeof(struct zip_eocd_record)) {
		bb_perror_msg("cannot open '%s'", zip_path);
		if (fd >= 0) close(fd);
		return 1;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	search_len = (st.st_size > 65536 + sizeof(struct zip_eocd_record)) ?
	             (65536 + sizeof(struct zip_eocd_record)) : st.st_size;

	for (i = 0; i + sizeof(struct zip_eocd_record) <= search_len; i++) {
		size_t off = st.st_size - sizeof(struct zip_eocd_record) - i;
		if (*(uint32_t *)(map + off) == SWAP_LE32(ZIP_EOCD_MAGIC)) {
			eocd_pos = (uint32_t)off;
			found_eocd = true;
			break;
		}
	}

	if (!found_eocd) {
		bb_error_msg("'%s' is not a valid ZIP archive", zip_path);
		munmap(map, st.st_size);
		return 1;
	}

	eocd = (struct zip_eocd_record *)(map + eocd_pos);
	cd_offset = SWAP_LE32(eocd->cd_offset);
	total_entries = SWAP_LE16(eocd->total_entries);

	pos = cd_offset;
	count = 0;
	while (pos + sizeof(struct zip_central_dir_hdr) <= st.st_size && count < total_entries) {
		struct zip_central_dir_hdr *cd = (struct zip_central_dir_hdr *)(map + pos);
		uint16_t nlen, xlen, clen, comp_m;
		uint32_t comp_sz, uncomp_sz, loc_off, ext_attr, payload_off;
		char name_buf[PATH_MAX];
		struct zip_local_hdr *lhdr;
		char dest_path[PATH_MAX * 2];
		mode_t mode;
		char *dname;
		int out_fd;

		if (SWAP_LE32(cd->signature) != ZIP_CENTRAL_DIR_MAGIC) break;

		nlen = SWAP_LE16(cd->filename_len);
		xlen = SWAP_LE16(cd->extra_len);
		clen = SWAP_LE16(cd->comment_len);
		comp_m = SWAP_LE16(cd->compression);
		comp_sz = SWAP_LE32(cd->comp_size);
		uncomp_sz = SWAP_LE32(cd->uncomp_size);
		loc_off = SWAP_LE32(cd->local_hdr_offset);
		ext_attr = SWAP_LE32(cd->external_attr);

		if (pos + sizeof(*cd) + nlen > st.st_size) break;
		if (nlen >= sizeof(name_buf)) nlen = sizeof(name_buf) - 1;
		memcpy(name_buf, map + pos + sizeof(*cd), nlen);
		name_buf[nlen] = '\0';

		if (target_entry && target_entry[0] != '\0' && strcmp(target_entry, name_buf) != 0) {
			pos += sizeof(*cd) + SWAP_LE16(cd->filename_len) + xlen + clen;
			count++;
			continue;
		}

		if (loc_off + sizeof(struct zip_local_hdr) > st.st_size) break;
		lhdr = (struct zip_local_hdr *)(map + loc_off);
		payload_off = loc_off + sizeof(struct zip_local_hdr) +
		              SWAP_LE16(lhdr->filename_len) + SWAP_LE16(lhdr->extra_len);
		if (payload_off + comp_sz > st.st_size) break;

		snprintf(dest_path, sizeof(dest_path), "%s/%s", dst_root, name_buf);
		mode = (ext_attr >> 16) & 07777;

		if (name_buf[nlen - 1] == '/') {
			bb_make_directory(dest_path, mode ? mode : 0755, FILEUTILS_RECUR);
		} else {
			dname = xstrdup(dest_path);
			bb_make_directory(dirname(dname), 0755, FILEUTILS_RECUR);
			free(dname);

			if (comp_m == 0) {
				out_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode ? mode : 0644);
				if (out_fd >= 0) {
					if (uncomp_sz > 0) full_write(out_fd, map + payload_off, uncomp_sz);
					close(out_fd);
					if (mode) chmod(dest_path, mode);
					extracted++;
					printf("[+] Extracted: %s (%u bytes)\n", name_buf, uncomp_sz);
				}
			} else if (comp_m == 8) {
				uint8_t *gz_tmp = xmalloc(comp_sz + 18);
				gz_tmp[0] = 0x1f; gz_tmp[1] = 0x8b; gz_tmp[2] = 0x08; gz_tmp[3] = 0;
				memset(gz_tmp + 4, 0, 6);
				memcpy(gz_tmp + 10, map + payload_off, comp_sz);
				*(uint32_t *)(gz_tmp + 10 + comp_sz) = SWAP_LE32(cd->crc32);
				*(uint32_t *)(gz_tmp + 10 + comp_sz + 4) = SWAP_LE32(uncomp_sz);

				out_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode ? mode : 0644);
				if (out_fd >= 0) {
					bb_decompress_data(BOOT_FMT_GZIP, gz_tmp, comp_sz + 18, out_fd);
					close(out_fd);
					if (mode) chmod(dest_path, mode);
					extracted++;
					printf("[+] Extracted (deflated): %s (%u bytes)\n", name_buf, uncomp_sz);
				}
				free(gz_tmp);
			}
		}

		pos += sizeof(*cd) + SWAP_LE16(cd->filename_len) + xlen + clen;
		count++;
	}

	munmap(map, st.st_size);
	printf("[✓] SUCCESS: Extracted %d file(s) from '%s' into '%s'\n", extracted, zip_path, dst_root);
	return 0;
}

static int zip_create_file(const char *out_zip, int num_files, char **files) {
	struct zip_writer zw;
	int i;
	struct stat st;
	const char *f, *bname;
	char dir_entry[PATH_MAX];
	mode_t m;

	if (!out_zip || num_files <= 0) {
		bb_error_msg("usage: magiskboot zip <out.zip> create <file1|dir1> [file2...]");
		return 1;
	}

	if (!zip_writer_init(&zw, out_zip)) return 1;

	for (i = 0; i < num_files; i++) {
		f = files[i];
		if (stat(f, &st) != 0) {
			bb_perror_msg("cannot stat '%s'", f);
			continue;
		}
		bname = bb_basename(f);
		if (S_ISDIR(st.st_mode)) {
			snprintf(dir_entry, sizeof(dir_entry), "%s/", bname);
			zip_writer_add_mem(&zw, dir_entry, "", 0, S_IFDIR | 0755);
			zip_writer_add_dir_recursive(&zw, bname, f);
		} else if (S_ISREG(st.st_mode)) {
			m = (st.st_mode & 0111) ? (S_IFREG | 0755) : (S_IFREG | 0644);
			zip_writer_add_file(&zw, bname, f, m);
			printf("[+] Added file '%s' -> '%s'\n", f, bname);
		}
	}

	if (!zip_writer_finish(&zw)) return 1;
	printf("[✓] SUCCESS: Created '%s'\n", out_zip);
	return 0;
}

static int magiskboot_dist_op(int argc, char **argv) {
	struct dist_package_options opts;
	int i;
	size_t mod_cap = 16;
	int ret;

	memset(&opts, 0, sizeof(opts));
	opts.modules = xzalloc(mod_cap * sizeof(char *));

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--module") == 0 || strcmp(argv[i], "--modules") == 0) {
			if (++i < argc) {
				if (opts.num_modules >= mod_cap) {
					mod_cap *= 2;
					opts.modules = xrealloc(opts.modules, mod_cap * sizeof(char *));
				}
				opts.modules[opts.num_modules++] = argv[i];
			}
		} else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel") == 0) {
			if (++i < argc) opts.kernel_path = argv[i];
		} else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dtb") == 0) {
			if (++i < argc) opts.dtb_path = argv[i];
		} else if (strcmp(argv[i], "--dtbo") == 0) {
			if (++i < argc) opts.dtbo_path = argv[i];
		} else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--app") == 0) {
			if (++i < argc) opts.app_path = argv[i];
		} else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--overlay") == 0) {
			if (++i < argc) opts.overlay_dir = argv[i];
		} else if (strcmp(argv[i], "--magiskboot") == 0) {
			if (++i < argc) opts.magiskboot_bin = argv[i];
		} else if (strcmp(argv[i], "--banner") == 0) {
			if (++i < argc) opts.banner = argv[i];
		} else if (strcmp(argv[i], "--device") == 0 || strcmp(argv[i], "--device-check") == 0) {
			if (++i < argc) opts.device_check = argv[i];
		} else if (strcmp(argv[i], "--android-version") == 0 || strcmp(argv[i], "--version-check") == 0) {
			if (++i < argc) opts.supported_versions = argv[i];
		} else if (strcmp(argv[i], "--patch-level") == 0 || strcmp(argv[i], "--level-check") == 0) {
			if (++i < argc) opts.supported_patchlevels = argv[i];
		} else if (strcmp(argv[i], "--vendor-boot") == 0) {
			if (++i < argc) opts.vendor_boot_path = argv[i];
		} else if (strcmp(argv[i], "--vendor-dlkm") == 0) {
			if (++i < argc) opts.vendor_dlkm_path = argv[i];
		} else if (strcmp(argv[i], "--system-dlkm") == 0) {
			if (++i < argc) opts.system_dlkm_path = argv[i];
		} else if (strcmp(argv[i], "--vbmeta-patch") == 0 || strcmp(argv[i], "--patch-vbmeta") == 0) {
			opts.patch_vbmeta = true;
		} else if (strcmp(argv[i], "--init-boot") == 0) {
			opts.target_init_boot = true;
		} else if (strcmp(argv[i], "--update-binary") == 0) {
			if (++i < argc) opts.update_binary_script = argv[i];
		} else if (argv[i][0] != '-') {
			opts.out_zip = argv[i];
		}
	}

	if (!opts.out_zip) {
		bb_error_msg("usage: magiskboot dist [options...] <output.zip>\n"
		             "  -m, --module <ko|dir>   Bundle kernel module(s)\n"
		             "  -k, --kernel <image>    Bundle kernel image\n"
		             "  -d, --dtb <dtb>         Bundle DTB image\n"
		             "  --dtbo <dtbo>           Bundle DTBO image\n"
		             "  -a, --app <apk>         Bundle Manager APK\n"
		             "  -o, --overlay <dir>     Bundle overlay.d/ directory\n"
		             "  --vendor-boot <image>   Bundle vendor_boot image\n"
		             "  --vendor-dlkm <img|dir> Bundle vendor_dlkm payload\n"
		             "  --system-dlkm <img|dir> Bundle system_dlkm payload\n"
		             "  --vbmeta-patch          Neutralize AVB/dm-verity on top-level vbmeta\n"
		             "  --magiskboot <bin>      Embed specific target magiskboot\n"
		             "  --banner <text>         Custom recovery installer banner\n"
		             "  --device <dev1,dev2>    Device check guardrails\n"
		             "  --android-version <ver> Supported Android version(s)\n"
		             "  --patch-level <date>    Supported security patch level\n"
		             "  --init-boot             Target init_boot partition (GKI 2.0)\n"
		             "  --update-binary <sh>    Custom update-binary script");
		free(opts.modules);
		return 1;
	}

	ret = package_dist_zip(&opts);
	free(opts.modules);
	return ret;
}

static int magiskboot_zip_op(int argc, char **argv) {
	const char *zip_file;
	const char *action;
	const char *entry;
	const char *dest;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot zip <file.zip> <create|list|extract> [args...]");
		return 1;
	}

	zip_file = argv[2];
	action = argv[3];

	if (strcmp(action, "create") == 0) {
		return zip_create_file(zip_file, argc - 4, argv + 4);
	}
	if (strcmp(action, "list") == 0 || strcmp(action, "ls") == 0) {
		return zip_list_file(zip_file);
	}
	if (strcmp(action, "extract") == 0 || strcmp(action, "x") == 0) {
		entry = (argc >= 5 && argv[4][0] != '\0') ? argv[4] : NULL;
		dest = (argc >= 6 && argv[5][0] != '\0') ? argv[5] : ".";
		return zip_extract_file(zip_file, entry, dest);
	}

	bb_error_msg("unknown zip action '%s' (supported: create, list, extract)", action);
	return 1;
}

/* =========================================================================
 * 13. Android FSTAB & Kernel Command-Line Toolkit
 * ========================================================================= */

static int fstab_print(const char *file) {
	FILE *fp;
	char line[1024];

	fp = fopen(file, "r");
	if (!fp) {
		bb_perror_msg("cannot open '%s'", file);
		return 1;
	}
	printf("======================================================================\n");
	printf("  Android FSTAB Inspector: %s\n", file);
	printf("======================================================================\n");
	printf("  %-30s %-16s %-8s %s\n", "Block Device", "Mount Point", "Type", "Flags & Options");
	printf("  %-30s %-16s %-8s %s\n", "------------------------------", "----------------", "--------", "--------------------");
	while (fgets(line, sizeof(line), fp)) {
		char *p = line;
		char *dev, *mnt, *type, *opts, *flags;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\0' || *p == '\n') continue;
		dev = strtok_r(p, " \t\r\n", &p);
		mnt = strtok_r(NULL, " \t\r\n", &p);
		type = strtok_r(NULL, " \t\r\n", &p);
		opts = strtok_r(NULL, " \t\r\n", &p);
		flags = strtok_r(NULL, " \t\r\n", &p);
		if (dev && mnt) {
			printf("  %-30s %-16s %-8s %s %s\n", dev, mnt, type ? type : "", opts ? opts : "", flags ? flags : "");
		}
	}
	fclose(fp);
	return 0;
}

static int fstab_patch(const char *file, const char *target_mnt, const char *old_opt, const char *new_opt) {
	FILE *fp;
	char line[4096];
	char out_path[PATH_MAX];
	FILE *out_fp;
	int count = 0;

	fp = fopen(file, "r");
	if (!fp) {
		bb_perror_msg("cannot open '%s'", file);
		return 1;
	}
	snprintf(out_path, sizeof(out_path), "%s.tmp.%d", file, (int)getpid());
	out_fp = fopen(out_path, "w");
	if (!out_fp) {
		fclose(fp);
		bb_perror_msg("cannot create '%s'", out_path);
		return 1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char orig_line[4096];
		char *p = line;
		char *dev, *mnt;
		strcpy(orig_line, line);

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\0' || *p == '\n') {
			fputs(orig_line, out_fp);
			continue;
		}

		dev = strtok_r(p, " \t\r\n", &p);
		mnt = strtok_r(NULL, " \t\r\n", &p);

		if (dev && mnt && strcmp(mnt, target_mnt) == 0 && old_opt && old_opt[0]) {
			char *pos = strstr(orig_line, old_opt);
			if (pos) {
				size_t prefix_len = pos - orig_line;
				size_t old_len = strlen(old_opt);
				fwrite(orig_line, 1, prefix_len, out_fp);
				if (new_opt && new_opt[0] && strcmp(new_opt, "-") != 0 && strcmp(new_opt, "none") != 0) {
					fputs(new_opt, out_fp);
				}
				fputs(pos + old_len, out_fp);
				count++;
				printf("[+] Patched %s on '%s': '%s' -> '%s'\n", target_mnt, file, old_opt, new_opt ? new_opt : "");
				continue;
			}
		}
		fputs(orig_line, out_fp);
	}
	fclose(fp);
	fclose(out_fp);

	if (count > 0) {
		rename(out_path, file);
		printf("[✓] SUCCESS: Modified %d entry in '%s'\n", count, file);
		return 0;
	} else {
		unlink(out_path);
		printf("[-] Notice: Target '%s' with option '%s' not found in '%s'\n", target_mnt, old_opt, file);
		return 0;
	}
}

static int magiskboot_fstab_op(int argc, char **argv) {
	const char *file;
	const char *action;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot fstab <file> <print|patch <mountpoint> <old_opt> [new_opt]>");
		return 1;
	}

	file = argv[2];
	action = argv[3];

	if (strcmp(action, "print") == 0 || strcmp(action, "show") == 0) {
		return fstab_print(file);
	}
	if (strcmp(action, "patch") == 0) {
		if (argc < 6) {
			bb_error_msg("usage: magiskboot fstab <file> patch <mountpoint> <old_opt> [new_opt]");
			return 1;
		}
		return fstab_patch(file, argv[4], argv[5], (argc >= 7) ? argv[6] : "");
	}

	bb_error_msg("unknown fstab action '%s'", action);
	return 1;
}

static int cmdline_print(const char *file) {
	int fd;
	struct stat st;
	char *buf;
	char *tok, *saveptr;

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		bb_perror_msg("cannot open '%s'", file);
		if (fd >= 0) close(fd);
		return 1;
	}
	buf = xmalloc(st.st_size + 1);
	if (full_read(fd, buf, st.st_size) != st.st_size) {
		close(fd); free(buf); return 1;
	}
	close(fd);
	buf[st.st_size] = '\0';
	while (st.st_size > 0 && (buf[st.st_size - 1] == '\n' || buf[st.st_size - 1] == '\r')) {
		buf[--st.st_size] = '\0';
	}
	printf("======================================================================\n");
	printf("  Kernel Command Line Inspector: %s\n", file);
	printf("======================================================================\n");
	tok = strtok_r(buf, " \t\r\n", &saveptr);
	while (tok) {
		printf("  • %s\n", tok);
		tok = strtok_r(NULL, " \t\r\n", &saveptr);
	}
	printf("======================================================================\n");
	free(buf);
	return 0;
}

static int cmdline_modify(const char *file, const char *action, const char *key, const char *val) {
	int fd;
	struct stat st;
	char *buf;
	char **tokens;
	size_t cap = 128, count = 0;
	char *tok, *saveptr;
	bool modified = false;
	size_t i;
	FILE *ofp;
	bool first;

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		bb_perror_msg("cannot open '%s'", file);
		if (fd >= 0) close(fd);
		return 1;
	}
	buf = xmalloc(st.st_size + 1);
	if (full_read(fd, buf, st.st_size) != st.st_size) {
		close(fd); free(buf); return 1;
	}
	close(fd);
	buf[st.st_size] = '\0';

	tokens = xmalloc(cap * sizeof(char *));
	tok = strtok_r(buf, " \t\r\n", &saveptr);
	while (tok) {
		if (count >= cap) {
			cap *= 2;
			tokens = xrealloc(tokens, cap * sizeof(char *));
		}
		tokens[count++] = xstrdup(tok);
		tok = strtok_r(NULL, " \t\r\n", &saveptr);
	}
	free(buf);

	if (strcmp(action, "add") == 0) {
		bool found = false;
		for (i = 0; i < count; i++) {
			if (strcmp(tokens[i], key) == 0) { found = true; break; }
		}
		if (!found) {
			if (count >= cap) { cap += 16; tokens = xrealloc(tokens, cap * sizeof(char *)); }
			tokens[count++] = xstrdup(key);
			modified = true;
			printf("[+] Appended cmdline option: '%s'\n", key);
		}
	} else if (strcmp(action, "rm") == 0 || strcmp(action, "del") == 0) {
		size_t klen = strlen(key);
		for (i = 0; i < count; i++) {
			if (strcmp(tokens[i], key) == 0 || (strncmp(tokens[i], key, klen) == 0 && tokens[i][klen] == '=')) {
				free(tokens[i]);
				tokens[i] = NULL;
				modified = true;
				printf("[+] Removed cmdline parameter: '%s'\n", key);
			}
		}
	} else if (strcmp(action, "patch") == 0 || strcmp(action, "set") == 0) {
		size_t klen = strlen(key);
		bool found = false;
		for (i = 0; i < count; i++) {
			if (strcmp(tokens[i], key) == 0 || (strncmp(tokens[i], key, klen) == 0 && tokens[i][klen] == '=')) {
				free(tokens[i]);
				tokens[i] = xasprintf("%s=%s", key, val ? val : "");
				found = true;
				modified = true;
				printf("[+] Patched cmdline parameter: '%s=%s'\n", key, val ? val : "");
			}
		}
		if (!found && val) {
			if (count >= cap) { cap += 16; tokens = xrealloc(tokens, cap * sizeof(char *)); }
			tokens[count++] = xasprintf("%s=%s", key, val);
			modified = true;
			printf("[+] Added new cmdline parameter: '%s=%s'\n", key, val);
		}
	}

	if (!modified) {
		printf("[-] Notice: cmdline not modified\n");
		for (i = 0; i < count; i++) if (tokens[i]) free(tokens[i]);
		free(tokens);
		return 0;
	}

	ofp = fopen(file, "w");
	if (!ofp) {
		bb_perror_msg("cannot write '%s'", file);
		for (i = 0; i < count; i++) if (tokens[i]) free(tokens[i]);
		free(tokens);
		return 1;
	}

	first = true;
	for (i = 0; i < count; i++) {
		if (tokens[i]) {
			if (!first) fputc(' ', ofp);
			fputs(tokens[i], ofp);
			first = false;
			free(tokens[i]);
		}
	}
	fputc('\n', ofp);
	fclose(ofp);
	free(tokens);
	printf("[✓] SUCCESS: Updated kernel command line '%s'\n", file);
	return 0;
}

static int magiskboot_cmdline_op(int argc, char **argv) {
	const char *file;
	const char *action;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot cmdline <file> <print|patch <key> <val>|add <opt>|rm <key>>");
		return 1;
	}

	file = argv[2];
	action = argv[3];

	if (strcmp(action, "print") == 0 || strcmp(action, "show") == 0) {
		return cmdline_print(file);
	}
	if (strcmp(action, "patch") == 0 || strcmp(action, "set") == 0) {
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> patch <key> [val]");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], (argc >= 6) ? argv[5] : "");
	}
	if (strcmp(action, "add") == 0) {
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> add <option>");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], NULL);
	}
	if (strcmp(action, "rm") == 0 || strcmp(action, "del") == 0) {
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> rm <key>");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], NULL);
	}

	bb_error_msg("unknown cmdline action '%s'", action);
	return 1;
}

/* =========================================================================
 * 14. AVB 2.0 VBMeta Inspector & dm-verity Neutralizer
 * ========================================================================= */

static int magiskboot_vbmeta_op(int argc, char **argv) {
	const char *target;
	const char *action = "status";
	int fd;
	struct stat st;
	uint8_t *map;
	size_t map_sz;
	off_t vbmeta_off = 0;
	bool found = false;
	struct avb_vbmeta_image_header *hdr;
	uint32_t flags;

	if (argc < 3) {
		bb_error_msg("usage: magiskboot vbmeta <image|block_device> [status|disable|restore]");
		return 1;
	}

	target = argv[2];
	if (argc >= 4) action = argv[3];

	fd = open(target, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (strcmp(action, "status") == 0 || strcmp(action, "print") == 0) {
			fd = open(target, O_RDONLY | O_CLOEXEC);
		}
		if (fd < 0) {
			bb_perror_msg("cannot open '%s'", target);
			return 1;
		}
	}

	if (fstat(fd, &st) < 0) {
		bb_perror_msg("cannot stat '%s'", target);
		close(fd);
		return 1;
	}

	map_sz = (size_t)st.st_size;
	if (map_sz == 0) {
		off_t blk_sz = lseek(fd, 0, SEEK_END);
		if (blk_sz > 0) map_sz = (size_t)blk_sz;
		lseek(fd, 0, SEEK_SET);
	}

	if (map_sz < sizeof(struct avb_vbmeta_image_header)) {
		bb_error_msg("'%s' is too small for AVB VBMeta structure", target);
		close(fd);
		return 1;
	}

	if (map_sz > 16 * 1024 * 1024) map_sz = 16 * 1024 * 1024;

	map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		map = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		if (map == MAP_FAILED) {
			bb_perror_msg("failed to mmap '%s'", target);
			close(fd);
			return 1;
		}
	}

	if (memcmp(map, AVB_MAGIC, AVB_MAGIC_LEN) == 0) {
		vbmeta_off = 0;
		found = true;
	}

	if (!found && map_sz >= sizeof(struct avb_footer)) {
		struct avb_footer *footer = (struct avb_footer *)(map + map_sz - sizeof(struct avb_footer));
		if (memcmp(footer->magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0) {
			uint64_t voff = __builtin_bswap64(footer->vbmeta_offset);
			if (voff + sizeof(struct avb_vbmeta_image_header) <= map_sz &&
			    memcmp(map + voff, AVB_MAGIC, AVB_MAGIC_LEN) == 0) {
				vbmeta_off = (off_t)voff;
				found = true;
			}
		}
	}

	if (!found) {
		size_t scan_limit = (map_sz > 1048576) ? 1048576 : map_sz;
		size_t i;
		for (i = 0; i + sizeof(struct avb_vbmeta_image_header) <= scan_limit; i += 64) {
			if (memcmp(map + i, AVB_MAGIC, AVB_MAGIC_LEN) == 0) {
				vbmeta_off = (off_t)i;
				found = true;
				break;
			}
		}
	}

	if (!found) {
		bb_error_msg("no valid AVB 2.0 VBMeta header ('AVB0') found in '%s'", target);
		munmap(map, map_sz);
		close(fd);
		return 1;
	}

	hdr = (struct avb_vbmeta_image_header *)(map + vbmeta_off);
	flags = __builtin_bswap32(hdr->flags);

	if (strcmp(action, "status") == 0 || strcmp(action, "print") == 0 || strcmp(action, "show") == 0) {
		printf("======================================================================\n");
		printf("  AVB 2.0 VBMeta Inspector: %s (Offset 0x%lx)\n", target, (unsigned long)vbmeta_off);
		printf("======================================================================\n");
		printf("  Magic:                  %.4s\n", hdr->magic);
		printf("  Libavb Version:         %u.%u\n",
		       __builtin_bswap32(hdr->required_libavb_version_major),
		       __builtin_bswap32(hdr->required_libavb_version_minor));
		printf("  Release String:         %.64s\n", hdr->release_string);
		printf("  Rollback Index:         %llu\n", (unsigned long long)__builtin_bswap64(hdr->rollback_index));
		printf("  Flags:                  0x%08x\n", flags);
		printf("  dm-verity (Hashtree):   %s\n",
		       (flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED) ? "DISABLED [✓]" : "ENABLED [! VERIFIED]");
		printf("  Verification (AVB):     %s\n",
		       (flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED) ? "DISABLED [✓]" : "ENABLED [! ENFORCED]");
		printf("======================================================================\n");
		munmap(map, map_sz);
		close(fd);
		return 0;
	}

	if (strcmp(action, "disable") == 0 || strcmp(action, "disable-verity") == 0 ||
	    strcmp(action, "disable-verification") == 0 || strcmp(action, "patch") == 0) {
		uint32_t new_flags = flags | AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED;
		if (flags != new_flags) {
			hdr->flags = __builtin_bswap32(new_flags);
			msync(map, map_sz, MS_SYNC);
			lseek(fd, vbmeta_off, SEEK_SET);
			full_write(fd, hdr, sizeof(*hdr));
			printf("[✓] SUCCESS: Neutralized AVB dm-verity & verification on '%s' (flags: 0x%08x -> 0x%08x)\n",
			       target, flags, new_flags);
		} else {
			printf("[-] Notice: AVB dm-verity and verification already disabled on '%s' (flags: 0x%08x)\n",
			       target, flags);
		}
	} else if (strcmp(action, "restore") == 0 || strcmp(action, "enable") == 0) {
		uint32_t new_flags = flags & ~(AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
		if (flags != new_flags) {
			hdr->flags = __builtin_bswap32(new_flags);
			msync(map, map_sz, MS_SYNC);
			lseek(fd, vbmeta_off, SEEK_SET);
			full_write(fd, hdr, sizeof(*hdr));
			printf("[✓] SUCCESS: Restored AVB verification enforcement on '%s' (flags: 0x%08x -> 0x%08x)\n",
			       target, flags, new_flags);
		} else {
			printf("[-] Notice: AVB verification already enabled on '%s' (flags: 0x%08x)\n", target, flags);
		}
	} else {
		bb_error_msg("unknown vbmeta action '%s' (supported: status, disable, restore)", action);
		munmap(map, map_sz);
		close(fd);
		return 1;
	}

	munmap(map, map_sz);
	close(fd);
	return 0;
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

	if (strcmp(cmd, "init") == 0) {
		const char *img;
		const char *act;
		const char *arg1 = NULL;
		const char *arg2 = NULL;
		int idx = 2;

		if (argc < 4) bb_show_usage();
		img = argv[idx++];
		act = argv[idx++];
		if (idx < argc) arg1 = argv[idx++];
		if (idx < argc) arg2 = argv[idx++];
		return magiskboot_init_op(img, act, arg1, arg2);
	}

	if (strcmp(cmd, "kernel") == 0) {
		if (argc < 4) bb_show_usage();
		return magiskboot_kernel_op(argv[2], argv[3], argc, argv);
	}

	if (strcmp(cmd, "de-enforce") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "de-enforce", argc, argv);
	}

	if (strcmp(cmd, "patch-sigenforce") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "sigenforce", argc, argv);
	}

	if (strcmp(cmd, "patch-cfi") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "cfi", argc, argv);
	}

	if (strcmp(cmd, "module") == 0 || strcmp(cmd, "mod") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_module_op(argc, argv);
	}

	if (strcmp(cmd, "patch-vermagic") == 0 || strcmp(cmd, "vermagic") == 0) {
		if (argc < 3) bb_show_usage();
		return magiskboot_patch_vermagic_op(argc, argv);
	}

	if (strcmp(cmd, "mod-info") == 0) {
		if (argc < 3) bb_show_usage();
		return module_info_file(argv[2]);
	}

	if (strcmp(cmd, "mod-check") == 0) {
		if (argc < 3) bb_show_usage();
		return module_check_file(argv[2]);
	}

	if (strcmp(cmd, "mod-audit") == 0) {
		int fd;
		struct stat st;
		uint8_t *map;
		struct elf_ctx ctx;
		int res;
		if (argc < 3) bb_show_usage();
		fd = open(argv[2], O_RDONLY | O_CLOEXEC);
		if (fd < 0 || fstat(fd, &st) < 0) { bb_perror_msg("cannot open '%s'", argv[2]); if (fd >= 0) close(fd); return 1; }
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;
		if (!elf_init_ctx(&ctx, map, st.st_size)) { munmap(map, st.st_size); return 1; }
		res = audit_module_symbols(&ctx, (argc >= 4) ? argv[3] : NULL);
		munmap(map, st.st_size);
		return res;
	}

	if (strcmp(cmd, "mod-strip") == 0) {
		if (argc < 3) bb_show_usage();
		return module_strip_file(argv[2], (argc >= 4) ? argv[3] : NULL);
	}

	if (strcmp(cmd, "mod-load") == 0) {
		if (argc < 3) bb_show_usage();
		return module_load_file(argv[2], (argc >= 4) ? argv[3] : "");
	}

	if (strcmp(cmd, "mod-unload") == 0) {
		return module_unload_name((argc >= 3) ? argv[2] : "kroot");
	}

	if (strcmp(cmd, "dist") == 0 || strcmp(cmd, "anykernel") == 0 ||
	    strcmp(cmd, "package-kernel") == 0 || strcmp(cmd, "package-zip") == 0) {
		return magiskboot_dist_op(argc, argv);
	}

	if (strcmp(cmd, "zip") == 0) {
		return magiskboot_zip_op(argc, argv);
	}

	if (strcmp(cmd, "fstab") == 0) {
		return magiskboot_fstab_op(argc, argv);
	}

	if (strcmp(cmd, "cmdline") == 0) {
		return magiskboot_cmdline_op(argc, argv);
	}

	if (strcmp(cmd, "vbmeta") == 0) {
		return magiskboot_vbmeta_op(argc, argv);
	}

	if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
		bb_show_usage();
	}

	bb_error_msg("unknown command '%s'", cmd);
	bb_show_usage();
	return 1;
}
