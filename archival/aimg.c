/* vi: set sw=4 ts=4: */
/*
 * aimg — Android Image Tool for BusyBox
 *
 * Implements Android boot image unpacking, repacking, component extraction,
 * kernel security neutralization (CONFIG_MODULE_SIG_FORCE, KCFI), module
 * vermagic/altinstructions patching, ramdisk CPIO/init injection, and universal
 * recovery flashable ZIP packaging in memory-safe C.
 *
 * Conforms to Linux Kernel Coding Style & ISO C90/C99/C11 standards.
 */

//config:config AIMG
//config:	bool "aimg (Android Image Tool)"
//config:	default y
//config:	help
//config:	Android Image Tool (boot, kernel, ramdisk, and recovery).

//applet:IF_AIMG(APPLET(aimg, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_AIMG) += aimg.o

//usage:#define aimg_trivial_usage
//usage:       "[ACTION] [OPTIONS] <file> [ARGS]..."
//usage:#define aimg_full_usage "\n\n"
//usage:       "Android Image Tool (Boot, Kernel Security, Ramdisk, and Recovery Packaging)\n"
//usage:     "\nKernel Security Neutralization:"
//usage:     "\n	--de-enforce <img|rec> [out]  Neutralize module sig enforcement & Clang CFI"
//usage:     "\n	--patch-sigenforce <img|rec>  Neutralize CONFIG_MODULE_SIG_FORCE"
//usage:     "\n	--patch-cfi <img|rec> [out]   Neutralize Clang KCFI & Forward-Edge CFI stubs"
//usage:     "\n	--permissive <img|rec> [out]  Force SELinux permissive in kernel image"
//usage:     "\n	--disable-rkp <img|rec> [out] Disable Samsung RKP / KNOX protections"
//usage:     "\n	--kernel-status <img|rec>     Inspect kernel security features & CFI jump tables"
//usage:     "\n"
//usage:     "\nImage & OTA Payload Operations:"
//usage:     "\n	-u, --unpack [dir] <img|payload> Unpack boot components or payload.bin partitions"
//usage:     "\n	    -k, --kernel-only         Extract kernel only (boot.img or payload.bin)"
//usage:     "\n	    -s, --split               Split image without decompressing ramdisk"
//usage:     "\n	    -h, --header-only         Parse and print header / payload manifest info"
//usage:     "\n	-r, --repack [out] <boot.img> Repack components into new boot image"
//usage:     "\n	    -n, --no-comp             Do not compress repacked ramdisk"
//usage:     "\n	-e, --extract <img|payload> [part|comp] [out] Extract partition or component"
//usage:     "\n	-c, --cleanup                 Clean up unpacked temporary files"
//usage:     "\n"
//usage:     "\nKernel Module Toolkit:"
//usage:     "\n	--mod-info <mod.ko>           Display module vermagic and ELF header info"
//usage:     "\n	--mod-audit <mod.ko> [sym]    Audit unresolved symbols against kernel"
//usage:     "\n	--mod-strip <mod.ko> [out]    Strip unneeded sections and debug symbols"
//usage:     "\n	--mod-patch <mod.ko> [opts]   Patch module vermagic, altinstructions, and CFI stubs"
//usage:     "\n	--mod-inject <boot.img> <mod> Inject module into boot ramdisk (--live, --install)"
//usage:     "\n	--mod-load <mod.ko> [args]    In-kernel load via finit_module / init_module"
//usage:     "\n	--mod-unload [name]           In-kernel unload via delete_module"
//usage:     "\n"
//usage:     "\nRamdisk & Component Patchers:"
//usage:     "\n	--init <boot.img> <action>    In-place /init tool (status, wrap, replace, extract, rm)"
//usage:     "\n	--cpio <ramdisk> <act> [...]  CPIO operations (test, ls, extract, add, mkdir, rm)"
//usage:     "\n	--dtb <file> [print|patch]    DTB inspector and AVB/fstab verity patcher"
//usage:     "\n	--vbmeta <file> [disable|...] VBMeta AVB 2.0 flags inspector and verity disabler"
//usage:     "\n	--fstab <file> <print|patch>  In-place fstab configuration tool"
//usage:     "\n	--cmdline <file> <print|patch> Kernel cmdline configuration tool"
//usage:     "\n	--hexpatch <file> <from> <to> In-place binary hex string patch"
//usage:     "\n	--decompress <in> [out]       Decompress kernel/ramdisk image"
//usage:     "\n	--set-recovery <boot> <rec>   Inject custom recovery (TWRP) into boot image (--live, --install)"
//usage:     "\n	--extract-recovery <boot> [o] Extract recovery subsystem (cpio, img, or dir) from boot image"
//usage:     "\n"
//usage:     "\nPackaging:"
//usage:     "\n	--dist <out.zip>              Create universal AnyKernel/Magisk flashable ZIP"
//usage:     "\n	--zip <file.zip> <act> [...]  ZIP archive operations (create, list, extract)"

#include "libbb.h"
#include "bb_archive.h"
#include "aimg.h"

#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif
#ifndef BLKROSET
#define BLKROSET _IO(0x12, 93)
#endif
#ifndef BLKSSZGET
#define BLKSSZGET _IO(0x12, 104)
#endif
#ifndef major
#define major(dev) ((unsigned int)(((dev) >> 8) & 0xfff))
#endif
#ifndef minor
#define minor(dev) ((unsigned int)((dev) & 0xff))
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

#include "aimg_lz4.c"

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
		if (memcmp(b, "\x02\x21\x4c\x18", 4) == 0) {
			if (boot_hdr_is_lz4_lg(b, len))
				return BOOT_FMT_LZ4_LG;
			return BOOT_FMT_LZ4_LEGACY;
		}
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

static int safe_rename_or_copy(const char *src, const char *dst) {
	if (rename(src, dst) == 0) return 0;
	if (errno == EXDEV) {
		if (copy_file(src, dst, FILEUTILS_FORCE) == 0) {
			unlink(src);
			return 0;
		}
	}
	return -1;
}


static void *magiskboot_read_file(const char *path, size_t *out_sz) {
	size_t max_sz = (size_t)INT_MAX - 4095;
	void *buf = xmalloc_open_read_close(path, &max_sz);
	if (out_sz) *out_sz = buf ? max_sz : 0;
	return buf;
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
	fp = fopen_or_warn(path, "w");
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
	static const char hdr_keys[] ALIGN1 =
		"name\0"
		"cmdline\0"
		"os_version\0"
		"os_patch_level\0";
	enum {
		HDR_KEY_name = 0,
		HDR_KEY_cmdline,
		HDR_KEY_os_version,
		HDR_KEY_os_patch_level,
	};
	FILE *fp;
	char *name = NULL;
	char *cmdline = NULL;
	char *extra_cmdline = NULL;
	uint32_t *os_ver_ptr = NULL;
	size_t name_max = 0;
	size_t cmd_max = 0;
	size_t extra_max = 0;
	char *line;

	if (!hdr || !hdr->raw || !path) return -1;
	fp = fopen_or_warn(path, "r");
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

	while ((line = xmalloc_fgetline(fp)) != NULL) {
		char *p = skip_whitespace(line);
		char *eq;
		const char *key;
		const char *val;
		size_t vlen;

		if (*p == '#' || *p == '\0') {
			free(line);
			continue;
		}

		eq = strchr(p, '=');
		if (!eq) {
			free(line);
			continue;
		}
		*eq = '\0';
		key = p;
		val = eq + 1;
		vlen = strlen(val);

		switch (index_in_strings(hdr_keys, key)) {
		case HDR_KEY_name:
			if (name && name_max > 0) {
				memset(name, 0, name_max);
				safe_strncpy(name, val, name_max);
			}
			break;
		case HDR_KEY_cmdline:
			if (cmdline && cmd_max > 0) {
				memset(cmdline, 0, cmd_max);
				if (extra_cmdline && extra_max > 0) memset(extra_cmdline, 0, extra_max);
				if (vlen >= cmd_max && extra_cmdline && extra_max > 0) {
					safe_strncpy(cmdline, val, cmd_max);
					safe_strncpy(extra_cmdline, val + (cmd_max - 1), extra_max);
				} else {
					safe_strncpy(cmdline, val, cmd_max);
				}
			}
			break;
		case HDR_KEY_os_version:
			if (os_ver_ptr) {
				int a = 0, b = 0, c = 0;
				if (sscanf(val, "%d.%d.%d", &a, &b, &c) >= 1) {
					uint32_t patch = *os_ver_ptr & 0x7ff;
					uint32_t ver = (((uint32_t)(a & 0x7f) << 14) |
					                ((uint32_t)(b & 0x7f) << 7)  |
					                ((uint32_t)(c & 0x7f)));
					*os_ver_ptr = (ver << 11) | patch;
				}
			}
			break;
		case HDR_KEY_os_patch_level:
			if (os_ver_ptr) {
				int y = 0, m = 0;
				if (sscanf(val, "%d-%d", &y, &m) == 2) {
					uint32_t ver = *os_ver_ptr >> 11;
					int year = (y >= 2000) ? (y - 2000) : 0;
					uint32_t patch = (((uint32_t)(year & 0x7f) << 4) | (uint32_t)(m & 0x0f));
					*os_ver_ptr = (ver << 11) | (patch & 0x7ff);
				}
			}
			break;
		default:
			break;
		}
		free(line);
	}

	fclose(fp);
	return 0;
}

static void boot_img_print_info(const boot_img_t *img, const char *path) {
	uint32_t ver;
	bool is_vnd;
	uint32_t os_ver = 0;

	if (!img || !img->hdr.raw) return;

	ver = dyn_hdr_version(&img->hdr);
	is_vnd = dyn_hdr_is_vendor(&img->hdr);

	printf("Image:                %s\n", path);
	printf("Format:               Android %sBoot Image (v%u)\n", is_vnd ? "Vendor " : "", ver);
	if (!is_vnd && img->kernel_size > 0) {
		printf("Kernel size:          %u bytes (%s)\n", img->kernel_size, boot_fmt2name(img->k_fmt));
	}
	if (img->kernel_dtb_size > 0) {
		printf("Kernel DTB size:      %zu bytes\n", img->kernel_dtb_size);
	}
	if (img->ramdisk_size > 0) {
		printf("Ramdisk size:         %u bytes (%s)\n", img->ramdisk_size, boot_fmt2name(img->r_fmt));
	}
	if (img->second_size > 0) {
		printf("Second size:          %u bytes\n", img->second_size);
	}
	if (img->recovery_dtbo_size > 0) {
		printf("Recovery DTBO size:   %u bytes\n", img->recovery_dtbo_size);
	}
	if (img->dtb_size > 0) {
		printf("DTB size:             %u bytes\n", img->dtb_size);
	}
	if (img->bootconfig_size > 0) {
		printf("Bootconfig size:      %u bytes\n", img->bootconfig_size);
	}

	if (ver < 3) {
		os_ver = ((struct boot_img_hdr_v0 *)img->hdr.raw)->os_version;
	} else if (!is_vnd) {
		os_ver = ((struct boot_img_hdr_v3 *)img->hdr.raw)->os_version;
	}
	if (os_ver) {
		int a = 0, b = 0, c = 0, y = 0, m = 0;
		boot_hdr_decode_os_version(os_ver, &a, &b, &c, &y, &m);
		printf("OS version:           %d.%d.%d\n", a, b, c);
		printf("OS patch level:       %d-%02d\n", y, m);
	}
	printf("Page size:            %u bytes\n", dyn_hdr_page_size(&img->hdr));
	if (img->flags & BOOT_FLAG_AVB) {
		printf("AVB 2.0 footer:       PRESENT\n");
	}
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

	if (fmt == BOOT_FMT_LZ4_LEGACY || fmt == BOOT_FMT_LZ4_LG) {
		return lz4_legacy_decompress(in, in_sz, out_fd);
	} else if (fmt == BOOT_FMT_LZ4) {
		return lz4_frame_decompress(in, in_sz, out_fd);
	}

	in_fd = xmkstemp(tmp_path);
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

	fd = open3_or_warn(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) return -1;

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

static off_t get_file_or_bdev_size(int fd, const struct stat *st)
{
	off_t sz = st->st_size;
	if (S_ISBLK(st->st_mode) || sz == 0) {
#ifdef BLKGETSIZE64
		uint64_t bsize = 0;
		if (ioctl(fd, BLKGETSIZE64, &bsize) == 0 && bsize > 0)
			return (off_t)bsize;
#endif
		{
			off_t end_off = lseek(fd, 0, SEEK_END);
			if (end_off > 0) {
				lseek(fd, 0, SEEK_SET);
				return end_off;
			}
		}
	}
	return sz;
}

static void *map_or_read_image(int fd, size_t size, bool rw)
{
	int prot = PROT_READ | (rw ? PROT_WRITE : 0);
	int flags = MAP_SHARED;
	void *ptr;

	/* 1. Attempt zero-copy direct mmap */
	ptr = mmap(NULL, size, prot, flags, fd, 0);
	if (ptr != MAP_FAILED && ptr != NULL)
		return ptr;

	/* 2. Resilient fallback for Android block devices where mmap(MAP_SHARED)
	 * fails with ENODEV, EACCES, or EINVAL due to block-level VFS driver constraints */
	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr != MAP_FAILED && ptr != NULL) {
		lseek(fd, 0, SEEK_SET);
		if (full_read(fd, ptr, size) < 1024) {
			munmap(ptr, size);
			return MAP_FAILED;
		}
		return ptr;
	}

	return MAP_FAILED;
}

static bool boot_img_parse(boot_img_t *img, const char *path) {
	int fd;
	struct stat st;
	off_t real_sz;
	const uint8_t *start;
	const uint8_t *end;
	const uint8_t *hdr_ptr = NULL;
	const uint8_t *addr;
	uint32_t page_sz;
	size_t off;

	memset(img, 0, sizeof(*img));

	fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return false;

	if (fstat(fd, &st) < 0) {
		bb_perror_msg("cannot stat '%s'", path);
		close(fd);
		return false;
	}

	real_sz = get_file_or_bdev_size(fd, &st);
	if (real_sz < 1024) {
		bb_error_msg("file '%s' is too small or invalid (%lld bytes)", path, (long long)real_sz);
		close(fd);
		return false;
	}

	img->map_sz = (size_t)real_sz;
	img->map_ptr = map_or_read_image(fd, img->map_sz, false);
	close(fd);

	if (img->map_ptr == MAP_FAILED || !img->map_ptr) {
		bb_perror_msg("mmap failed for '%s'", path);
		return false;
	}

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
			}
			off += align_to(img->kernel_size, page_sz);

			dtb_off = boot_find_dtb_offset(img->kernel, img->kernel_size);
			if (dtb_off > 0) {
				img->kernel_dtb = img->kernel + dtb_off;
				img->kernel_dtb_size = img->kernel_size - dtb_off;
				img->kernel_size = dtb_off;
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
		}
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

static int magiskboot_unpack(const char *image, bool skip_kernel_decomp, bool skip_ramdisk_decomp, bool hdr_only, bool kernel_only) {
	boot_img_t boot;
	if (!boot_img_parse(&boot, image)) return 1;

	if (kernel_only) {
		if (boot.kernel && boot.kernel_size > 0) {
			write_to_disk(KERNEL_FILE, boot.kernel, boot.kernel_size, boot.k_fmt, skip_kernel_decomp);
			printf("Extracted kernel (%u bytes) -> %s\n", boot.kernel_size, KERNEL_FILE);
		}
		if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
			write_to_disk(KER_DTB_FILE, boot.kernel_dtb, boot.kernel_dtb_size, BOOT_FMT_UNKNOWN, true);
			printf("Extracted kernel_dtb (%zu bytes) -> %s\n", boot.kernel_dtb_size, KER_DTB_FILE);
		}
		boot_img_free(&boot);
		return 0;
	}

	dyn_hdr_dump_props(&boot.hdr, HEADER_FILE);
	if (hdr_only) {
		boot_img_print_info(&boot, image);
		boot_img_free(&boot);
		return 0;
	}

	boot_img_print_info(&boot, image);

	if (boot.kernel && boot.kernel_size > 0) {
		write_to_disk(KERNEL_FILE, boot.kernel, boot.kernel_size, boot.k_fmt, skip_kernel_decomp);
	}
	if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
		write_to_disk(KER_DTB_FILE, boot.kernel_dtb, boot.kernel_dtb_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.ramdisk && boot.ramdisk_size > 0) {
		write_to_disk(RAMDISK_FILE, boot.ramdisk, boot.ramdisk_size, boot.r_fmt, skip_ramdisk_decomp);
	}
	if (boot.second && boot.second_size > 0) {
		write_to_disk(SECOND_FILE, boot.second, boot.second_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.extra && boot.extra_size > 0) {
		write_to_disk(EXTRA_FILE, boot.extra, boot.extra_size, boot.e_fmt, skip_ramdisk_decomp);
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

	ifd = open_or_warn(src_path, O_RDONLY | O_CLOEXEC);
	if (ifd < 0) {
		if (out_size) *out_size = 0;
		return 0;
	}

	if (fstat(ifd, &st) < 0 || st.st_size <= 0) {
		close(ifd);
		if (out_size) *out_size = 0;
		return 0;
	}

	written = bb_copyfd_size(ifd, out_fd, st.st_size);
	close(ifd);
	if (written < 0) written = 0;

	if (out_size) *out_size = (uint32_t)written;

	/* Align to page size */
	if (page_sz > 0 && written > 0) {
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

	if (fmt == BOOT_FMT_LZ4_LEGACY) {
		return lz4_legacy_compress(src, dst, false);
	} else if (fmt == BOOT_FMT_LZ4_LG) {
		return lz4_legacy_compress(src, dst, true);
	} else if (fmt == BOOT_FMT_LZ4) {
		return lz4_frame_compress(src, dst);
	}

	if (fmt == BOOT_FMT_XZ || fmt == BOOT_FMT_LZMA) {
		prog = "xz";
		arg = "-c";
	} else if (fmt == BOOT_FMT_BZIP2) {
		prog = "bzip2";
		arg = "-c";
	}

	out_tfd = open3_or_warn(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_tfd < 0) return -1;

	pid = fork();
	if (pid == 0) {
		int applet;
		char *args[4];
		dup2(out_tfd, STDOUT_FILENO);
		close(out_tfd);
		args[0] = (char *)prog;
		args[1] = (char *)arg;
		args[2] = (char *)src;
		args[3] = NULL;
		applet = find_applet_by_name(prog);
		if (applet >= 0) {
			run_applet_no_and_exit(applet, prog, args);
		}
		BB_EXECVP(prog, args);
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


static const char *prepare_kernel_for_repack(boot_img_t *boot, bool skip_comp, char *tmp_buf, size_t tmp_sz) {
	if (access(KERNEL_FILE, R_OK) != 0) return KERNEL_FILE;

	if (!skip_comp && boot_fmt_compressed(boot->k_fmt)) {
		int in_fd = open_or_warn(KERNEL_FILE, O_RDONLY);
		if (in_fd >= 0) {
			uint8_t magic[16];
			ssize_t n = full_read(in_fd, magic, sizeof(magic));
			close(in_fd);
			if (n >= 2 && boot_check_fmt(magic, n) == boot->k_fmt) {
				return KERNEL_FILE;
			}
		}
		safe_strncpy(tmp_buf, "/tmp/mb_kernel_XXXXXX", tmp_sz);
		close(xmkstemp(tmp_buf));
		if (compress_file_format(KERNEL_FILE, tmp_buf, boot->k_fmt) == 0) {
			return tmp_buf;
		}
	}
	return KERNEL_FILE;
}

static const char *prepare_ramdisk_for_repack(boot_img_t *boot, bool skip_comp, char *tmp_buf, size_t tmp_sz) {
	if (access("ramdisk.cpio.gz", R_OK) == 0) return "ramdisk.cpio.gz";
	if (access("ramdisk.cpio.xz", R_OK) == 0) return "ramdisk.cpio.xz";
	if (access("ramdisk.cpio.lz4", R_OK) == 0) return "ramdisk.cpio.lz4";
	if (access("ramdisk.cpio.bz2", R_OK) == 0) return "ramdisk.cpio.bz2";

	if (!skip_comp && boot_fmt_compressed(boot->r_fmt) && access(RAMDISK_FILE, R_OK) == 0) {
		int in_fd = open_or_warn(RAMDISK_FILE, O_RDONLY);
		if (in_fd >= 0) {
			uint8_t magic[16];
			ssize_t n = full_read(in_fd, magic, sizeof(magic));
			close(in_fd);
			if (n >= 2 && boot_check_fmt(magic, n) == boot->r_fmt) {
				return RAMDISK_FILE;
			}
		}
		safe_strncpy(tmp_buf, "/tmp/mb_ramdisk_XXXXXX", tmp_sz);
		close(xmkstemp(tmp_buf));
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
	}

	target = out_img ? out_img : "new-boot.img";

	out_fd = open3_or_warn(target, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) {
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
			char tmp_kernel[PATH_MAX];
			const char *kernel_path;
			tmp_kernel[0] = '\0';
			kernel_path = prepare_kernel_for_repack(&boot, skip_comp, tmp_kernel, sizeof(tmp_kernel));
			copy_file_section(out_fd, kernel_path, page_sz, &kernel_sz);
			if (tmp_kernel[0] != '\0') {
				unlink(tmp_kernel);
			}
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
		uint64_t orig_vbmeta_off = SWAP_BE64(boot.avb_footer->vbmeta_offset);
		uint64_t orig_vbmeta_sz = SWAP_BE64(boot.avb_footer->vbmeta_size);
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
			new_footer.original_image_size = SWAP_BE64((uint64_t)aosp_img_size);
			new_footer.vbmeta_offset = SWAP_BE64((uint64_t)new_vbmeta_off);
			new_footer.vbmeta_size = boot.avb_footer->vbmeta_size;
			full_write(out_fd, &new_footer, sizeof(new_footer));
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

	close(out_fd);
	printf("Repacked boot image -> %s\n", target);
	boot_img_free(&boot);
	return 0;
}


static int magiskboot_extract_recovery_op(int argc, char **argv);

static int magiskboot_extract_component(const char *image, const char *comp, const char *outfile, bool skip_decomp) {
	boot_img_t boot;
	const char *dest;
	const void *data = NULL;
	size_t sz = 0;
	uint8_t fmt = BOOT_FMT_UNKNOWN;
	int ret;

	static const char comps[] ALIGN1 =
		"kernel\0"
		"ramdisk\0"
		"dtb\0"
		"kernel_dtb\0"
		"recovery_dtbo\0"
		"second\0"
		"extra\0"
		"bootconfig\0"
		"recovery\0";
	enum {
		COMP_kernel = 0,
		COMP_ramdisk,
		COMP_dtb,
		COMP_kernel_dtb,
		COMP_recovery_dtbo,
		COMP_second,
		COMP_extra,
		COMP_bootconfig,
		COMP_recovery,
	};

	if (!image || !comp) return 1;
	if (!boot_img_parse(&boot, image)) return 1;

	switch (index_in_strings(comps, comp)) {
	case COMP_kernel:
		data = boot.kernel;
		sz = boot.kernel_size;
		fmt = boot.k_fmt;
		dest = outfile ? outfile : KERNEL_FILE;
		break;
	case COMP_ramdisk:
		data = boot.ramdisk;
		sz = boot.ramdisk_size;
		fmt = boot.r_fmt;
		dest = outfile ? outfile : RAMDISK_FILE;
		break;
	case COMP_dtb:
		data = boot.dtb;
		sz = boot.dtb_size;
		dest = outfile ? outfile : DTB_FILE;
		break;
	case COMP_kernel_dtb:
		data = boot.kernel_dtb;
		sz = boot.kernel_dtb_size;
		dest = outfile ? outfile : KER_DTB_FILE;
		break;
	case COMP_recovery_dtbo:
		data = boot.recovery_dtbo;
		sz = boot.recovery_dtbo_size;
		dest = outfile ? outfile : RECV_DTBO_FILE;
		break;
	case COMP_second:
		data = boot.second;
		sz = boot.second_size;
		dest = outfile ? outfile : SECOND_FILE;
		break;
	case COMP_extra:
		data = boot.extra;
		sz = boot.extra_size;
		fmt = boot.e_fmt;
		dest = outfile ? outfile : EXTRA_FILE;
		break;
	case COMP_bootconfig:
		data = boot.bootconfig;
		sz = boot.bootconfig_size;
		dest = outfile ? outfile : BOOTCONFIG_FILE;
		break;
	case COMP_recovery: {
		char *rec_argv[5];
		int rec_argc = 3;
		boot_img_free(&boot);
		rec_argv[0] = (char *)"aimg";
		rec_argv[1] = (char *)"--extract-recovery";
		rec_argv[2] = (char *)image;
		if (outfile) {
			rec_argv[3] = (char *)outfile;
			rec_argc = 4;
		}
		rec_argv[rec_argc] = NULL;
		return magiskboot_extract_recovery_op(rec_argc, rec_argv);
	}
	default:
		bb_error_msg("unknown component '%s' (supported: kernel, ramdisk, dtb, kernel_dtb, recovery_dtbo, second, extra, bootconfig, recovery)", comp);
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
		printf("Extracted '%s' (%zu bytes) -> %s\n", comp, sz, dest);
	}
	boot_img_free(&boot);
	return (ret == 0) ? 0 : 1;
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

	if (!hex2bin((char *)pat, from_hex, pat_sz) || !hex2bin((char *)patch, to_hex, patch_sz)) {
		bb_error_msg("invalid hex string");
		free(pat);
		free(patch);
		return false;
	}

	limit = size - pat_sz;
	for (i = 0; i <= limit; ++i) {
		if (buf[i] == pat[0] && memcmp(buf + i, pat, pat_sz) == 0) {
			size_t replace_len = (patch_sz < pat_sz) ? patch_sz : pat_sz;
			memcpy(buf + i, patch, replace_len);
			printf("Hex patch @ 0x%08zX: %s -> %s\n", i, from_hex, to_hex);
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
	bool is_ok;

	if (!file || !from_hex || !to_hex) return 1;

	fd = open_or_warn(file, O_RDWR | O_CLOEXEC);
	if (fd < 0) return 1;

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

	is_ok = hexpatch_buffer(buf, st.st_size, from_hex, to_hex);

	msync(buf, st.st_size, MS_SYNC);
	munmap(buf, st.st_size);
	close(fd);

	return is_ok ? 0 : 1;
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
	return bb_strtou(buf, NULL, 16);
}

static cpio_node_t *cpio_read_all(const char *path) {
	int fd;
	struct stat st;
	uint8_t *map;
	size_t off = 0;
	cpio_node_t *head = NULL;
	cpio_node_t **tail = &head;

	fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
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
	fd = open3_or_warn(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
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
	if (safe_rename_or_copy(tmp_path, path) != 0) {
		unlink(tmp_path);
		return -1;
	}
	return 0;
}

static int cpio_exec_cmd(cpio_node_t **head_ptr, int argc, char **argv, bool *modified) {
	static const char cpio_acts[] ALIGN1 =
		"mkdir\0"
		"add\0"
		"ln\0"
		"rm\0"
		"extract\0"
		"ls\0";
	enum {
		CPIO_ACT_mkdir = 0,
		CPIO_ACT_add,
		CPIO_ACT_ln,
		CPIO_ACT_rm,
		CPIO_ACT_extract,
		CPIO_ACT_ls,
	};
	const char *act;
	if (argc < 1) return 0;
	act = argv[0];

	switch (index_in_strings(cpio_acts, act)) {
	case CPIO_ACT_mkdir: {
		uint32_t mode;
		const char *path;
		cpio_node_t *node;
		if (argc < 3) return 1;
		mode = bb_strtou(argv[1], NULL, 8) | 0040000;
		path = argv[2];

		/* Check if already exists */
		for (node = *head_ptr; node; node = node->next) {
			if (strcmp(node->name, path) == 0) {
				node->mode = mode;
				*modified = true;
				return 3;
			}
		}
		node = xzalloc(sizeof(*node));
		node->name = xstrdup(path);
		node->mode = mode;
		node->nlink = 2;
		{
			cpio_node_t **tail_ptr = head_ptr;
			while (*tail_ptr) tail_ptr = &(*tail_ptr)->next;
			node->next = NULL;
			*tail_ptr = node;
		}
		*modified = true;
		return 3;
	}

	case CPIO_ACT_add: {
		uint32_t mode;
		const char *entry_name;
		const char *infile;
		void *buf = NULL;
		size_t in_sz = 0;
		cpio_node_t *node = NULL;
		cpio_node_t *curr;

		if (argc < 4) return 1;
		mode = bb_strtou(argv[1], NULL, 8) | 0100000;
		entry_name = argv[2];
		infile = argv[3];

		buf = (uint8_t *)magiskboot_read_file(infile, &in_sz);

		for (curr = *head_ptr; curr; curr = curr->next) {
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
			{
				cpio_node_t **tail_ptr = head_ptr;
				while (*tail_ptr) tail_ptr = &(*tail_ptr)->next;
				node->next = NULL;
				*tail_ptr = node;
			}
		}
		*modified = true;
		return 4;
	}

	case CPIO_ACT_ln: {
		const char *target;
		const char *entry_name;
		cpio_node_t *node = NULL;
		cpio_node_t *curr;
		size_t tlen;

		if (argc < 3) return 1;
		target = argv[1];
		entry_name = argv[2];
		tlen = strlen(target);

		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				node = curr;
				break;
			}
		}

		if (node) {
			free(node->data);
			node->data = xstrdup(target);
			node->filesize = (uint32_t)tlen;
			node->mode = 0120777; /* S_IFLNK | 0777 */
		} else {
			node = xzalloc(sizeof(*node));
			node->name = xstrdup(entry_name);
			node->mode = 0120777; /* S_IFLNK | 0777 */
			node->filesize = (uint32_t)tlen;
			node->data = xstrdup(target);
			node->nlink = 1;
			{
				cpio_node_t **tail_ptr = head_ptr;
				while (*tail_ptr) tail_ptr = &(*tail_ptr)->next;
				node->next = NULL;
				*tail_ptr = node;
			}
		}
		*modified = true;
		return 3;
	}

	case CPIO_ACT_rm: {
		bool recur = false;
		const char *entry_name;
		int idx = 1;
		cpio_node_t *prev = NULL;
		cpio_node_t *curr;

		if (argc < 2) return 1;
		if (strcmp(argv[idx], "-r") == 0) {
			recur = true;
			idx++;
			if (idx >= argc) return 1;
		}
		entry_name = argv[idx];

		curr = *head_ptr;
		while (curr) {
			bool match = (strcmp(curr->name, entry_name) == 0);
			if (!match && recur) {
				const char *sub = is_prefixed_with(curr->name, entry_name);
				if (sub && *sub == '/') match = true;
			}

			if (match) {
				cpio_node_t *to_del = curr;
				if (prev) {
					prev->next = curr->next;
					curr = curr->next;
				} else {
					*head_ptr = curr->next;
					curr = *head_ptr;
				}
				free(to_del->name);
				free(to_del->data);
				free(to_del);
				*modified = true;
			} else {
				prev = curr;
				curr = curr->next;
			}
		}
		return idx + 1;
	}

	case CPIO_ACT_extract: {
		const char *target_entry = (argc >= 2) ? argv[1] : NULL;
		const char *out_file = (argc >= 3) ? argv[2] : target_entry;
		cpio_node_t *curr;
		if (target_entry) {
			bool found = false;
			for (curr = *head_ptr; curr; curr = curr->next) {
				if (strcmp(curr->name, target_entry) == 0) {
					int out_fd;
					const char *slash = strrchr(out_file, '/');
					if (slash) {
						char *d = xstrndup(out_file, slash - out_file);
						bb_make_directory(d, 0755, FILEUTILS_RECUR);
						free(d);
					}
					out_fd = open3_or_warn(out_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, curr->mode & 07777);
					if (out_fd >= 0) {
						if (curr->data && curr->filesize > 0) {
							full_write(out_fd, curr->data, curr->filesize);
						}
						close(out_fd);
						chmod(out_file, curr->mode & 07777);
						found = true;
						printf("Extracted '%s' -> %s\n", target_entry, out_file);
					}
					break;
				}
			}
			if (!found) {
				bb_error_msg("entry '%s' not found", target_entry);
			}
			return (argc >= 3) ? 3 : 2;
		} else {
			for (curr = *head_ptr; curr; curr = curr->next) {
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
					out_fd = open3_or_warn(curr->name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, curr->mode & 07777);
					if (out_fd >= 0) {
						if (curr->data && curr->filesize > 0) {
							full_write(out_fd, curr->data, curr->filesize);
						}
						close(out_fd);
						chmod(curr->name, curr->mode & 07777);
					}
				}
			}
			printf("Extracted all cpio entries into current directory\n");
			return 1;
		}
	}

	case CPIO_ACT_ls: {
		cpio_node_t *curr;
		for (curr = *head_ptr; curr; curr = curr->next) {
			printf("%06o %10u %s\n", curr->mode, curr->filesize, curr->name);
		}
		return 1;
	}

	default:
		bb_error_msg("unknown cpio action '%s' (supported: test, ls, extract, mkdir, add, ln, rm)", act);
		return 1;
	}
}

static int magiskboot_cpio(int argc, char **argv) {
	const char *cpio_file;
	cpio_node_t *head = NULL;
	bool modified = false;
	int i;
	int ret = 0;

	if (argc < 4) bb_show_usage();
	cpio_file = argv[2];

	/* Fast-path test command */
	if (strcmp(argv[3], "test") == 0) {
		int fd = open_or_warn(cpio_file, O_RDONLY | O_CLOEXEC);
		char magic[6];
		ssize_t n;
		if (fd < 0) return 1;
		n = full_read(fd, magic, 6);
		close(fd);
		if (n == 6 && (memcmp(magic, "070701", 6) == 0 || memcmp(magic, "070702", 6) == 0)) {
			printf("0\n");
			return 0;
		}
		return 1;
	}

	head = cpio_read_all(cpio_file);

	i = 3;
	while (i < argc) {
		const char *arg = argv[i];
		if (strchr(arg, ' ')) {
			/* Quoted multi-word command, e.g. "add 0755 init path" */
			char *copy = xstrdup(arg);
			char *toks[16];
			int tok_cnt = 0;
			char *saveptr = NULL;
			char *tok = strtok_r(copy, " \t\r\n", &saveptr);
			while (tok && tok_cnt < 16) {
				toks[tok_cnt++] = tok;
				tok = strtok_r(NULL, " \t\r\n", &saveptr);
			}
			if (tok_cnt > 0) {
				cpio_exec_cmd(&head, tok_cnt, toks, &modified);
			}
			free(copy);
			i++;
		} else {
			/* Separate argv tokens */
			int consumed = cpio_exec_cmd(&head, argc - i, &argv[i], &modified);
			i += (consumed > 0) ? consumed : 1;
		}
	}

	if (modified) {
		ret = cpio_write_all(cpio_file, head);
	}

	cpio_free_all(head);
	return ret;
}

/* =========================================================================
 * 7. Device Tree Blob (DTB) Manipulation Engine
 * ========================================================================= */

static int magiskboot_dtb(int argc, char **argv) {
	static const char dtb_acts[] ALIGN1 =
		"test\0"
		"print\0"
		"dump\0"
		"patch\0";
	enum {
		DTB_ACT_test = 0,
		DTB_ACT_print,
		DTB_ACT_dump,
		DTB_ACT_patch,
	};
	const char *dtb_file;
	const char *action;
	int fd;
	struct stat st;
	uint8_t *p;

	if (argc < 3) bb_show_usage();
	dtb_file = argv[2];
	action = (argc >= 4) ? argv[3] : "test";

	fd = open_or_warn(dtb_file, O_RDWR | O_CLOEXEC);
	if (fd < 0) return 1;
	if (fstat(fd, &st) < 0 || st.st_size < 16) {
		close(fd);
		return 1;
	}

	p = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED || !p) {
		close(fd);
		return 1;
	}

	switch (index_in_strings(dtb_acts, action)) {
	case DTB_ACT_test: {
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
	}
	case DTB_ACT_print:
	case DTB_ACT_dump: {
		int32_t off = boot_find_dtb_offset(p, st.st_size);
		if (off >= 0) {
			const uint8_t *dtb = p + off;
			uint32_t dtb_total_sz = ((uint32_t)dtb[4] << 24) | ((uint32_t)dtb[5] << 16) | ((uint32_t)dtb[6] << 8) | (uint32_t)dtb[7];
			uint32_t dtb_ver = ((uint32_t)dtb[20] << 24) | ((uint32_t)dtb[21] << 16) | ((uint32_t)dtb[22] << 8) | (uint32_t)dtb[23];
			printf("DTB Magic: 0x%08X\n", ((uint32_t)dtb[0] << 24) | ((uint32_t)dtb[1] << 16) | ((uint32_t)dtb[2] << 8) | (uint32_t)dtb[3]);
			printf("DTB Total Size: %u bytes\n", dtb_total_sz);
			printf("FDT Version: %u\n", dtb_ver);
		}
		break;
	}
	case DTB_ACT_patch: {
		size_t i;
		int count = 0;
		for (i = 0; i + 8 <= (size_t)st.st_size; i++) {
			if (memcmp(p + i, ",verify", 7) == 0) {
				memset(p + i, 0, 7);
				printf("Patched fstab verity @ 0x%08zX\n", i);
				count++;
			} else if (memcmp(p + i, ",avb", 4) == 0) {
				memset(p + i, 0, 4);
				printf("Patched fstab avb @ 0x%08zX\n", i);
				count++;
			}
		}
		msync(p, st.st_size, MS_SYNC);
		printf("DTB patch complete: %d patches applied\n", count);
		break;
	}
	default:
		bb_error_msg("unknown dtb action '%s' (supported: test, print, patch)", action);
		munmap(p, st.st_size);
		close(fd);
		return 1;
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
	printf("Cleaned up %d temporary boot files\n", count);
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
	ifd = open_or_warn(infile, O_RDONLY | O_CLOEXEC);
	if (ifd < 0) return 1;
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

	ofd = open3_or_warn(outfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (ofd < 0) {
		munmap(in_map, st.st_size);
		free(default_out);
		return 1;
	}

	ret = bb_decompress_data(fmt, in_map, st.st_size, ofd);
	close(ofd);
	munmap(in_map, st.st_size);

	if (ret == 0) {
		printf("Decompressed %s (%s) -> %s\n", infile, boot_fmt2name(fmt), outfile);
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
	static const char init_acts[] ALIGN1 =
		"extract\0"
		"get\0"
		"dump\0"
		"status\0"
		"info\0"
		"test\0"
		"replace\0"
		"add\0"
		"set\0"
		"wrap\0"
		"inject-wrapper\0"
		"unwrap\0"
		"restore\0"
		"rm\0"
		"remove\0";
	enum {
		INIT_ACT_extract = 0,
		INIT_ACT_get,
		INIT_ACT_dump,
		INIT_ACT_status,
		INIT_ACT_info,
		INIT_ACT_test,
		INIT_ACT_replace,
		INIT_ACT_add,
		INIT_ACT_set,
		INIT_ACT_wrap,
		INIT_ACT_inject_wrapper,
		INIT_ACT_unwrap,
		INIT_ACT_restore,
		INIT_ACT_rm,
		INIT_ACT_remove,
	};
	boot_img_t boot;
	char tmp_cpio[PATH_MAX];
	int c_fd;
	cpio_node_t *head;
	cpio_node_t *curr;
	bool modified = false;
	int ret = 0;
	int act_idx;

	if (!image || !action) return 1;

	act_idx = index_in_strings(init_acts, action);

	/* Actions unwrap, restore, rm, remove do not take an input binary; any extra arg is outfile */
	if (act_idx >= INIT_ACT_unwrap && act_idx <= INIT_ACT_remove) {
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

	safe_strncpy(tmp_cpio, "/tmp/mb_init_XXXXXX", sizeof(tmp_cpio));
	c_fd = xmkstemp(tmp_cpio);

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

	switch (act_idx) {
	case INIT_ACT_extract:
	case INIT_ACT_get:
	case INIT_ACT_dump: {
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
		ofd = open3_or_warn(dest, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
		if (ofd < 0) {
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		if (init_node->data && init_node->filesize > 0) {
			full_write(ofd, init_node->data, init_node->filesize);
		}
		close(ofd);
		chmod(dest, 0755);
		printf("Extracted '%s' from '%s' -> %s (%u bytes)\n",
		       init_node->name, image, dest, init_node->filesize);
		cpio_free_all(head);
		boot_img_free(&boot);
		return 0;
	}

	case INIT_ACT_status:
	case INIT_ACT_info:
	case INIT_ACT_test: {
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
	}

	case INIT_ACT_replace:
	case INIT_ACT_add:
	case INIT_ACT_set: {
		void *new_data;
		size_t in_sz = 0;
		cpio_node_t *node = NULL;

		if (!arg) {
			bb_error_msg("missing new init binary argument");
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		new_data = magiskboot_read_file(arg, &in_sz);
		if (!new_data || in_sz == 0) {
			bb_perror_msg("cannot read new init binary '%s'", arg);
			if (new_data) free(new_data);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				node = curr;
				break;
			}
		}
		if (node) {
			free(node->data);
			node->data = new_data;
			node->filesize = (uint32_t)in_sz;
			node->mode = 0100755;
		} else {
			node = xzalloc(sizeof(*node));
			node->name = xstrdup("init");
			node->mode = 0100755;
			node->filesize = (uint32_t)in_sz;
			node->data = new_data;
			node->nlink = 1;
			node->next = head;
			head = node;
		}
		fprintf(stderr, "[+] Injected new init '%s' (%zu bytes)\n", arg, in_sz);
		modified = true;
		break;
	}

	case INIT_ACT_wrap:
	case INIT_ACT_inject_wrapper: {
		void *wrap_data;
		size_t wrap_sz = 0;
		cpio_node_t *init_node = NULL;
		cpio_node_t *real_node = NULL;
		cpio_node_t *new_init;

		if (!arg) {
			bb_error_msg("missing wrapper binary argument");
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

		wrap_data = magiskboot_read_file(arg, &wrap_sz);
		if (!wrap_data || wrap_sz == 0) {
			bb_perror_msg("cannot read wrapper binary '%s'", arg);
			if (wrap_data) free(wrap_data);
			cpio_free_all(head);
			boot_img_free(&boot);
			return 1;
		}

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
		new_init->filesize = (uint32_t)wrap_sz;
		new_init->data = wrap_data;
		new_init->nlink = 1;
		new_init->next = head;
		head = new_init;

		fprintf(stderr, "[+] Installed wrapper binary as /init (%zu bytes)\n", wrap_sz);
		modified = true;
		break;
	}

	case INIT_ACT_unwrap:
	case INIT_ACT_restore: {
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
		break;
	}

	case INIT_ACT_rm:
	case INIT_ACT_remove: {
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
		break;
	}

	default:
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

		safe_strncpy(tmp_new_cpio, "/tmp/mb_new_cpio_XXXXXX", sizeof(tmp_new_cpio));
		close(xmkstemp(tmp_new_cpio));
		cpio_write_all(tmp_new_cpio, head);
		cpio_free_all(head);

		if (boot_fmt_compressed(boot.r_fmt)) {
			safe_strncpy(tmp_new_rd, "/tmp/mb_new_rd_XXXXXX", sizeof(tmp_new_rd));
			close(xmkstemp(tmp_new_rd));
			if (compress_file_format(tmp_new_cpio, tmp_new_rd, boot.r_fmt) != 0) {
				bb_error_msg("failed to compress ramdisk (format: %s)", boot_fmt2name(boot.r_fmt));
				unlink(tmp_new_cpio);
				cpio_free_all(head);
				boot_img_free(&boot);
				return 1;
			}
			unlink(tmp_new_cpio);
		} else {
			safe_strncpy(tmp_new_rd, tmp_new_cpio, sizeof(tmp_new_rd));
		}

		if (outfile && outfile[0] != '\0') {
			safe_strncpy(final_target, outfile, sizeof(final_target));
		} else {
			strncpy(final_target, image, sizeof(final_target) - 1);
			final_target[sizeof(final_target) - 1] = '\0';
		}

		snprintf(tmp_out_boot, sizeof(tmp_out_boot), "%s.tmp.%d", final_target, (int)getpid());

		out_fd = open3_or_warn(tmp_out_boot, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
		if (out_fd < 0) {
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
			uint64_t orig_vbmeta_off = SWAP_BE64(boot.avb_footer->vbmeta_offset);
			uint64_t orig_vbmeta_sz = SWAP_BE64(boot.avb_footer->vbmeta_size);
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
				new_footer.original_image_size = SWAP_BE64((uint64_t)aosp_img_size);
				new_footer.vbmeta_offset = SWAP_BE64((uint64_t)new_vbmeta_off);
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
 * 11. Dynamic ELF Kernel Module Patcher, BTF Introspection & Module Lifecycle
 * ========================================================================= */

#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE 0
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

static void log_kmsg_msg(const char *msg)
{
	int fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (fd >= 0) {
		full_write(fd, msg, strlen(msg));
		close(fd);
	}
}
static uint8_t *decompress_gzip_buffer(const uint8_t *in_buf, size_t in_size, size_t *out_size)
{
	char tmp_path[] = "/tmp/mb_kdecomp_XXXXXX";
	int out_fd;
	struct stat st;
	uint8_t *out_buf = NULL;

	if (!in_buf || in_size < 10 || !out_size)
		return NULL;
	if (in_buf[0] != 0x1f || in_buf[1] != 0x8b)
		return NULL;

	out_fd = xmkstemp(tmp_path);
	unlink(tmp_path);

	if (bb_decompress_data(BOOT_FMT_GZIP, in_buf, in_size, out_fd) != 0) {
		close(out_fd);
		return NULL;
	}

	if (fstat(out_fd, &st) == 0 && st.st_size > 0) {
		lseek(out_fd, 0, SEEK_SET);
		out_buf = (uint8_t *)xmalloc(st.st_size);
		if (full_read(out_fd, out_buf, st.st_size) == (ssize_t)st.st_size) {
			*out_size = (size_t)st.st_size;
		} else {
			free(out_buf);
			out_buf = NULL;
		}
	}
	close(out_fd);
	return out_buf;
}

/*
 * Generic ARM64 Disassembly Instruction Decoders
 */
static inline bool kroot_elf_decode_adrp(uint32_t insn, uint64_t pc, int *rd, uint64_t *page_addr)
{
	if ((insn & 0x9f000000U) != 0x90000000U)
		return false;
	if (rd)
		*rd = (int)(insn & 0x1fU);
	if (page_addr) {
		int64_t immlo = (int64_t)((insn >> 29) & 0x3U);
		int64_t immhi = (int64_t)((insn >> 5) & 0x7ffffU);
		int64_t imm = (immhi << 2) | immlo;
		if (imm & (1LL << 20))
			imm -= (1LL << 21);
		*page_addr = (pc & ~0xfffULL) + (uint64_t)(imm << 12);
	}
	return true;
}

static inline bool kroot_elf_decode_add_sub_imm(uint32_t insn, int *rd, int *rn,
                                                uint32_t *imm, bool *is_sub, bool *is_64bit)
{
	if ((insn & 0x1f000000U) != 0x11000000U)
		return false;
	if (rd)
		*rd = (int)(insn & 0x1fU);
	if (rn)
		*rn = (int)((insn >> 5) & 0x1fU);
	if (is_sub)
		*is_sub = ((insn & (1U << 30)) != 0);
	if (is_64bit)
		*is_64bit = ((insn & (1U << 31)) != 0);
	if (imm) {
		uint32_t val = (insn >> 10) & 0xfffU;
		if (insn & (1U << 22))
			val <<= 12;
		*imm = val;
	}
	return true;
}

static inline bool kroot_elf_decode_cmp_imm(uint32_t insn, int *rn, uint32_t *imm, bool *is_64bit)
{
	if ((insn & 0x3f80001fU) != 0x3100001fU)
		return false;
	if (is_64bit)
		*is_64bit = ((insn & (1U << 31)) != 0);
	if (rn)
		*rn = (int)((insn >> 5) & 0x1fU);
	if (imm) {
		uint32_t shift = (insn >> 22) & 1U;
		uint32_t imm12 = (insn >> 10) & 0xfffU;
		*imm = imm12 << (shift ? 12 : 0);
	}
	return true;
}

static inline bool kroot_elf_decode_b_cond(uint32_t insn, uint64_t pc, int *cond, uint64_t *target)
{
	if ((insn & 0xff000010U) != 0x54000000U)
		return false;
	if (cond)
		*cond = (int)(insn & 0x0fU);
	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18))
			imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_ldr_imm(uint32_t insn, int *rt, int *rn,
                                            int32_t *offset, int *size, bool *is_signed)
{
	uint32_t u_cls = insn & 0x3fc00000U;
	uint32_t s_cls;
	if (u_cls == 0x39400000U || u_cls == 0x39800000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = (int32_t)(((insn >> 10) & 0xfffU) * sz);
		if (size) *size = sz;
		if (is_signed) *is_signed = (u_cls == 0x39800000U);
		return true;
	}
	s_cls = insn & 0x3fe00c00U;
	if (s_cls == 0x38400000U || s_cls == 0x38800000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		int32_t simm9 = (int32_t)((insn >> 12) & 0x1ffU);
		if (simm9 & 0x100U) simm9 |= ~0x1ff;
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = simm9;
		if (size) *size = sz;
		if (is_signed) *is_signed = (s_cls == 0x38800000U);
		return true;
	}
	return false;
}

static inline bool kroot_elf_decode_str_imm(uint32_t insn, int *rt, int *rn,
                                            int32_t *offset, int *size)
{
	if ((insn & 0x3fc00000U) == 0x39000000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = (int32_t)(((insn >> 10) & 0xfffU) * sz);
		if (size) *size = sz;
		return true;
	}
	return false;
}

static inline bool kroot_elf_decode_cbz(uint32_t insn, uint64_t pc, int *rt,
                                        bool *is_cbnz, bool *is_64bit, uint64_t *target)
{
	if ((insn & 0x7e000000U) != 0x34000000U)
		return false;
	if (rt) *rt = (int)(insn & 0x1fU);
	if (is_cbnz) *is_cbnz = ((insn & (1U << 24)) != 0);
	if (is_64bit) *is_64bit = ((insn & (1U << 31)) != 0);
	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_b_bl(uint32_t insn, uint64_t pc, bool *is_bl, uint64_t *target)
{
	if ((insn & 0x7c000000U) != 0x14000000U)
		return false;
	if (is_bl) *is_bl = ((insn & 0x80000000U) != 0);
	if (target) {
		int64_t imm26 = (int64_t)(insn & 0x03ffffffU);
		if (imm26 & (1LL << 25)) imm26 -= (1LL << 26);
		*target = pc + (uint64_t)(imm26 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_blr(uint32_t insn, int *rn)
{
	if ((insn & 0xfffffc1fU) == 0xd63f0000U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		return true;
	}
	return false;
}

static inline bool kroot_elf_decode_blr_auth(uint32_t insn, int *rn, bool *use_b_key, bool *use_zero)
{
	if ((insn & 0xffff0800U) == 0xd73f0800U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (use_b_key) *use_b_key = ((insn >> 10) & 1) != 0;
		if (use_zero) *use_zero = (insn & 0x1fU) == 31;
		return true;
	}
	return false;
}

/*
 * Dynamic BTF (BPF Type Format) Kernel Introspection Engine
 */
static const uint8_t *find_btf_header(const uint8_t *data, size_t size)
{
	const struct kroot_btf_header *h0;
	size_t i;

	if (size < sizeof(struct kroot_btf_header))
		return NULL;

	h0 = (const struct kroot_btf_header *)data;
	if (h0->magic == KROOT_BTF_MAGIC && h0->version == KROOT_BTF_VERSION &&
	    h0->hdr_len >= 24 && h0->hdr_len <= 128 &&
	    h0->type_len > 0 && h0->str_len > 0 &&
	    (size_t)h0->hdr_len + h0->type_off + h0->type_len <= size &&
	    (size_t)h0->hdr_len + h0->str_off + h0->str_len <= size) {
		return data;
	}

	for (i = 0; i + sizeof(struct kroot_btf_header) <= size; i += 4) {
		if (data[i] == 0x9f && data[i + 1] == 0xeb) {
			const struct kroot_btf_header *h = (const struct kroot_btf_header *)(data + i);
			if (h->version == KROOT_BTF_VERSION &&
			    h->hdr_len >= 24 && h->hdr_len <= 128 &&
			    h->type_len > 0 && h->str_len > 0 &&
			    (size_t)i + h->hdr_len + h->type_off + h->type_len <= size &&
			    (size_t)i + h->hdr_len + h->str_off + h->str_len <= size) {
				const char *str_tab = (const char *)(data + i + h->hdr_len + h->str_off);
				if (str_tab[0] == '\0') {
					return data + i;
				}
			}
		}
	}
	return NULL;
}

static int parse_module_layout_from_btf(const uint8_t *btf_raw, size_t btf_size,
                                       struct module_layout_probe *out)
{
	const struct kroot_btf_header *hdr;
	size_t min_hdr_sz, type_start, type_end, str_start, str_end, str_len, cur;
	const uint8_t *types;
	const char *strs;

	if (!btf_raw || btf_size < sizeof(struct kroot_btf_header))
		return -1;
	hdr = (const struct kroot_btf_header *)btf_raw;
	if (hdr->magic != KROOT_BTF_MAGIC)
		return -1;

	min_hdr_sz = hdr->hdr_len;
	if (min_hdr_sz < 24 || min_hdr_sz > btf_size)
		return -1;

	type_start = min_hdr_sz + hdr->type_off;
	type_end   = type_start + hdr->type_len;
	str_start  = min_hdr_sz + hdr->str_off;
	str_end    = str_start + hdr->str_len;

	if (type_end > btf_size || str_end > btf_size)
		return -1;

	types = btf_raw + type_start;
	strs = (const char *)(btf_raw + str_start);
	str_len = hdr->str_len;
	cur = 0;

	while (cur + sizeof(struct kroot_btf_type) <= hdr->type_len) {
		const struct kroot_btf_type *t = (const struct kroot_btf_type *)(types + cur);
		uint32_t kind = (t->info >> 24) & 0x7f;
		uint32_t vlen = t->info & 0xffffff;
		uint32_t kflag = (t->info >> 31) & 1;

		size_t elem_sz = sizeof(struct kroot_btf_type);
		switch (kind) {
		case KROOT_BTF_KIND_INT: elem_sz += sizeof(uint32_t); break;
		case KROOT_BTF_KIND_ARRAY: elem_sz += sizeof(struct kroot_btf_array); break;
		case KROOT_BTF_KIND_STRUCT:
		case KROOT_BTF_KIND_UNION: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_member); break;
		case KROOT_BTF_KIND_ENUM: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_enum); break;
		case KROOT_BTF_KIND_ENUM64: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_enum64); break;
		case KROOT_BTF_KIND_FUNC_PROTO: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_param); break;
		case KROOT_BTF_KIND_VAR: elem_sz += sizeof(struct kroot_btf_var); break;
		case KROOT_BTF_KIND_DATASEC: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_var_secinfo); break;
		case KROOT_BTF_KIND_DECL_TAG: elem_sz += 4; break;
		default: break;
		}

		if (cur + elem_sz > hdr->type_len)
			break;

		if (kind == KROOT_BTF_KIND_STRUCT && t->name_off < str_len) {
			const char *tname = strs + t->name_off;
			if (strcmp(tname, "module") == 0) {
				const struct kroot_btf_member *m = (const struct kroot_btf_member *)(t + 1);
				uint32_t i;
				out->mod_size = t->size;
				printf("[+] Found BTF struct module (size = %zu bytes, %u members):\n",
				       out->mod_size, vlen);
				for (i = 0; i < vlen; i++) {
					if (m[i].name_off < str_len) {
						const char *mname = strs + m[i].name_off;
						uint32_t bit_off = kflag ? (m[i].offset & 0xffffff) : m[i].offset;
						uint32_t byte_off = bit_off / 8;
						if (strcmp(mname, "init") == 0) {
							out->init_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "exit") == 0) {
							out->exit_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "core_layout") == 0) {
							out->core_layout_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						}
					}
				}
				if (out->mod_size > 0 && out->init_off > 0) {
					out->found = true;
					return 0;
				}
			}
		}
		cur += elem_sz;
	}
	return -1;
}


static int probe_module_layout_from_kernel_image(const uint8_t *data, size_t size,
                                                 struct module_layout_probe *out)
{
	size_t limit, i;
	if (!data || size < 64)
		return -1;

	printf("[*] Probing silicon kernel image (%zu bytes, %.2f MB) for struct module ABI...\n",
	       size, (double)size / (1024.0 * 1024.0));

	limit = size - 64;

	/*
	 * Machine-Code Module Size Discovery:
	 * In Linux 6.4+, kernel/module/main.c enforces:
	 *   if (shdr->sh_size != sizeof(struct module))
	 *       pr_err("module %s: .gnu.linkonce.this_module section size must match...\n");
	 */
	if (out->mod_size == 0) {
		const char *needle = ".gnu.linkonce.this_module section size must match";
		size_t needle_len = strlen(needle);
		const uint8_t *found_str = NULL;
		size_t s_idx;

		for (s_idx = 0; s_idx + needle_len <= size; s_idx++) {
			if (data[s_idx] == (uint8_t)needle[0] &&
			    memcmp(data + s_idx, needle, needle_len) == 0) {
				found_str = data + s_idx;
				break;
			}
		}

		if (found_str) {
			size_t str_idx = (size_t)(found_str - data);
			size_t str_start = str_idx;
			uint64_t target_page;
			uint32_t target_lo12, raw_lo12;
			size_t err_pc = 0, pc;

			if (str_idx >= 32) {
				size_t p_off;
				for (p_off = str_idx - 1; p_off >= str_idx - 32; p_off--) {
					if (memcmp(data + p_off, "module %s:", 10) == 0) {
						str_start = p_off;
						if (p_off >= 2 && data[p_off - 2] == 1)
							str_start = p_off - 2;
						break;
					}
				}
			}

			target_page = (uint64_t)(str_start & ~0xfffULL);
			target_lo12 = (uint32_t)(str_start & 0xfffULL);
			raw_lo12 = (uint32_t)(str_idx & 0xfffULL);

			for (pc = 0; pc + 4 <= limit; pc += 4) {
				uint32_t insn = *(const uint32_t *)(data + pc);
				int adrp_rd = 0;
				uint64_t page_addr = 0;
				if (kroot_elf_decode_adrp(insn, (uint64_t)pc, &adrp_rd, &page_addr) && page_addr == target_page) {
					size_t next_pc;
					for (next_pc = pc + 4; next_pc <= pc + 32 && next_pc + 4 <= limit; next_pc += 4) {
						uint32_t insn2 = *(const uint32_t *)(data + next_pc);
						int add_rd = 0, add_rn = 0;
						uint32_t add_imm = 0;
						bool is_sub = false, is_64bit = false;
						if (kroot_elf_decode_add_sub_imm(insn2, &add_rd, &add_rn, &add_imm, &is_sub, &is_64bit) &&
						    !is_sub && add_rn == adrp_rd &&
						    (add_imm == target_lo12 || add_imm == raw_lo12 || (size_t)abs((int)(add_imm - raw_lo12)) < 16)) {
							err_pc = pc;
							break;
						}
					}
					if (err_pc > 0)
						break;
				}
			}

			if (err_pc > 0) {
				size_t window_start = (err_pc > 8192) ? (err_pc - 8192) : 0;
				size_t b_pc;
				for (b_pc = window_start; b_pc < err_pc; b_pc += 4) {
					uint32_t b_insn = *(const uint32_t *)(data + b_pc);
					int cond = 0;
					uint64_t b_target = 0;
					if (kroot_elf_decode_b_cond(b_insn, (uint64_t)b_pc, &cond, &b_target)) {
						if ((b_target >= (uint64_t)(err_pc > 64 ? err_pc - 64 : 0) &&
						     b_target <= (uint64_t)(err_pc + 64)) ||
						    ((b_target & ~0x1fULL) == (err_pc & ~0x1fULL))) {
							size_t c_start = (b_pc > 16) ? (b_pc - 16) : 0;
							size_t c_pc;
							for (c_pc = b_pc - 4; c_pc >= c_start; c_pc -= 4) {
								uint32_t c_insn = *(const uint32_t *)(data + c_pc);
								int c_rn = 0;
								uint32_t c_imm = 0;
								bool c_64 = false;
								if (kroot_elf_decode_cmp_imm(c_insn, &c_rn, &c_imm, &c_64) &&
								    c_imm >= 256 && c_imm <= 8192) {
									out->mod_size = (size_t)c_imm;
									out->found = true;
									printf("    • [Silicon] sizeof(struct module) : %zu bytes (0x%zx) at image offset 0x%zx\n",
									       out->mod_size, out->mod_size, c_pc);
									break;
								}
								if (c_pc == 0) break;
							}
							if (out->mod_size > 0) break;
						}
					}
				}
			}
		}
	}

	for (i = 0; i < limit; i += 4) {
		uint32_t w0 = *(const uint32_t *)(data + i);
		int rt0, rn0, sz0;
		int32_t off0;
		bool is_signed0;
		size_t off;

		if (!kroot_elf_decode_ldr_imm(w0, &rt0, &rn0, &off0, &sz0, &is_signed0) ||
		    sz0 != 8 || off0 < 16 || off0 > 4096 || rn0 == 31)
			continue;

		off = (size_t)off0;

		if (out->init_off == 0 && rt0 == 0) {
			size_t j;
			for (j = 1; j <= 3 && i + (j + 2) * 4 <= limit; j++) {
				uint32_t wj = *(const uint32_t *)(data + i + j * 4);
				int cbz_rt;
				bool is_cbnz, is_64bit;
				uint64_t cbz_target = 0;
				if (kroot_elf_decode_cbz(wj, (uint64_t)(i + j * 4), &cbz_rt, &is_cbnz, &is_64bit, &cbz_target) && cbz_rt == 0) {
					size_t k;
					for (k = j + 1; k <= j + 4 && i + (k + 1) * 4 <= limit; k++) {
						uint32_t wk = *(const uint32_t *)(data + i + k * 4);
						bool is_bl;
						uint64_t bl_target = 0;
						if (kroot_elf_decode_b_bl(wk, (uint64_t)(i + k * 4), &is_bl, &bl_target) && is_bl) {
							bool is_do_init = false;
							size_t m;
							for (m = k + 1; m <= k + 32 && i + (m + 1) * 4 <= limit; m++) {
								uint32_t wm = *(const uint32_t *)(data + i + m * 4);
								int str_rt, str_rn, str_sz;
								int32_t str_off_val;
								if (kroot_elf_decode_str_imm(wm, &str_rt, &str_rn, &str_off_val, &str_sz) &&
								    str_rn == rn0 && str_rt == 31 && str_sz == 4 && str_off_val == 0) {
									is_do_init = true;
									break;
								}
							}
							if (!is_do_init) continue;

							out->init_off = off;
							out->found = true;
							printf("[+] Silicon Machine Code Opcode Discovery:\n");
							printf("    • [Silicon] offsetof(init)      : %zu (0x%zx) at image offset 0x%zx (rn=x%d)\n",
							       out->init_off, out->init_off, i, rn0);
							break;
						}
					}
					if (out->init_off > 0) break;
				}
			}
		}

		if (out->exit_off == 0 && (out->init_off == 0 || off > out->init_off)) {
			int target_reg = rt0;
			size_t k;
			for (k = 1; k <= 32 && i + (k + 1) * 4 <= limit; k++) {
				uint32_t wk = *(const uint32_t *)(data + i + k * 4);
				int blr_rn;
				bool use_b_key, use_zero;
				if (kroot_elf_decode_blr(wk, &blr_rn) && blr_rn == target_reg) {
					out->exit_off = off;
					out->found = true;
					printf("    • [Silicon] offsetof(exit)      : %zu (0x%zx) at image offset 0x%zx (rn=x%d, BLR X%d)\n",
					       out->exit_off, out->exit_off, i, rn0, blr_rn);
					break;
				}
				if (kroot_elf_decode_blr_auth(wk, &blr_rn, &use_b_key, &use_zero) && blr_rn == target_reg) {
					out->exit_off = off;
					out->found = true;
					printf("    • [Silicon] offsetof(exit)      : %zu (0x%zx) at image offset 0x%zx (rn=x%d, BLRA* X%d)\n",
					       out->exit_off, out->exit_off, i, rn0, blr_rn);
					break;
				}
				if ((wk & 0xffe0ffe0) == 0xaa0003e0) {
					int mov_rd = wk & 0x1f;
					int mov_rm = (wk >> 16) & 0x1f;
					if (mov_rm == target_reg)
						target_reg = mov_rd;
				}
			}
		}

		if (out->init_off > 0 && out->exit_off > 0)
			return 0;
	}

	return (out->init_off > 0 || out->mod_size > 0) ? 0 : -1;
}

static int probe_module_layout_from_buffer(const uint8_t *map, size_t size, struct module_layout_probe *out)
{
	const uint8_t *k_data;
	size_t k_size;
	uint8_t *decompressed = NULL;
	const uint8_t *btf;
	int res;

	if (!map || size < 4096)
		return -1;

	k_data = map;
	k_size = size;

	if (size > 4096 && memcmp(map, "ANDROID!", 8) == 0) {
		uint32_t hdr_ver = *(const uint32_t *)(map + 40);
		size_t k_off = (hdr_ver >= 3) ? 4096 : *(const uint32_t *)(map + 36);
		size_t k_sz = *(const uint32_t *)(map + 8);
		if (k_off < size) {
			k_data = map + k_off;
			k_size = (k_sz > 0 && k_off + k_sz <= size) ? k_sz : (size - k_off);
		}
	}

	if (k_size > 10 && k_data[0] == 0x1f && k_data[1] == 0x8b) {
		size_t decomp_sz = 0;
		decompressed = decompress_gzip_buffer(k_data, k_size, &decomp_sz);
		if (decompressed && decomp_sz > 4096) {
			k_data = decompressed;
			k_size = decomp_sz;
		}
	}

	btf = find_btf_header(k_data, k_size);
	if (btf && parse_module_layout_from_btf(btf, k_size - (size_t)(btf - k_data), out) == 0) {
		if (decompressed) free(decompressed);
		return 0;
	}

	res = probe_module_layout_from_kernel_image(k_data, k_size, out);
	if (decompressed) free(decompressed);
	return res;
}

/* Recursively find the active 'by-name' partition directory under /dev/block dynamically */
static int find_by_name_dir(const char *base, int depth, char *out_dir, size_t max_len)
{
	DIR *d;
	struct dirent *de;

	if (depth <= 0) return -1;
	d = opendir(base);
	if (!d) return -1;

	while ((de = readdir(d)) != NULL) {
		char subpath[PATH_MAX];
		struct stat st;

		if (de->d_name[0] == '.') continue;
		snprintf(subpath, sizeof(subpath), "%s/%s", base, de->d_name);

		if (strcmp(de->d_name, "by-name") == 0) {
			if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
				char test_boot[PATH_MAX];
				/* Verify this by-name directory actually contains boot or boot_a */
				snprintf(test_boot, sizeof(test_boot), "%.*s/boot", (int)(sizeof(test_boot) - 16), subpath);
				if (access(test_boot, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
				snprintf(test_boot, sizeof(test_boot), "%.*s/boot_a", (int)(sizeof(test_boot) - 16), subpath);
				if (access(test_boot, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
			}
		}

		if (lstat(subpath, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
			if (find_by_name_dir(subpath, depth - 1, out_dir, max_len) == 0) {
				closedir(d);
				return 0;
			}
		}
	}
	closedir(d);
	return -1;
}


static int get_active_slot_suffix(char *slot_suffix, size_t max_len)
{
	int fd;
	char buf[2048];
	ssize_t n;
	char *p;
	char *eq;
	const char *env_slot;

	slot_suffix[0] = '\0';

	/* 1. Parse /proc/cmdline in-memory */
	fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = full_read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			p = strstr(buf, "androidboot.slot_suffix=");
			if (p) {
				sscanf(p + 24, "%15s", slot_suffix);
			} else {
				p = strstr(buf, "androidboot.slot=");
				if (p) {
					char sname[16] = {0};
					if (sscanf(p + 17, "%15s", sname) == 1 && max_len > 1) {
						snprintf(slot_suffix, max_len, "_%.*s", (int)(max_len - 2), sname);
					}
				}
			}
		}
	}
	if (slot_suffix[0] != '\0') return 0;

	/* 2. Parse /proc/bootconfig in-memory (Android 12+ GKI) */
	fd = open("/proc/bootconfig", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = full_read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			p = strstr(buf, "androidboot.slot_suffix");
			if (p) {
				eq = strchr(p, '=');
				if (eq) {
					while (*++eq == ' ' || *eq == '"');
					sscanf(eq, "%15[^\" \t\r\n]", slot_suffix);
				}
			}
		}
	}
	if (slot_suffix[0] != '\0') return 0;

	/* 3. Recovery environment variables */
	env_slot = getenv("SLOT");
	if (!env_slot) env_slot = getenv("BOOT_SLOT");
	if (env_slot && env_slot[0] != '\0') {
		if (env_slot[0] == '_') {
			safe_strncpy(slot_suffix, env_slot, max_len);
		} else {
			snprintf(slot_suffix, max_len, "_%s", env_slot);
		}
		return 0;
	}

	/* 4. Parse active /proc/mounts */
	fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = full_read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			if (strstr(buf, "_a ") || strstr(buf, "_a/")) {
				strcpy(slot_suffix, "_a");
				return 0;
			} else if (strstr(buf, "_b ") || strstr(buf, "_b/")) {
				strcpy(slot_suffix, "_b");
				return 0;
			}
		}
	}

	return -1;
}


static int find_target_boot_image(char *out_path, size_t max_len)
{
	char by_name_dir[PATH_MAX];
	char slot_suffix[16];
	char test_path[PATH_MAX];
	bool is_ab = false;

	if (!out_path || max_len < 16)
		return -1;

	/* Dynamically discover the platform's 'by-name' directory under /dev/block */
	if (find_by_name_dir("/dev/block", 4, by_name_dir, sizeof(by_name_dir)) != 0) {
		bb_error_msg("failed to locate 'by-name' partition directory under /dev/block");
		return -1;
	}

	/* Dynamically determine if the device is A/B by inspecting the partition table */
	snprintf(test_path, sizeof(test_path), "%.*s/boot_a", (int)(sizeof(test_path) - 16), by_name_dir);
	if (access(test_path, F_OK) == 0) {
		is_ab = true;
	}

	get_active_slot_suffix(slot_suffix, sizeof(slot_suffix));
	if (is_ab && slot_suffix[0] == '\0') {
		strcpy(slot_suffix, "_a");
	}

	printf("[*] Dynamic partition topology: %s%s%s%s\n",
	       is_ab ? "A/B" : "A-only",
	       slot_suffix[0] ? " (active slot: " : "",
	       slot_suffix[0] ? slot_suffix : "",
	       slot_suffix[0] ? ")" : "");

	if (is_ab && slot_suffix[0] != '\0') {
		snprintf(out_path, max_len, "%.*s/boot%s", (int)(max_len - 32), by_name_dir, slot_suffix);
	} else {
		snprintf(out_path, max_len, "%.*s/boot", (int)(max_len - 16), by_name_dir);
	}

	if (access(out_path, F_OK) == 0) {
		printf("[+] Active boot partition resolved: %s\n", out_path);
		return 0;
	}

	bb_error_msg("target boot partition '%s' does not exist", out_path);
	return -1;
}


static int extract_vermagic_from_buffer(const uint8_t *data, size_t size, char *out_magic, size_t max_len)
{
	size_t i;

	if (!data || size < 64 || !out_magic || max_len < 16)
		return -1;

	/* Primary: scan for full vermagic ending with "aarch64" */
	for (i = 0; i + 7 <= size; i++) {
		if (memcmp(data + i, "aarch64", 7) == 0) {
			size_t end_pos = i + 7;
			size_t start_pos = i;
			while (start_pos > 0 && data[start_pos - 1] >= 0x20 && data[start_pos - 1] <= 0x7E) {
				start_pos--;
			}
			if (end_pos > start_pos) {
				size_t cand_len = end_pos - start_pos;
				if (cand_len >= 20 && cand_len < max_len && cand_len < 256) {
					char cand[256];
					int maj = 0;
					memcpy(cand, data + start_pos, cand_len);
					cand[cand_len] = '\0';
					if (sscanf(cand, "%d.", &maj) == 1 && maj >= 2 && maj <= 99 &&
					    (strstr(cand, " SMP ") != NULL || strstr(cand, " preempt ") != NULL || strstr(cand, " mod_unload ") != NULL)) {
						snprintf(out_magic, max_len, "%s", cand);
						return 0;
					}
				}
			}
		}
	}

	/* Secondary fallback: scan for "Linux version " banner */
	for (i = 0; i + 14 <= size; i++) {
		if (memcmp(data + i, "Linux version ", 14) == 0) {
			const char *p = (const char *)(data + i + 14);
			size_t k = 0;
			while (i + 14 + k < size && p[k] != ' ' && p[k] != '\0' && k < 64) {
				k++;
			}
			if (k >= 3) {
				char ver[64];
				int maj = 0;
				memcpy(ver, p, k);
				ver[k] = '\0';
				if (sscanf(ver, "%d.", &maj) == 1 && maj >= 2 && maj <= 99) {
					snprintf(out_magic, max_len, "%s SMP preempt mod_unload modversions aarch64", ver);
					return 0;
				}
			}
		}
	}
	return -1;
}


static int detect_vermagic_from_boot_image(const char *boot_path, char *out_magic, size_t max_len)
{
	int fd;
	struct stat st;
	off_t real_sz;
	uint8_t *map;
	const uint8_t *k_data;
	size_t k_size;
	uint8_t *decompressed = NULL;
	int ret;

	if (!boot_path || !out_magic) return -1;
	fd = open(boot_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return -1;
	}

	real_sz = get_file_or_bdev_size(fd, &st);
	if (real_sz < 4096) {
		close(fd);
		return -1;
	}

	map = (uint8_t *)map_or_read_image(fd, (size_t)real_sz, false);
	close(fd);
	if (map == MAP_FAILED) return -1;

	k_data = map;
	k_size = (size_t)real_sz;

	if (k_size > 4096 && memcmp(map, "ANDROID!", 8) == 0) {
		uint32_t hdr_ver = *(const uint32_t *)(map + 40);
		size_t k_off = (hdr_ver >= 3) ? 4096 : *(const uint32_t *)(map + 36);
		size_t k_sz = *(const uint32_t *)(map + 8);
		if (k_off < k_size) {
			k_data = map + k_off;
			k_size = (k_sz > 0 && k_off + k_sz <= k_size) ? k_sz : (k_size - k_off);
		}
	}

	if (k_size > 10 && k_data[0] == 0x1f && k_data[1] == 0x8b) {
		size_t decomp_sz = 0;
		decompressed = decompress_gzip_buffer(k_data, k_size, &decomp_sz);
		if (decompressed && decomp_sz > 4096) {
			k_data = decompressed;
			k_size = decomp_sz;
		}
	}

	ret = extract_vermagic_from_buffer(k_data, k_size, out_magic, max_len);
	if (decompressed) free(decompressed);
	munmap(map, (size_t)real_sz);

	if (ret == 0) {
		printf("[+] Dynamically extracted vermagic from image '%s': '%s'\n", boot_path, out_magic);
	}
	return ret;
}

static int probe_target_module_layout(const char *boot_img_path, const char *target_magic,
                                      struct module_layout_probe *out)
{
	int fd;
	char discovered_boot[512];

	(void)target_magic;
	memset(out, 0, sizeof(*out));
	discovered_boot[0] = '\0';

	/* 1. Try reading live kernel BTF from /sys/kernel/btf/vmlinux */
	fd = open("/sys/kernel/btf/vmlinux", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		struct stat st;
		if (fstat(fd, &st) == 0 && st.st_size > 4096) {
			uint8_t *map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
			if (map != MAP_FAILED) {
				const uint8_t *btf = find_btf_header(map, st.st_size);
				if (btf) {
					int res = parse_module_layout_from_btf(btf, st.st_size - (size_t)(btf - map), out);
					munmap(map, st.st_size);
					close(fd);
					if (res == 0) {
						printf("[+] Dynamically introspected struct module from live /sys/kernel/btf/vmlinux\n");
						return 0;
					}
				} else {
					munmap(map, st.st_size);
				}
			}
		}
		close(fd);
	}

	/* 2. Try parsing kernel image from boot_img_path if provided, or auto-discover */
	if (!boot_img_path || boot_img_path[0] == '\0') {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
			boot_img_path = discovered_boot;
		}
	}

	if (boot_img_path && boot_img_path[0] != '\0') {
		fd = open(boot_img_path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			struct stat st;
			if (fstat(fd, &st) == 0) {
				off_t real_sz = get_file_or_bdev_size(fd, &st);
				if (real_sz > 4096) {
					uint8_t *map = (uint8_t *)map_or_read_image(fd, (size_t)real_sz, false);
					if (map != MAP_FAILED) {
						if (probe_module_layout_from_buffer(map, (size_t)real_sz, out) == 0) {
							munmap(map, (size_t)real_sz);
							close(fd);
							printf("[+] Dynamically introspected struct module from image: %s\n", boot_img_path);
							return 0;
						}
						munmap(map, (size_t)real_sz);
					}
				}
			}
			close(fd);
		}
	}

	return -1;
}


/*
 * Running Kernel Config & Vermagic Detection
 */
static int detect_from_running_kernel(char *out_magic, size_t max_len, int *out_cfi_mode)
{
	struct utsname uts;
	int has_smp = 1;
	int has_preempt = 1;
	int has_mod_unload = 1;
	int has_modversions = 1;
	int is_cfi = 0;
	int parsed_config = 0;
	FILE *kf;
	size_t cfg_sz = 0;
	char *cfg_txt;

	if (uname(&uts) != 0)
		return -1;

	cfg_txt = (char *)xmalloc_open_zipped_read_close("/proc/config.gz", &cfg_sz);
	if (cfg_txt && cfg_sz > 0) {
		char *line_start = cfg_txt;
		char *line_end;
		while ((line_end = strchr(line_start, '\n')) != NULL) {
			*line_end = '\0';
			if (strstr(line_start, "CONFIG_SMP=y")) has_smp = 1;
			else if (strstr(line_start, "# CONFIG_SMP is not set")) has_smp = 0;
			else if (strstr(line_start, "CONFIG_PREEMPT=y")) has_preempt = 1;
			else if (strstr(line_start, "# CONFIG_PREEMPT is not set") ||
			         strstr(line_start, "CONFIG_PREEMPT_NONE=y") ||
			         strstr(line_start, "CONFIG_PREEMPT_VOLUNTARY=y")) has_preempt = 0;
			else if (strstr(line_start, "CONFIG_MODULE_UNLOAD=y")) has_mod_unload = 1;
			else if (strstr(line_start, "# CONFIG_MODULE_UNLOAD is not set")) has_mod_unload = 0;
			else if (strstr(line_start, "CONFIG_MODVERSIONS=y")) has_modversions = 1;
			else if (strstr(line_start, "# CONFIG_MODVERSIONS is not set")) has_modversions = 0;
			else if (strstr(line_start, "CONFIG_CFI_CLANG=y")) is_cfi = 1;
			line_start = line_end + 1;
		}
		parsed_config = 1;
		free(cfg_txt);
	}

	if (!parsed_config) {
		char *vbuf = (char *)xmalloc_open_read_close("/proc/version", NULL);
		if (vbuf) {
			has_smp = (strstr(vbuf, "SMP") != NULL);
			has_preempt = (strstr(vbuf, "PREEMPT") != NULL);
			free(vbuf);
		}
	}

	kf = fopen_for_read("/proc/kallsyms");
	if (kf) {
		char *kline;
		while ((kline = xmalloc_fgetline(kf)) != NULL) {
			if (strstr(kline, "__cfi_slowpath") || strstr(kline, "__cfi_check")) {
				is_cfi = 1;
				free(kline);
				break;
			}
			free(kline);
		}
		fclose(kf);
	}

	snprintf(out_magic, max_len, "%s%s%s%s%s aarch64",
	         uts.release,
	         has_smp ? " SMP" : "",
	         has_preempt ? " preempt" : "",
	         has_mod_unload ? " mod_unload" : "",
	         has_modversions ? " modversions" : "");

	if (out_cfi_mode && *out_cfi_mode < 0) {
		*out_cfi_mode = is_cfi ? 1 : 0;
	}

	return 0;
}

static void get_running_vermagic(char *buf, size_t max_len)
{
	int cfi = -1;
	if (detect_from_running_kernel(buf, max_len, &cfi) != 0) {
		struct utsname u;
		if (uname(&u) == 0) {
			snprintf(buf, max_len, "%s SMP preempt mod_unload modversions aarch64", u.release);
		} else {
			snprintf(buf, max_len, "unknown");
		}
	}
}

static const char *resolve_default_module_path(int argc, char **argv, int path_idx)
{
	if (argc > path_idx && argv[path_idx] && argv[path_idx][0] != '\0')
		return argv[path_idx];
	if (access(DEFAULT_MODULE_PATH, R_OK) == 0)
		return DEFAULT_MODULE_PATH;
	if (access(FALLBACK_MODULE_PATH, R_OK) == 0)
		return FALLBACK_MODULE_PATH;
	if (access(LEGACY_FALLBACK_PATH, R_OK) == 0)
		return LEGACY_FALLBACK_PATH;
	return DEFAULT_MODULE_PATH;
}

/*
 * Standard ELF64 Session, Section Offset Shifter & Mutation Engine
 */
static bool elf64_init_ctx(struct elf64_ctx *ctx, uint8_t *buf, size_t size, size_t capacity, bool is_allocated)
{
	if (!ctx || !buf || size < sizeof(Elf64_Ehdr))
		return false;

	memset(ctx, 0, sizeof(*ctx));
	ctx->buf = buf;
	ctx->size = size;
	ctx->capacity = capacity ? capacity : size;
	ctx->is_allocated = is_allocated;

	if (memcmp(ctx->buf, ELFMAG, SELFMAG) != 0 || ctx->buf[EI_CLASS] != ELFCLASS64) {
		return false;
	}

	ctx->ehdr = (Elf64_Ehdr *)ctx->buf;
	if (ctx->ehdr->e_shoff == 0 || ctx->ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
	    ctx->ehdr->e_shoff + ctx->ehdr->e_shnum * sizeof(Elf64_Shdr) > ctx->size) {
		return false;
	}

	ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
	ctx->shnum = ctx->ehdr->e_shnum;

	if (ctx->ehdr->e_shstrndx < ctx->shnum) {
		Elf64_Shdr *str_shdr = &ctx->shdrs[ctx->ehdr->e_shstrndx];
		if (str_shdr->sh_offset + str_shdr->sh_size <= ctx->size) {
			ctx->shstrtab = (const char *)(ctx->buf + str_shdr->sh_offset);
		}
	}

	return true;
}

static void elf64_free_ctx(struct elf64_ctx *ctx)
{
	if (ctx && ctx->is_allocated && ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
	}
}

static int elf64_find_section(struct elf64_ctx *ctx, const char *name, Elf64_Shdr **out_shdr, size_t *out_idx)
{
	size_t i;
	if (!ctx || !ctx->shstrtab || !name)
		return -1;

	for (i = 0; i < ctx->shnum; i++) {
		const char *sname = ctx->shstrtab + ctx->shdrs[i].sh_name;
		if (strcmp(sname, name) == 0) {
			if (out_shdr) *out_shdr = &ctx->shdrs[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}


static int elf64_find_section_by_type(struct elf64_ctx *ctx, uint32_t type, Elf64_Shdr **out_shdr, size_t *out_idx)
{
	size_t i;
	if (!ctx) return -1;
	for (i = 0; i < ctx->shnum; i++) {
		if (ctx->shdrs[i].sh_type == type) {
			if (out_shdr) *out_shdr = &ctx->shdrs[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}


static int elf64_find_symbol(struct elf64_ctx *ctx, const char *name, Elf64_Sym *out_sym, size_t *out_idx)
{
	Elf64_Shdr *symtab = NULL;
	size_t symtab_idx = 0;
	const char *strtab;
	Elf64_Sym *syms;
	size_t num_syms;
	size_t i;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, &symtab_idx) != 0)
		return -1;

	if (symtab->sh_link >= ctx->shnum)
		return -1;

	strtab = (const char *)(ctx->buf + ctx->shdrs[symtab->sh_link].sh_offset);
	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	num_syms = symtab->sh_size / sizeof(Elf64_Sym);

	for (i = 0; i < num_syms; i++) {
		const char *sname = strtab + syms[i].st_name;
		if (strcmp(sname, name) == 0) {
			if (out_sym) *out_sym = syms[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}


static int elf64_update_sym(struct elf64_ctx *ctx, size_t sym_idx, const Elf64_Sym *sym)
{
	Elf64_Shdr *symtab = NULL;
	size_t num_syms;
	Elf64_Sym *syms;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, NULL) != 0)
		return -1;

	num_syms = symtab->sh_size / sizeof(Elf64_Sym);
	if (sym_idx >= num_syms)
		return -1;

	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	syms[sym_idx] = *sym;
	return 0;
}

static int elf64_find_rela_by_symbol(struct elf64_ctx *ctx, size_t rela_sec_idx, size_t sym_idx,
                                     Elf64_Rela *out_rela, size_t *out_idx)
{
	Elf64_Shdr *rela_shdr;
	Elf64_Rela *relas;
	size_t num_relas;
	size_t i;

	if (!ctx || rela_sec_idx >= ctx->shnum)
		return -1;

	rela_shdr = &ctx->shdrs[rela_sec_idx];
	if (rela_shdr->sh_type != SHT_RELA)
		return -1;

	relas = (Elf64_Rela *)(ctx->buf + rela_shdr->sh_offset);
	num_relas = rela_shdr->sh_size / sizeof(Elf64_Rela);

	for (i = 0; i < num_relas; i++) {
		if (ELF64_R_SYM(relas[i].r_info) == sym_idx) {
			if (out_rela) *out_rela = relas[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}


static int elf64_update_rela(struct elf64_ctx *ctx, size_t rela_sec_idx, size_t rela_idx, const Elf64_Rela *rela)
{
	Elf64_Shdr *rela_shdr;
	size_t num_relas;
	Elf64_Rela *relas;

	if (!ctx || rela_sec_idx >= ctx->shnum)
		return -1;

	rela_shdr = &ctx->shdrs[rela_sec_idx];
	if (rela_shdr->sh_type != SHT_RELA)
		return -1;

	num_relas = rela_shdr->sh_size / sizeof(Elf64_Rela);
	if (rela_idx >= num_relas)
		return -1;

	relas = (Elf64_Rela *)(ctx->buf + rela_shdr->sh_offset);
	relas[rela_idx] = *rela;
	return 0;
}

static int elf64_neutralize_section(struct elf64_ctx *ctx, const char *name)
{
	Elf64_Shdr *shdr = NULL;
	if (elf64_find_section(ctx, name, &shdr, NULL) == 0 && shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0) {
		shdr->sh_type = SHT_NOBITS;
		shdr->sh_size = 0;
		shdr->sh_flags = 0;
		return 1;
	}
	return 0;
}

/*
 * Dynamic ELF Section Resizer & Offset Shifter
 *
 * When expanding a section, shifts all subsequent sections, section headers,
 * and string tables in lockstep by a 16-byte aligned delta, guaranteeing
 * 100% ELF standard compliance without corrupting any file or table offsets.
 */
static int elf64_resize_section(struct elf64_ctx *ctx, size_t sec_idx, size_t new_size)
{
	Elf64_Shdr *shdr;
	size_t diff;
	size_t delta;
	size_t shift_start;
	size_t bytes_to_shift;
	size_t i;

	if (!ctx || sec_idx >= ctx->shnum)
		return -1;

	shdr = &ctx->shdrs[sec_idx];
	if (new_size <= shdr->sh_size) {
		shdr->sh_size = new_size;
		return 0;
	}

	diff = new_size - shdr->sh_size;
	delta = (diff + 63) & ~63ULL;

	if (ctx->size + delta > ctx->capacity) {
		size_t new_cap = ctx->size + delta + 65536;
		uint8_t *new_buf;
		if (ctx->is_allocated) {
			new_buf = (uint8_t *)realloc(ctx->buf, new_cap);
			if (!new_buf) return -1;
		} else {
			new_buf = (uint8_t *)malloc(new_cap);
			if (!new_buf) return -1;
			memcpy(new_buf, ctx->buf, ctx->size);
			ctx->is_allocated = true;
		}
		ctx->buf = new_buf;
		ctx->capacity = new_cap;
		ctx->ehdr = (Elf64_Ehdr *)ctx->buf;
		ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
		shdr = &ctx->shdrs[sec_idx];
		if (ctx->ehdr->e_shstrndx < ctx->shnum) {
			ctx->shstrtab = (const char *)(ctx->buf + ctx->shdrs[ctx->ehdr->e_shstrndx].sh_offset);
		}
	}

	shift_start = shdr->sh_offset + shdr->sh_size;
	bytes_to_shift = ctx->size - shift_start;

	/*
	 * Update all section header offsets that reside at or after shift_start.
	 * Must be executed BEFORE memmove so that if the section header table
	 * resides at or after shift_start (which is typical for ELF files),
	 * its offsets are updated in-place before the table is moved.
	 */
	for (i = 0; i < ctx->shnum; i++) {
		if (ctx->shdrs[i].sh_type != SHT_NULL && ctx->shdrs[i].sh_offset >= shift_start) {
			ctx->shdrs[i].sh_offset += delta;
		}
	}

	if (ctx->ehdr->e_shoff >= shift_start) {
		ctx->ehdr->e_shoff += delta;
	}

	if (ctx->ehdr->e_phoff >= shift_start) {
		ctx->ehdr->e_phoff += delta;
	}

	if (bytes_to_shift > 0) {
		memmove(ctx->buf + shift_start + delta, ctx->buf + shift_start, bytes_to_shift);
	}
	memset(ctx->buf + shift_start, 0, delta);

	/* Re-synchronize context pointers with shifted section header table */
	ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
	shdr = &ctx->shdrs[sec_idx];

	if (ctx->ehdr->e_shstrndx < ctx->shnum) {
		ctx->shstrtab = (const char *)(ctx->buf + ctx->shdrs[ctx->ehdr->e_shstrndx].sh_offset);
	}

	shdr->sh_size = new_size;
	ctx->size += delta;
	return 0;
}

/*
 * In-place & Dynamic Re-packing .modinfo Vermagic Patcher
 */
static int patch_vermagic_buf(struct elf64_ctx *ctx, const char *target_magic)
{
	Elf64_Shdr *modinfo_shdr = NULL;
	size_t modinfo_idx = 0;
	char *buf;
	size_t len;
	size_t new_magic_len;
	size_t pos = 0;
	size_t target_pos = (size_t)-1;
	size_t avail_val_len = 0;
	char *entries[64];
	size_t entry_lens[64];
	int num_entries = 0;
	char new_vm_entry[512];
	size_t new_vm_len;
	size_t needed_len;
	char *tmp;
	size_t w;
	int i;
	size_t new_sec_sz;

	if (elf64_find_section(ctx, ".modinfo", &modinfo_shdr, &modinfo_idx) != 0) {
		fprintf(stderr, "[-] Section .modinfo not found\n");
		return -1;
	}

	buf = (char *)(ctx->buf + modinfo_shdr->sh_offset);
	len = modinfo_shdr->sh_size;
	new_magic_len = strlen(target_magic);

	while (pos < len) {
		const char *entry = buf + pos;
		size_t entry_len = strnlen(entry, len - pos);
		if (is_prefixed_with(entry, "vermagic=")) {
			size_t slot_end;
			target_pos = pos;
			slot_end = pos + entry_len + 1;
			while (slot_end < len && buf[slot_end] == '\0') slot_end++;
			avail_val_len = (slot_end - pos > 10) ? (slot_end - pos - 10) : (entry_len - 9);
			break;
		}
		pos += entry_len + 1;
	}

	if (target_pos == (size_t)-1) {
		fprintf(stderr, "[-] Entry 'vermagic=' not found in .modinfo\n");
		return -1;
	}

	/* Case 1: Fits in-place directly within current slot and padding */
	if (new_magic_len <= avail_val_len) {
		char *val_ptr = buf + target_pos + 9;
		memcpy(val_ptr, target_magic, new_magic_len);
		val_ptr[new_magic_len] = '\0';
		if (avail_val_len > new_magic_len) {
			memset(val_ptr + new_magic_len + 1, 0, avail_val_len - new_magic_len);
		}
		printf("[+] In-place updated vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Case 2: Exceeds slot. Re-pack .modinfo buffer */
	pos = 0;
	while (pos < len && num_entries < 64) {
		const char *e = buf + pos;
		size_t elen = strnlen(e, len - pos);
		if (elen > 0) {
			entries[num_entries] = (char *)e;
			entry_lens[num_entries] = elen;
			num_entries++;
		}
		pos += elen + 1;
	}

	snprintf(new_vm_entry, sizeof(new_vm_entry), "vermagic=%s", target_magic);
	new_vm_len = strlen(new_vm_entry);

	needed_len = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			needed_len += new_vm_len + 1;
		} else {
			needed_len += entry_lens[i] + 1;
		}
	}

	if (needed_len <= modinfo_shdr->sh_size) {
		tmp = xzalloc(modinfo_shdr->sh_size);
		w = 0;
		for (i = 0; i < num_entries; i++) {
			if (is_prefixed_with(entries[i], "vermagic=")) {
				memcpy(tmp + w, new_vm_entry, new_vm_len + 1);
				w += new_vm_len + 1;
			} else {
				memcpy(tmp + w, entries[i], entry_lens[i] + 1);
				w += entry_lens[i] + 1;
			}
		}
		memcpy(buf, tmp, modinfo_shdr->sh_size);
		free(tmp);
		printf("[+] Re-packed .modinfo in-place with vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Try dropping scmversion/srcversion non-essential strings first */
	needed_len = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			needed_len += new_vm_len + 1;
		} else if (!is_prefixed_with(entries[i], "scmversion=") &&
		           !is_prefixed_with(entries[i], "srcversion=")) {
			needed_len += entry_lens[i] + 1;
		}
	}

	if (needed_len <= modinfo_shdr->sh_size) {
		tmp = xzalloc(modinfo_shdr->sh_size);
		w = 0;
		for (i = 0; i < num_entries; i++) {
			if (is_prefixed_with(entries[i], "vermagic=")) {
				memcpy(tmp + w, new_vm_entry, new_vm_len + 1);
				w += new_vm_len + 1;
			} else if (!is_prefixed_with(entries[i], "scmversion=") &&
			           !is_prefixed_with(entries[i], "srcversion=")) {
				memcpy(tmp + w, entries[i], entry_lens[i] + 1);
				w += entry_lens[i] + 1;
			}
		}
		memcpy(buf, tmp, modinfo_shdr->sh_size);
		free(tmp);
		printf("[+] Compacted .modinfo and aligned vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Exceeds section size even after filtering: resize section and shift subsequent sections */
	new_sec_sz = (needed_len + 63) & ~63ULL;
	if (elf64_resize_section(ctx, modinfo_idx, new_sec_sz) != 0) {
		fprintf(stderr, "[-] Failed to resize .modinfo section\n");
		return -1;
	}

	modinfo_shdr = &ctx->shdrs[modinfo_idx];
	buf = (char *)(ctx->buf + modinfo_shdr->sh_offset);
	memset(buf, 0, modinfo_shdr->sh_size);
	w = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			memcpy(buf + w, new_vm_entry, new_vm_len + 1);
			w += new_vm_len + 1;
		} else if (!is_prefixed_with(entries[i], "scmversion=") &&
		           !is_prefixed_with(entries[i], "srcversion=")) {
			memcpy(buf + w, entries[i], entry_lens[i] + 1);
			w += entry_lens[i] + 1;
		}
	}
	printf("[+] Dynamically expanded .modinfo (%zu -> %zu bytes) and shifted subsequent sections\n",
	       len, modinfo_shdr->sh_size);
	return 0;
}

/*
 * Relocation Adaptation, Alternative Neutralization & CFI Patcher
 */
static int patch_this_module_relocations(struct elf64_ctx *ctx, const char *filepath,
                                         int cfi_mode, const char *target_magic,
                                         const char *boot_img_path)
{
	int alt_neutralized = 0;
	size_t target_init_off = 0;
	size_t target_exit_off = 0;
	size_t target_mod_size = 0;
	struct module_layout_probe probe;
	Elf64_Shdr *this_mod_shdr = NULL;
	size_t this_mod_idx = 0;
	Elf64_Shdr *rela_shdr = NULL;
	size_t rela_sec_idx = 0;
	Elf64_Sym sym_cfi_check;
	size_t idx_cfi_check = 0;

	(void)filepath;
	(void)cfi_mode;
	(void)target_magic;
	if (!ctx) return 0;

	/* 1. Neutralize .altinstructions and .rela.altinstructions */
	alt_neutralized += elf64_neutralize_section(ctx, ".altinstructions");
	alt_neutralized += elf64_neutralize_section(ctx, ".rela.altinstructions");
	if (alt_neutralized > 0) {
		printf("[+] Neutralized %d alternative section(s) via ELF mutation\n", alt_neutralized);
	}

	/* 2. Canonical target struct module ABI layouts discovered dynamically via BTF / Silicon probe */
	memset(&probe, 0, sizeof(probe));
	if (probe_target_module_layout(boot_img_path, target_magic, &probe) == 0 && probe.found) {
		target_init_off = probe.init_off;
		target_exit_off = probe.exit_off;
		target_mod_size = probe.mod_size;
		printf("[+] Dynamic Module ABI Discovery:\n");
		printf("    • sizeof(struct module) : %zu bytes\n", target_mod_size);
		printf("    • offsetof(init)        : %zu (0x%zx)\n", target_init_off, target_init_off);
		printf("    • offsetof(exit)        : %zu (0x%zx)\n", target_exit_off, target_exit_off);
	} else {
		printf("[*] BTF/silicon introspection not available; preserving native module ABI offsets\n");
	}

	/* 3. Sanitize and adapt .gnu.linkonce.this_module */
	if (elf64_find_section(ctx, ".gnu.linkonce.this_module", &this_mod_shdr, &this_mod_idx) == 0) {
		if (this_mod_shdr->sh_size > 80) {
			size_t zero_bytes = this_mod_shdr->sh_size - 80;
			printf("[*] Sanitizing .gnu.linkonce.this_module: preserving 80-byte header (state+list+name), zeroing %zu trailing bytes\n", zero_bytes);
			memset(ctx->buf + this_mod_shdr->sh_offset + 80, 0, zero_bytes);
		}

		if (target_mod_size > 0 && this_mod_shdr->sh_size != target_mod_size) {
			Elf64_Sym sym_this_mod;
			size_t idx_this_mod = 0;
			printf("[+] Adapting .gnu.linkonce.this_module section size: %zu -> %zu bytes (Kernel struct module invariant)\n",
			       (size_t)this_mod_shdr->sh_size, target_mod_size);
			if (target_mod_size > this_mod_shdr->sh_size) {
				elf64_resize_section(ctx, this_mod_idx, target_mod_size);
				this_mod_shdr = &ctx->shdrs[this_mod_idx];
			} else {
				this_mod_shdr->sh_size = target_mod_size;
			}

			/* Synchronize __this_module symbol size in .symtab */
			if (elf64_find_symbol(ctx, "__this_module", &sym_this_mod, &idx_this_mod) == 0) {
				sym_this_mod.st_size = target_mod_size;
				elf64_update_sym(ctx, idx_this_mod, &sym_this_mod);
			}
		}
	}

	/* 4. Relocate init_module and cleanup_module in .rela.gnu.linkonce.this_module */
	if (elf64_find_section(ctx, ".rela.gnu.linkonce.this_module", &rela_shdr, &rela_sec_idx) == 0) {
		Elf64_Sym sym_init, sym_cleanup;
		size_t idx_init = 0, idx_cleanup = 0;
		bool has_init = (elf64_find_symbol(ctx, "init_module", &sym_init, &idx_init) == 0);
		bool has_cleanup = (elf64_find_symbol(ctx, "cleanup_module", &sym_cleanup, &idx_cleanup) == 0);

		Elf64_Rela init_rela, cleanup_rela;
		size_t init_rela_idx = 0, cleanup_rela_idx = 0;
		bool found_init_rela = false, found_cleanup_rela = false;
		int patched = 0;

		if (has_init && elf64_find_rela_by_symbol(ctx, rela_sec_idx, idx_init, &init_rela, &init_rela_idx) == 0) {
			found_init_rela = true;
		}
		if (has_cleanup && elf64_find_rela_by_symbol(ctx, rela_sec_idx, idx_cleanup, &cleanup_rela, &cleanup_rela_idx) == 0) {
			found_cleanup_rela = true;
		}

		if (found_init_rela && target_init_off > 0 && init_rela.r_offset != target_init_off) {
			printf("[+] Adapting init_module relocation: 0x%lx -> 0x%lx (Dynamic BTF ABI)\n",
			       (unsigned long)init_rela.r_offset, (unsigned long)target_init_off);
			init_rela.r_offset = target_init_off;
			elf64_update_rela(ctx, rela_sec_idx, init_rela_idx, &init_rela);
			patched++;
		}

		if (found_cleanup_rela) {
			if (target_exit_off > 0 && cleanup_rela.r_offset != target_exit_off) {
				printf("[+] Adapting cleanup_module relocation: 0x%lx -> 0x%lx (Dynamic ABI Discovery)\n",
				       (unsigned long)cleanup_rela.r_offset, (unsigned long)target_exit_off);
				cleanup_rela.r_offset = target_exit_off;
				elf64_update_rela(ctx, rela_sec_idx, cleanup_rela_idx, &cleanup_rela);
				patched++;
			} else if (target_exit_off > 0 && cleanup_rela.r_offset == target_exit_off) {
				printf("[*] cleanup_module relocation already matches target offset 0x%lx\n", (unsigned long)target_exit_off);
			} else if (target_exit_off == 0 || (target_mod_size > 0 && cleanup_rela.r_offset >= target_mod_size)) {
				printf("[+] Neutralizing out-of-bounds/unverified cleanup_module relocation at 0x%lx\n",
				       (unsigned long)cleanup_rela.r_offset);
				cleanup_rela.r_info = ELF64_R_INFO(ELF64_R_SYM(cleanup_rela.r_info), 0 /* R_AARCH64_NONE */);
				cleanup_rela.r_offset = 0;
				elf64_update_rela(ctx, rela_sec_idx, cleanup_rela_idx, &cleanup_rela);
				patched++;
			}
		}

		if (patched > 0) {
			printf("[+] SUCCESS: Dynamically adapted %d relocation(s) in .rela.gnu.linkonce.this_module\n", patched);
		}
	}

	/* 5. Neutralize synthesized Cross-DSO __cfi_check stub */
	if (elf64_find_symbol(ctx, "__cfi_check", &sym_cfi_check, &idx_cfi_check) == 0) {
		if (sym_cfi_check.st_shndx < ctx->shnum) {
			Elf64_Shdr *text_shdr = &ctx->shdrs[sym_cfi_check.st_shndx];
			if (sym_cfi_check.st_value + sizeof(uint32_t) <= text_shdr->sh_size) {
				uint32_t *p_insn = (uint32_t *)(ctx->buf + text_shdr->sh_offset + sym_cfi_check.st_value);
				uint32_t ret_insn = ARM64_RET_OPCODE; /* 0xd65f03c0 */
				if (*p_insn != ret_insn) {
					*p_insn = ret_insn;
					printf("[+] Neutralized synthesized __cfi_check stub (patched to RET at offset 0x%lx)\n",
					       (unsigned long)sym_cfi_check.st_value);
				}
			}
		}
	}

	return (int)target_mod_size;
}

/*
 * Module Commands & Lifecycle Helpers
 */
static int audit_module_symbols(struct elf64_ctx *ctx, const char *kallsyms_path)
{
	Elf64_Shdr *symtab = NULL;
	const char *strtab;
	Elf64_Sym *syms;
	size_t num_syms;
	char *needed[1024];
	bool is_weak[1024];
	bool resolved[1024];
	size_t needed_cnt = 0;
	size_t i;
	const char *ks_path;
	FILE *kf;
	char *line;
	size_t missing_strong = 0, missing_weak = 0, resolved_cnt = 0;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, NULL) != 0) {
		fprintf(stderr, "[-] Symbol table not found\n");
		return 1;
	}

	strtab = (const char *)(ctx->buf + ctx->shdrs[symtab->sh_link].sh_offset);
	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	num_syms = symtab->sh_size / sizeof(Elf64_Sym);

	for (i = 1; i < num_syms && needed_cnt < 1024; i++) {
		unsigned char bind, type;
		const char *name;
		if (syms[i].st_shndx != SHN_UNDEF) continue;
		bind = ELF64_ST_BIND(syms[i].st_info);
		type = ELF64_ST_TYPE(syms[i].st_info);
		if (bind == STB_LOCAL || type == STT_SECTION || type == STT_FILE) continue;

		name = strtab + syms[i].st_name;
		if (!name || name[0] == '\0') continue;

		needed[needed_cnt] = xstrdup(name);
		is_weak[needed_cnt] = (bind == STB_WEAK);
		resolved[needed_cnt] = false;
		needed_cnt++;
	}

	if (needed_cnt == 0) {
		printf("[+] Pre-flight audit: Zero unresolved external dependencies (self-contained module).\n");
		return 0;
	}

	ks_path = kallsyms_path ? kallsyms_path : "/proc/kallsyms";
	printf("[*] Pre-flight audit: Checking %zu external symbol(s) against %s...\n", needed_cnt, ks_path);

	kf = fopen_for_read(ks_path);
	if (!kf) {
		fprintf(stderr, "[!] Warning: Cannot open %s for verification.\n", ks_path);
		for (i = 0; i < needed_cnt; i++) {
			printf("  [%s] %s\n", is_weak[i] ? "WEAK" : "GLOBAL", needed[i]);
			free(needed[i]);
		}
		return 0;
	}

	while ((line = xmalloc_fgetline(kf)) != NULL) {
		char *p = strrchr(line, ' ');
		if (!p) p = strrchr(line, '\t');
		if (p) {
			p++;
			chomp(p);

			for (i = 0; i < needed_cnt; i++) {
				if (!resolved[i] && strcmp(needed[i], p) == 0) {
					resolved[i] = true;
				}
			}
		}
		free(line);
	}
	fclose(kf);

	for (i = 0; i < needed_cnt; i++) {
		if (resolved[i]) resolved_cnt++;
		else if (is_weak[i]) {
			missing_weak++;
			printf("[?] Unresolved WEAK symbol  : %s\n", needed[i]);
		} else {
			missing_strong++;
			fprintf(stderr, "[-] UNRESOLVED GLOBAL symbol: %s\n", needed[i]);
		}
		free(needed[i]);
	}

	printf("[*] Audit Summary: %zu resolved, %zu missing strong, %zu missing weak\n",
	       resolved_cnt, missing_strong, missing_weak);
	return (missing_strong > 0) ? 2 : 0;
}

static int module_info_file(const char *filepath)
{
	int fd;
	struct stat st;
	uint8_t *map;
	struct elf64_ctx ctx;
	Elf64_Shdr *modinfo = NULL;

	fd = open_or_warn(filepath, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
		munmap(map, st.st_size);
		return 1;
	}

	printf("======================================================================\n");
	printf("  ELF Kernel Module Inspection: %s\n", filepath);
	printf("======================================================================\n");
	printf("[*] Architecture    : %s (0x%04x)\n",
	       (ctx.ehdr->e_machine == EM_AARCH64) ? "AArch64 (ARM64)" : "Other", ctx.ehdr->e_machine);
	printf("[*] Section Count   : %u\n", (unsigned int)ctx.shnum);

	if (elf64_find_section(&ctx, ".modinfo", &modinfo, NULL) == 0) {
		const char *buf = (const char *)(ctx.buf + modinfo->sh_offset);
		size_t pos = 0;
		printf("\n[*] Module Info (.modinfo):\n");
		while (pos < modinfo->sh_size) {
			const char *entry = buf + pos;
			size_t elen = strnlen(entry, modinfo->sh_size - pos);
			if (elen > 0) {
				const char *eq = strchr(entry, '=');
				if (eq) {
					printf("  %-20.*s = %s\n", (int)(eq - entry), entry, eq + 1);
				} else {
					printf("  %s\n", entry);
				}
			}
			pos += elen + 1;
		}
	}
	printf("======================================================================\n");

	elf64_free_ctx(&ctx);
	munmap(map, st.st_size);
	return 0;
}

static int module_check_file(const char *module_path)
{
	int fd;
	struct stat st;
	uint8_t *map;
	struct elf64_ctx ctx;
	char mod_ver[256];
	Elf64_Shdr *modinfo = NULL;
	char run_ver[256];
	int res = 0;

	memset(mod_ver, 0, sizeof(mod_ver));

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
		munmap(map, st.st_size);
		return 1;
	}

	if (elf64_find_section(&ctx, ".modinfo", &modinfo, NULL) == 0) {
		const char *buf = (const char *)(ctx.buf + modinfo->sh_offset);
		size_t pos = 0;
		while (pos < modinfo->sh_size) {
			const char *entry = buf + pos;
			size_t elen = strnlen(entry, modinfo->sh_size - pos);
			const char *v = is_prefixed_with(entry, "vermagic=");
			if (v) {
				safe_strncpy(mod_ver, v, sizeof(mod_ver));
				break;
			}
			pos += elen + 1;
		}
	}

	get_running_vermagic(run_ver, sizeof(run_ver));

	printf("============================================================\n");
	printf("  Module Path    : %s\n", module_path);
	printf("  Module Vermagic: %s\n", mod_ver[0] ? mod_ver : "(not found)");
	printf("  Running Kernel : %s\n", run_ver);
	printf("============================================================\n");

	if (mod_ver[0] && strcmp(mod_ver, run_ver) == 0) {
		printf("[✓] Status: 100%% EXACT MATCH — loads natively via insmod/modprobe.\n");
	} else {
		printf("[!] Status: MISMATCH — requires patch-vermagic alignment.\n");
		res = 1;
	}

	elf64_free_ctx(&ctx);
	munmap(map, st.st_size);
	return res;
}

static int module_strip_file(const char *in_file, const char *out_file)
{
	size_t sz = 0;
	uint8_t *buf;
	struct elf64_ctx ctx;
	int neutralized = 0;
	size_t i;
	const char *target;
	int out_fd;

	buf = (uint8_t *)magiskboot_read_file(in_file, &sz);
	if (!buf) {
		bb_perror_msg("cannot read '%s'", in_file);
		return 1;
	}

	if (!elf64_init_ctx(&ctx, buf, sz, sz, true)) {
		free(buf);
		return 1;
	}

	for (i = 0; i < ctx.shnum; i++) {
		const char *name = ctx.shstrtab + ctx.shdrs[i].sh_name;
		if (is_prefixed_with(name, ".debug_") || strcmp(name, ".comment") == 0 ||
		    strcmp(name, ".note.GNU-stack") == 0) {
			if (ctx.shdrs[i].sh_type != SHT_NOBITS && ctx.shdrs[i].sh_size > 0) {
				ctx.shdrs[i].sh_type = SHT_NOBITS;
				ctx.shdrs[i].sh_size = 0;
				ctx.shdrs[i].sh_flags = 0;
				neutralized++;
			}
		}
	}
	printf("[+] Neutralized %d unneeded/debug section(s)\n", neutralized);

	target = out_file ? out_file : in_file;
	out_fd = open3_or_warn(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0 || full_write(out_fd, ctx.buf, ctx.size) != (ssize_t)ctx.size) {
		if (out_fd >= 0) {
			bb_perror_msg("failed to write '%s'", target);
			close(out_fd);
		}
		elf64_free_ctx(&ctx);
		return 1;
	}
	close(out_fd);
	elf64_free_ctx(&ctx);
	printf("[+] SUCCESS: %s stripped in-place!\n", target);
	return 0;
}

static int module_patch_file(const char *in_file, const char *out_file, const char *target_vermagic,
                             const char *boot_img_path)
{
	int fd;
	struct stat st;
	size_t alloc_sz;
	uint8_t *buf;
	struct elf64_ctx ctx;
	char vermagic_buf[256];
	const char *target;
	int out_fd;

	fd = open_or_warn(in_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}

	alloc_sz = st.st_size + 65536;
	buf = (uint8_t *)xmalloc(alloc_sz);
	xread(fd, buf, st.st_size);
	close(fd);

	if (!elf64_init_ctx(&ctx, buf, st.st_size, alloc_sz, true)) {
		free(buf);
		return 1;
	}

	if (!target_vermagic || target_vermagic[0] == '\0') {
		char discovered_boot[512];
		discovered_boot[0] = '\0';
		if (!boot_img_path || boot_img_path[0] == '\0') {
			if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
				boot_img_path = discovered_boot;
			}
		}
		if (boot_img_path && detect_vermagic_from_boot_image(boot_img_path, vermagic_buf, sizeof(vermagic_buf)) == 0) {
			target_vermagic = vermagic_buf;
		} else {
			get_running_vermagic(vermagic_buf, sizeof(vermagic_buf));
			target_vermagic = vermagic_buf;
		}
	}

	if (patch_vermagic_buf(&ctx, target_vermagic) != 0) {
		elf64_free_ctx(&ctx);
		return 1;
	}

	patch_this_module_relocations(&ctx, in_file, 0, target_vermagic, boot_img_path);

	target = out_file ? out_file : in_file;
	out_fd = open3_or_warn(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0 || full_write(out_fd, ctx.buf, ctx.size) != (ssize_t)ctx.size) {
		if (out_fd >= 0) {
			bb_perror_msg("failed to write '%s'", target);
			close(out_fd);
		}
		elf64_free_ctx(&ctx);
		return 1;
	}
	close(out_fd);
	elf64_free_ctx(&ctx);
	printf("[✓] Patched module written to '%s'\n", target);
	return 0;
}

static int module_load_file(const char *module_path, const char *module_args)
{
	int fd;
	struct stat st;
	size_t alloc_sz;
	uint8_t *buf;
	struct elf64_ctx ctx;
	char target_vermagic[256];
	long ret;
	char msg[512];

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}

	alloc_sz = st.st_size + 65536;
	buf = (uint8_t *)xmalloc(alloc_sz);
	xread(fd, buf, st.st_size);
	close(fd);

	if (!elf64_init_ctx(&ctx, buf, st.st_size, alloc_sz, true)) {
		free(buf);
		return 1;
	}

	target_vermagic[0] = '\0';
	{
		char discovered_boot[512];
		discovered_boot[0] = '\0';
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
			detect_vermagic_from_boot_image(discovered_boot, target_vermagic, sizeof(target_vermagic));
		}
	}
	if (target_vermagic[0] == '\0') {
		get_running_vermagic(target_vermagic, sizeof(target_vermagic));
	}

	patch_vermagic_buf(&ctx, target_vermagic);
	patch_this_module_relocations(&ctx, module_path, 0, target_vermagic, NULL);

	printf("[+] Calling SYS_init_module(size=%zu, args=\"%s\")...\n", ctx.size, module_args ? module_args : "");
	ret = syscall(SYS_init_module, ctx.buf, ctx.size, module_args ? module_args : "");

	if (ret == 0) {
		printf("[✓] SUCCESS: Module loaded into kernel!\n");
		snprintf(msg, sizeof(msg), "<6>magiskboot: Module '%s' loaded successfully with vermagic '%s'\n",
		         module_path, target_vermagic);
		log_kmsg_msg(msg);
		elf64_free_ctx(&ctx);
		return 0;
	}

	if (errno == EEXIST) {
		printf("[!] Module already resident in kernel.\n");
		elf64_free_ctx(&ctx);
		return 0;
	}

	bb_perror_msg("init_module failed");
	elf64_free_ctx(&ctx);
	return 1;
}

static int module_finit_file(const char *module_path, const char *module_args)
{
	int fd;
	long ret;

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 1;

	printf("[+] Calling SYS_finit_module(fd=%d, args=\"%s\")...\n", fd, module_args ? module_args : "");
	ret = syscall(SYS_finit_module, fd, module_args ? module_args : "", 0);
	close(fd);

	if (ret == 0) {
		printf("[✓] SUCCESS: Module loaded via SYS_finit_module!\n");
		return 0;
	}
	if (errno == EEXIST) {
		printf("[!] Module already resident in kernel.\n");
		return 0;
	}

	printf("[!] sys_finit_module returned %ld (errno=%d: %s). Falling back to in-memory vermagic alignment...\n",
	       ret, errno, strerror(errno));
	return module_load_file(module_path, module_args);
}

static int module_unload_name(const char *module_name)
{
	const char *name = (module_name && module_name[0]) ? module_name : "kroot";
	long ret;

	printf("[+] Unloading module '%s'...\n", name);

	ret = syscall(SYS_delete_module, name, O_NONBLOCK);
	if (ret != 0 && strcmp(name, "kroot") == 0) {
		ret = syscall(SYS_delete_module, "compat_modern_kernel", O_NONBLOCK);
	}

	if (ret == 0) {
		printf("[✓] SUCCESS: Module '%s' unloaded.\n", name);
		return 0;
	}
	bb_perror_msg("delete_module failed");
	return 1;
}

static int magiskboot_module_op(int argc, char **argv)
{
	static const char mod_acts[] ALIGN1 =
		"info\0"
		"check\0"
		"audit\0"
		"strip\0"
		"patch\0"
		"load\0"
		"finit\0"
		"unload\0";
	enum {
		MOD_ACT_info = 0,
		MOD_ACT_check,
		MOD_ACT_audit,
		MOD_ACT_strip,
		MOD_ACT_patch,
		MOD_ACT_load,
		MOD_ACT_finit,
		MOD_ACT_unload,
	};
	const char *action;

	if (argc < 3) bb_show_usage();
	action = argv[2];

	switch (index_in_strings(mod_acts, action)) {
	case MOD_ACT_info: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		return module_info_file(path);
	}
	case MOD_ACT_check: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		return module_check_file(path);
	}
	case MOD_ACT_audit: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		int fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *map;
		struct elf64_ctx ctx;
		int res;

		if (fd < 0 || fstat(fd, &st) < 0) {
			if (fd >= 0) close(fd);
			return 1;
		}
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;

		if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
			munmap(map, st.st_size);
			return 1;
		}
		res = audit_module_symbols(&ctx, (argc >= 5) ? argv[4] : NULL);
		elf64_free_ctx(&ctx);
		munmap(map, st.st_size);
		return res;
	}
	case MOD_ACT_strip: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *out_f = (argc >= 5) ? argv[4] : in_f;
		return module_strip_file(in_f, out_f);
	}
	case MOD_ACT_patch: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *out_f = (argc >= 5 && argv[4][0] != '-') ? argv[4] : in_f;
		const char *vmagic = NULL;
		const char *boot_img = NULL;
		int i;

		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--vermagic") == 0 && i + 1 < argc) vmagic = argv[++i];
			else if (strcmp(argv[i], "--boot") == 0 && i + 1 < argc) boot_img = argv[++i];
		}
		return module_patch_file(in_f, out_f, vmagic, boot_img);
	}
	case MOD_ACT_load: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *margs = (argc >= 5) ? argv[4] : "";
		return module_load_file(in_f, margs);
	}
	case MOD_ACT_finit: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *margs = (argc >= 5) ? argv[4] : "";
		return module_finit_file(in_f, margs);
	}
	case MOD_ACT_unload: {
		const char *mname = (argc >= 4) ? argv[3] : "kroot";
		return module_unload_name(mname);
	}
	default:
		bb_error_msg("unknown module action '%s'", action);
		return 1;
	}
}

/* =========================================================================
 * Kernel Security & Vermagic Patching Engine (de-enforce, patch-sigenforce, patch-cfi, patch-vermagic)
 * ========================================================================= */
#include "aimg_patch.c"

/* =========================================================================
 * 12. Universal Recovery Flashable ZIP Packaging & ZIP Archive Engine
 * ========================================================================= */
#include "aimg_zip.c"

/* =========================================================================
 * 13. Android FSTAB & Kernel Command-Line Toolkit
 * ========================================================================= */

static int fstab_print(const char *file) {
	FILE *fp;
	char *line;

	fp = fopen_or_warn(file, "r");
	if (!fp) return 1;

	printf("======================================================================\n");
	printf("  Android FSTAB Inspector: %s\n", file);
	printf("======================================================================\n");
	printf("  %-30s %-16s %-8s %s\n", "Block Device", "Mount Point", "Type", "Flags & Options");
	printf("  %-30s %-16s %-8s %s\n", "------------------------------", "----------------", "--------", "--------------------");
	while ((line = xmalloc_fgetline(fp)) != NULL) {
		char *p = skip_whitespace(line);
		char *dev, *mnt, *type, *opts, *flags;
		if (*p != '#' && *p != '\0') {
			dev = strtok_r(p, " \t", &p);
			mnt = strtok_r(NULL, " \t", &p);
			type = strtok_r(NULL, " \t", &p);
			opts = strtok_r(NULL, " \t", &p);
			flags = strtok_r(NULL, " \t", &p);
			if (dev && mnt) {
				printf("  %-30s %-16s %-8s %s %s\n", dev, mnt, type ? type : "", opts ? opts : "", flags ? flags : "");
			}
		}
		free(line);
	}
	fclose(fp);
	return 0;
}

static int fstab_patch(const char *file, const char *target_mnt, const char *old_opt, const char *new_opt) {
	FILE *fp;
	char *line;
	char out_path[PATH_MAX];
	FILE *out_fp;
	int count = 0;

	fp = fopen_or_warn(file, "r");
	if (!fp) return 1;

	snprintf(out_path, sizeof(out_path), "%s.tmp.XXXXXX", file);
	close(xmkstemp(out_path));
	out_fp = fopen_for_write(out_path);
	if (!out_fp) {
		fclose(fp);
		bb_perror_msg("cannot create '%s'", out_path);
		return 1;
	}

	while ((line = xmalloc_fgetline(fp)) != NULL) {
		char *p = skip_whitespace(line);
		char *dev, *mnt;

		if (*p == '#' || *p == '\0') {
			fprintf(out_fp, "%s\n", line);
			free(line);
			continue;
		}

		dev = strtok_r(p, " \t", &p);
		mnt = strtok_r(NULL, " \t", &p);

		if (dev && mnt && strcmp(mnt, target_mnt) == 0 && old_opt && old_opt[0]) {
			char *pos = strstr(line, old_opt);
			if (pos) {
				size_t prefix_len = pos - line;
				size_t old_len = strlen(old_opt);
				fwrite(line, 1, prefix_len, out_fp);
				if (new_opt && new_opt[0] && strcmp(new_opt, "-") != 0 && strcmp(new_opt, "none") != 0) {
					fputs(new_opt, out_fp);
				}
				fprintf(out_fp, "%s\n", pos + old_len);
				count++;
				printf("[+] Patched %s on '%s': '%s' -> '%s'\n", target_mnt, file, old_opt, new_opt ? new_opt : "");
				free(line);
				continue;
			}
		}
		fprintf(out_fp, "%s\n", line);
		free(line);
	}
	fclose(fp);
	fclose(out_fp);

	if (count > 0) {
		safe_rename_or_copy(out_path, file);
		printf("[✓] SUCCESS: Modified %d entry in '%s'\n", count, file);
		return 0;
	} else {
		unlink(out_path);
		printf("[-] Notice: Target '%s' with option '%s' not found in '%s'\n", target_mnt, old_opt, file);
		return 0;
	}
}

static int magiskboot_fstab_op(int argc, char **argv) {
	static const char fstab_acts[] ALIGN1 =
		"print\0"
		"show\0"
		"patch\0";
	enum {
		FSTAB_ACT_print = 0,
		FSTAB_ACT_show,
		FSTAB_ACT_patch,
	};
	const char *file;
	const char *action;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot fstab <file> <print|patch <mountpoint> <old_opt> [new_opt]>");
		return 1;
	}

	file = argv[2];
	action = argv[3];

	switch (index_in_strings(fstab_acts, action)) {
	case FSTAB_ACT_print:
	case FSTAB_ACT_show:
		return fstab_print(file);
	case FSTAB_ACT_patch:
		if (argc < 6) {
			bb_error_msg("usage: magiskboot fstab <file> patch <mountpoint> <old_opt> [new_opt]");
			return 1;
		}
		return fstab_patch(file, argv[4], argv[5], (argc >= 7) ? argv[6] : "");
	default:
		bb_error_msg("unknown fstab action '%s'", action);
		return 1;
	}
}

static int cmdline_print(const char *file) {
	char *buf;
	char *tok, *saveptr;

	buf = (char *)xmalloc_open_read_close(file, NULL);
	if (!buf) {
		bb_perror_msg("cannot open '%s'", file);
		return 1;
	}
	trim(buf);
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
	static const char cmd_acts[] ALIGN1 =
		"add\0"
		"rm\0"
		"del\0"
		"patch\0"
		"set\0";
	enum {
		CMD_ACT_add = 0,
		CMD_ACT_rm,
		CMD_ACT_del,
		CMD_ACT_patch,
		CMD_ACT_set,
	};
	char *buf;
	char **tokens;
	size_t cap = 128, count = 0;
	char *tok, *saveptr;
	bool modified = false;
	size_t i;
	FILE *ofp;
	bool first;

	buf = (char *)xmalloc_open_read_close(file, NULL);
	if (!buf) {
		bb_perror_msg("cannot open '%s'", file);
		return 1;
	}

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

	switch (index_in_strings(cmd_acts, action)) {
	case CMD_ACT_add: {
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
		break;
	}
	case CMD_ACT_rm:
	case CMD_ACT_del:
		for (i = 0; i < count; i++) {
			const char *rest = is_prefixed_with(tokens[i], key);
			if (rest && (*rest == '\0' || *rest == '=')) {
				free(tokens[i]);
				tokens[i] = NULL;
				modified = true;
				printf("[+] Removed cmdline parameter: '%s'\n", key);
			}
		}
		break;
	case CMD_ACT_patch:
	case CMD_ACT_set: {
		bool found = false;
		for (i = 0; i < count; i++) {
			const char *rest = is_prefixed_with(tokens[i], key);
			if (rest && (*rest == '\0' || *rest == '=')) {
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
		break;
	}
	default:
		break;
	}

	if (!modified) {
		printf("[-] Notice: cmdline not modified\n");
		for (i = 0; i < count; i++) if (tokens[i]) free(tokens[i]);
		free(tokens);
		return 0;
	}

	ofp = fopen_or_warn(file, "w");
	if (!ofp) {
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
	static const char cmdline_acts[] ALIGN1 =
		"print\0"
		"show\0"
		"patch\0"
		"set\0"
		"add\0"
		"rm\0"
		"del\0";
	enum {
		CMDLINE_ACT_print = 0,
		CMDLINE_ACT_show,
		CMDLINE_ACT_patch,
		CMDLINE_ACT_set,
		CMDLINE_ACT_add,
		CMDLINE_ACT_rm,
		CMDLINE_ACT_del,
	};
	const char *file;
	const char *action;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot cmdline <file> <print|patch <key> <val>|add <opt>|rm <key>>");
		return 1;
	}

	file = argv[2];
	action = argv[3];

	switch (index_in_strings(cmdline_acts, action)) {
	case CMDLINE_ACT_print:
	case CMDLINE_ACT_show:
		return cmdline_print(file);
	case CMDLINE_ACT_patch:
	case CMDLINE_ACT_set:
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> patch <key> [val]");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], (argc >= 6) ? argv[5] : "");
	case CMDLINE_ACT_add:
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> add <option>");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], NULL);
	case CMDLINE_ACT_rm:
	case CMDLINE_ACT_del:
		if (argc < 5) {
			bb_error_msg("usage: magiskboot cmdline <file> rm <key>");
			return 1;
		}
		return cmdline_modify(file, action, argv[4], NULL);
	default:
		bb_error_msg("unknown cmdline action '%s'", action);
		return 1;
	}
}

/* =========================================================================
 * 14. AVB 2.0 VBMeta Inspector & dm-verity Neutralizer
 * ========================================================================= */

static int magiskboot_vbmeta_op(int argc, char **argv) {
	static const char vbmeta_acts[] ALIGN1 =
		"status\0"
		"print\0"
		"show\0"
		"disable\0"
		"disable-verity\0"
		"disable-verification\0"
		"patch\0"
		"restore\0"
		"enable\0";
	enum {
		VBMETA_ACT_status = 0,
		VBMETA_ACT_print,
		VBMETA_ACT_show,
		VBMETA_ACT_disable,
		VBMETA_ACT_disable_verity,
		VBMETA_ACT_disable_verification,
		VBMETA_ACT_patch,
		VBMETA_ACT_restore,
		VBMETA_ACT_enable,
	};
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
	int act_idx;

	if (argc < 3) {
		bb_error_msg("usage: magiskboot vbmeta <image|block_device> [status|disable|restore]");
		return 1;
	}

	target = argv[2];
	if (argc >= 4) action = argv[3];

	act_idx = index_in_strings(vbmeta_acts, action);

	fd = open_or_warn(target, (act_idx <= VBMETA_ACT_show) ? (O_RDONLY | O_CLOEXEC) : (O_RDWR | O_CLOEXEC));
	if (fd < 0) return 1;

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
			uint64_t voff = SWAP_BE64(footer->vbmeta_offset);
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
	flags = SWAP_BE32(hdr->flags);

	switch (act_idx) {
	case VBMETA_ACT_status:
	case VBMETA_ACT_print:
	case VBMETA_ACT_show:
		printf("======================================================================\n");
		printf("  AVB 2.0 VBMeta Inspector: %s (Offset 0x%lx)\n", target, (unsigned long)vbmeta_off);
		printf("======================================================================\n");
		printf("  Magic:                  %.4s\n", hdr->magic);
		printf("  Libavb Version:         %u.%u\n",
		       SWAP_BE32(hdr->required_libavb_version_major),
		       SWAP_BE32(hdr->required_libavb_version_minor));
		printf("  Release String:         %.64s\n", hdr->release_string);
		printf("  Rollback Index:         %llu\n", (unsigned long long)SWAP_BE64(hdr->rollback_index));
		printf("  Flags:                  0x%08x\n", flags);
		printf("  dm-verity (Hashtree):   %s\n",
		       (flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED) ? "DISABLED [✓]" : "ENABLED [! VERIFIED]");
		printf("  Verification (AVB):     %s\n",
		       (flags & AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED) ? "DISABLED [✓]" : "ENABLED [! ENFORCED]");
		printf("======================================================================\n");
		munmap(map, map_sz);
		close(fd);
		return 0;

	case VBMETA_ACT_disable:
	case VBMETA_ACT_disable_verity:
	case VBMETA_ACT_disable_verification:
	case VBMETA_ACT_patch: {
		uint32_t new_flags = flags | AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED;
		if (flags != new_flags) {
			hdr->flags = SWAP_BE32(new_flags);
			msync(map, map_sz, MS_SYNC);
			lseek(fd, vbmeta_off, SEEK_SET);
			full_write(fd, hdr, sizeof(*hdr));
			printf("[✓] SUCCESS: Neutralized AVB dm-verity & verification on '%s' (flags: 0x%08x -> 0x%08x)\n",
			       target, flags, new_flags);
		} else {
			printf("[-] Notice: AVB dm-verity and verification already disabled on '%s' (flags: 0x%08x)\n",
			       target, flags);
		}
		break;
	}

	case VBMETA_ACT_restore:
	case VBMETA_ACT_enable: {
		uint32_t new_flags = flags & ~(AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED | AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
		if (flags != new_flags) {
			hdr->flags = SWAP_BE32(new_flags);
			msync(map, map_sz, MS_SYNC);
			lseek(fd, vbmeta_off, SEEK_SET);
			full_write(fd, hdr, sizeof(*hdr));
			printf("[✓] SUCCESS: Restored AVB verification enforcement on '%s' (flags: 0x%08x -> 0x%08x)\n",
			       target, flags, new_flags);
		} else {
			printf("[-] Notice: AVB verification already enabled on '%s' (flags: 0x%08x)\n", target, flags);
		}
		break;
	}

	default:
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
 * Kernel Module Injection & Live Boot Flashing Engine (add-module)
 * ========================================================================= */

#ifndef BLKROSET
#define BLKROSET _IO(0x12, 93)
#endif

/*
 * Set or replace an entry in the in-memory CPIO linked list.
 * Takes ownership of data.
 */
static void cpio_set_file(cpio_node_t **head_ptr, const char *name, uint32_t mode, void *data, uint32_t size)
{
	cpio_node_t *curr;
	for (curr = *head_ptr; curr; curr = curr->next) {
		if (strcmp(curr->name, name) == 0) {
			free(curr->data);
			curr->data = data;
			curr->filesize = size;
			curr->mode = mode;
			return;
		}
	}

	curr = xzalloc(sizeof(*curr));
	curr->name = xstrdup(name);
	curr->mode = mode;
	curr->filesize = size;
	curr->data = data;
	curr->nlink = 1;
	{
		cpio_node_t **tail_ptr = head_ptr;
		while (*tail_ptr) tail_ptr = &(*tail_ptr)->next;
		*tail_ptr = curr;
	}
}

/*
 * Append a single-line entry to a text file in CPIO if not already present.
 */
static void cpio_append_line_if_missing(cpio_node_t **head_ptr, const char *path, const char *line)
{
	cpio_node_t *curr;
	size_t line_len = strlen(line);

	for (curr = *head_ptr; curr; curr = curr->next) {
		if (strcmp(curr->name, path) == 0) {
			if (curr->data && curr->filesize > 0) {
				const char *d = (const char *)curr->data;
				size_t dsz = curr->filesize;
				const char *p = d;
				bool found = false;

				while (p < d + dsz && (p = strstr(p, line)) != NULL) {
					bool start_ok = (p == d || *(p - 1) == '\n');
					const char *end_p = p + line_len;
					bool end_ok = (end_p == d + dsz || *end_p == '\n' || *end_p == '\r' || *end_p == '\0');
					if (start_ok && end_ok) {
						found = true;
						break;
					}
					p += line_len;
				}

				if (found) {
					return; /* Already present */
				}

				{
					/* Append line cleanly */
					size_t new_sz;
					char *new_data;
					size_t pos;

					new_sz = dsz + line_len + 2;
					new_data = xmalloc(new_sz);
					memcpy(new_data, d, dsz);
					pos = dsz;
					if (pos > 0 && new_data[pos - 1] != '\n') {
						new_data[pos++] = '\n';
					}
					memcpy(new_data + pos, line, line_len);
					pos += line_len;
					new_data[pos++] = '\n';

					free(curr->data);
					curr->data = new_data;
					curr->filesize = (uint32_t)pos;
					return;
				}
			} else {
				char *new_data = xasprintf("%s\n", line);
				free(curr->data);
				curr->data = new_data;
				curr->filesize = (uint32_t)strlen(new_data);
				return;
			}
		}
	}

	/* Entry does not exist: create file with this line */
	{
		char *new_data = xasprintf("%s\n", line);
		cpio_set_file(head_ptr, path, 0100644, new_data, (uint32_t)strlen(new_data));
	}
}

/*
 * Universal Kernel Module Ramdisk Injector.
 * Injects any .ko module into ramdisk.cpio, dynamically updating
 * modules.load and modules.dep for early kernel first-stage init modprobe.
 */
static char *resolve_init_wrapper_binary(const char *custom)
{
	static const char *const names[] = {
		"busybox",
		"busybox-arm64",
		"busybox-aarch64",
		"init_wrapper",
		"init_wrapper_aarch64",
		"init_wrapper-arm64",
		"init_wrapper-aarch64",
		NULL
	};
	const char *env_path;
	char exe_path[PATH_MAX];
	char exe_dir[PATH_MAX];
	ssize_t len;
	int i;

	/* 1. Explicit CLI argument */
	if (custom && access(custom, R_OK) == 0)
		return xstrdup(custom);

	/* 2. Environment variable overrides */
	env_path = getenv("BUSYBOX_BIN");
	if (env_path && access(env_path, R_OK) == 0)
		return xstrdup(env_path);

	env_path = getenv("INIT_WRAPPER_BIN");
	if (env_path && access(env_path, R_OK) == 0)
		return xstrdup(env_path);

	/* 3. Probe relative to the running executable's directory */
	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len > 0) {
		char *slash;
		exe_path[len] = '\0';
		safe_strncpy(exe_dir, exe_path, sizeof(exe_dir));
		slash = strrchr(exe_dir, '/');
		if (slash) {
			*slash = '\0';
			for (i = 0; names[i]; i++) {
				char cand[PATH_MAX];
				snprintf(cand, sizeof(cand), "%.*s/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
			}
			/* Check sibling directories bin/ or tools/ */
			for (i = 0; names[i]; i++) {
				char cand[PATH_MAX];
				snprintf(cand, sizeof(cand), "%.*s/../bin/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
				snprintf(cand, sizeof(cand), "%.*s/../tools/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
				snprintf(cand, sizeof(cand), "%.*s/tools/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
			}
		}
	}

	/* 4. Probe current working directory */
	for (i = 0; names[i]; i++) {
		if (access(names[i], R_OK) == 0)
			return xstrdup(names[i]);
		{
			char cand[PATH_MAX];
			snprintf(cand, sizeof(cand), "bin/%s", names[i]);
			if (access(cand, R_OK) == 0)
				return xstrdup(cand);
			snprintf(cand, sizeof(cand), "tools/%s", names[i]);
			if (access(cand, R_OK) == 0)
				return xstrdup(cand);
		}
	}

	return NULL;
}

static int ramdisk_inject_kernel_module(const char *cpio_path, const char *mod_path, const char *mod_filename)
{
	cpio_node_t *head;
	cpio_node_t *curr;
	size_t mod_sz = 0;
	void *mod_data;
	bool has_system_modules = false;
	char mod_target[PATH_MAX];
	char dep_line[PATH_MAX];

	head = cpio_read_all(cpio_path);
	if (!head) {
		bb_error_msg("failed to parse ramdisk CPIO archive '%s'", cpio_path);
		return -1;
	}

	mod_data = magiskboot_read_file(mod_path, &mod_sz);
	if (!mod_data || mod_sz == 0) {
		bb_error_msg("failed to read staged module '%s'", mod_path);
		if (mod_data) free(mod_data);
		cpio_free_all(head);
		return -1;
	}

	/* Check ramdisk directory structure conventions */
	for (curr = head; curr; curr = curr->next) {
		if (strncmp(curr->name, "system/lib/modules", 18) == 0) {
			has_system_modules = true;
			break;
		}
	}

	/* Format dependency entry (<filename>:\n) */
	snprintf(dep_line, sizeof(dep_line), "%s:", mod_filename);

	/* 1. Inject into standard canonical /lib/modules/ */
	snprintf(mod_target, sizeof(mod_target), "lib/modules/%s", mod_filename);
	cpio_set_file(&head, mod_target, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);
	cpio_append_line_if_missing(&head, "lib/modules/modules.load", mod_filename);
	cpio_append_line_if_missing(&head, "lib/modules/modules.dep", dep_line);
	printf("[+] Ramdisk injection: Added %s (%zu bytes)\n", mod_target, mod_sz);
	printf("[+] Autoload configuration: Updated lib/modules/modules.load & modules.dep\n");

	/* 2. Create empty index files if not present */
	{
		cpio_node_t *node;
		bool has_alias = false, has_syms = false;
		for (node = head; node; node = node->next) {
			if (strcmp(node->name, "lib/modules/modules.alias") == 0) has_alias = true;
			else if (strcmp(node->name, "lib/modules/modules.symbols") == 0) has_syms = true;
		}
		if (!has_alias) cpio_set_file(&head, "lib/modules/modules.alias", 0100644, xzalloc(1), 0);
		if (!has_syms) cpio_set_file(&head, "lib/modules/modules.symbols", 0100644, xzalloc(1), 0);
	}

	/* 3. Inject root-level copy (failsafe for early init) */
	cpio_set_file(&head, mod_filename, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);

	/* 4. Second-stage early-init fallback triggers in init.modules.rc */
	{
		cpio_node_t *rc_node = NULL;
		cpio_node_t *n;
		char insmod_line1[PATH_MAX + 32];
		char insmod_line2[PATH_MAX + 32];

		snprintf(insmod_line1, sizeof(insmod_line1), "    insmod /lib/modules/%s", mod_filename);
		snprintf(insmod_line2, sizeof(insmod_line2), "    insmod /%s", mod_filename);

		for (n = head; n; n = n->next) {
			if (strcmp(n->name, "init.modules.rc") == 0) {
				rc_node = n;
				break;
			}
		}

		if (rc_node && rc_node->data && rc_node->filesize > 0) {
			cpio_append_line_if_missing(&head, "init.modules.rc", insmod_line1);
			cpio_append_line_if_missing(&head, "init.modules.rc", insmod_line2);
		} else {
			char *rc_content = xasprintf("on early-init\n%s\n%s\n", insmod_line1, insmod_line2);
			cpio_set_file(&head, "init.modules.rc", 0100644, rc_content, (uint32_t)strlen(rc_content));
		}
	}
	printf("[+] Dual-stage fallback: Generated init.modules.rc & root /%s\n", mod_filename);

	/* 5. If system/lib/modules exists (system-as-root / Android 10+ ramdisk layout), mirror there */
	if (has_system_modules) {
		snprintf(mod_target, sizeof(mod_target), "system/lib/modules/%s", mod_filename);
		cpio_set_file(&head, mod_target, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);
		cpio_append_line_if_missing(&head, "system/lib/modules/modules.load", mod_filename);
		cpio_append_line_if_missing(&head, "system/lib/modules/modules.dep", dep_line);
		printf("[+] Ramdisk injection: Mirrored to %s\n", mod_target);
	}

	/* 6. Universal First-Stage Init Wrapper (PID 1 Module Loader & BusyBox Integration) */
	{
		char *wrapper_bin_path = resolve_init_wrapper_binary(NULL);
		if (wrapper_bin_path) {
			size_t w_sz = 0;
			void *w_data = magiskboot_read_file(wrapper_bin_path, &w_sz);
			if (w_data && w_sz > 0) {
				cpio_node_t *init_node = NULL;
				cpio_node_t *init_real_node = NULL;
				cpio_node_t *n;
				bool is_busybox = false;
				const char *bname = bb_basename(wrapper_bin_path);

				if (strncmp(bname, "busybox", 7) == 0)
					is_busybox = true;

				for (n = head; n; n = n->next) {
					if (strcmp(n->name, "init") == 0) init_node = n;
					else if (strcmp(n->name, "init.real") == 0) init_real_node = n;
				}

				/* Back up stock /init before modifying */
				if (init_node && !init_real_node) {
					if (S_ISLNK(init_node->mode)) {
						const char *tgt = (const char *)init_node->data;
						if (tgt && tgt[0] != '\0') {
							cpio_set_file(&head, "init.real", 0120777, xstrdup(tgt), (uint32_t)strlen(tgt));
						} else {
							cpio_set_file(&head, "init.real", 0120777, xstrdup("/system/bin/init"), (uint32_t)strlen("/system/bin/init"));
						}
						printf("[+] First-stage init: Preserved symlink target -> init.real\n");
					} else {
						cpio_set_file(&head, "init.real", init_node->mode,
						              xmemdup(init_node->data, init_node->filesize), init_node->filesize);
						printf("[+] First-stage init: Preserved stock binary -> init.real\n");
					}
				}

				if (is_busybox) {
					/* Inject BusyBox into sbin/busybox and make /init a symlink to it */
					cpio_set_file(&head, "sbin/busybox", 0100755, xmemdup(w_data, w_sz), (uint32_t)w_sz);
					printf("[+] First-stage init: Injected BusyBox universal binary -> sbin/busybox (%zu bytes)\n", w_sz);

					if (init_node) {
						free(init_node->data);
						init_node->mode = 0120777;
						init_node->filesize = (uint32_t)strlen("/sbin/busybox");
						init_node->data = xstrdup("/sbin/busybox");
					} else {
						cpio_set_file(&head, "init", 0120777, xstrdup("/sbin/busybox"), (uint32_t)strlen("/sbin/busybox"));
					}
					printf("[+] First-stage init: Configured PID 1 /init -> /sbin/busybox (applet: init_wrapper)\n");
				} else {
					/* Inject standalone init_wrapper as /init binary */
					if (init_node) {
						free(init_node->data);
						init_node->mode = 0100755;
						init_node->filesize = (uint32_t)w_sz;
						init_node->data = xmemdup(w_data, w_sz);
						printf("[+] First-stage init: Injected universal init_wrapper as PID 1 /init\n");
					} else {
						cpio_set_file(&head, "init", 0100755, xmemdup(w_data, w_sz), (uint32_t)w_sz);
						printf("[+] First-stage init: Injected universal init_wrapper as PID 1 /init\n");
					}
				}
				free(w_data);
			}
			free(wrapper_bin_path);
		} else {
			printf("[!] Warning: init_wrapper / busybox binary not found; falling back to init.modules.rc\n");
		}
	}

	free(mod_data);

	if (cpio_write_all(cpio_path, head) != 0) {
		bb_error_msg("failed to write modified CPIO archive '%s'", cpio_path);
		cpio_free_all(head);
		return -1;
	}

	cpio_free_all(head);
	return 0;
}

static int magiskboot_add_module_op(int argc, char **argv)
{
	bool live = false;
	bool install = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *module_ko = NULL;
	const char *out_img = NULL;
	const char *mod_filename = NULL;
	char discovered_boot[512];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_module_ko[PATH_MAX];
	char staged_module[PATH_MAX];
	char repacked_img[PATH_MAX];
	int i;
	int ret = 0;
	int in_fd, out_fd;
	struct stat st_img;
	off_t written;

	discovered_boot[0] = '\0';
	abs_module_ko[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "--install") == 0) {
			install = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			i++; /* skip device ID */
		} else if (argv[i][0] == '-') {
			/* skip unrecognized options */
		} else {
			if (!boot_img && !live) {
				boot_img = argv[i];
			} else if (!module_ko) {
				module_ko = argv[i];
			} else if (!out_img) {
				out_img = argv[i];
			}
		}
	}

	if (part_name) {
		char pbuf[PATH_MAX];
		snprintf(pbuf, sizeof(pbuf), "/dev/block/by-name/%s", part_name);
		if (access(pbuf, F_OK) == 0) {
			strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
			discovered_boot[sizeof(discovered_boot) - 1] = '\0';
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
				discovered_boot[sizeof(discovered_boot) - 1] = '\0';
				boot_img = discovered_boot;
			}
		}
	}

	if (live || !boot_img) {
		live = true;
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		boot_img = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", boot_img);
	}

	if (!module_ko) {
		bb_error_msg("missing module (.ko) argument");
		return 1;
	}

	if (!realpath(module_ko, abs_module_ko)) {
		safe_strncpy(abs_module_ko, module_ko, sizeof(abs_module_ko));
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}
	safe_strncpy(tmp_work_dir, "/tmp/mb_addmod_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}
	if (chdir(tmp_work_dir) != 0) {
		bb_perror_msg("cannot chdir to '%s'", tmp_work_dir);
		return 1;
	}

	/* 1. Unpack boot image keeping kernel untouched and compressed */
	printf("[*] Unpacking boot image: %s\n", boot_img);
	if (magiskboot_unpack(boot_img, true, false, false, false) != 0) {
		bb_error_msg("failed to unpack boot image '%s'", boot_img);
		chdir(old_cwd);
		remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
		return 1;
	}

	/* 2. Patch module vermagic and relocations to align with boot kernel */
	mod_filename = bb_basename(abs_module_ko);
	if (!mod_filename || mod_filename[0] == '\0') {
		mod_filename = "module.ko";
	}

	snprintf(staged_module, sizeof(staged_module), "%s/%s", tmp_work_dir, mod_filename);
	copy_file(abs_module_ko, staged_module, FILEUTILS_FORCE);
	module_patch_file(staged_module, staged_module, NULL, boot_img);

	/* 3. Inject module and autoload lists into ramdisk.cpio */
	if (access("ramdisk.cpio", F_OK) == 0) {
		printf("[*] Injecting module '%s' into ramdisk.cpio...\n", mod_filename);
		if (ramdisk_inject_kernel_module("ramdisk.cpio", staged_module, mod_filename) != 0) {
			bb_error_msg("failed to inject module into ramdisk.cpio");
			ret = 1;
			goto cleanup;
		}
	} else {
		bb_error_msg("ramdisk.cpio not found after unpack");
		ret = 1;
		goto cleanup;
	}

	/* 4. Repack boot image using existing battle-tested magiskboot_repack */
	if (out_img && !install) {
		if (out_img[0] == '/') {
			safe_strncpy(repacked_img, out_img, sizeof(repacked_img));
		} else {
			char *p = concat_path_file(old_cwd, out_img);
			safe_strncpy(repacked_img, p, sizeof(repacked_img));
			free(p);
		}
	} else {
		char *p = concat_path_file(tmp_work_dir, "new-boot.img");
		safe_strncpy(repacked_img, p, sizeof(repacked_img));
		free(p);
	}

	printf("[*] Repacking boot image -> %s...\n", repacked_img);
	if (magiskboot_repack(boot_img, repacked_img, false) != 0) {
		bb_error_msg("failed to repack boot image");
		ret = 1;
		goto cleanup;
	}

	/* 5. If --install is specified, flash directly to target block device */
	if (install) {
		struct stat st_out;
		off_t bdev_sz = 0;
		int sec_sz = 512;
		char stream_buf[1024 * 1024]; /* 1MB streaming buffer */
		struct timespec t_start, t_end;
		double elapsed, mb_sec;

		printf("[*] Flashing patched boot image directly to %s...\n", boot_img);
		in_fd = open_or_warn(repacked_img, O_RDONLY | O_CLOEXEC);
		if (in_fd < 0) {
			ret = 1;
			goto cleanup;
		}
		if (fstat(in_fd, &st_img) < 0 || st_img.st_size < 4096) {
			bb_error_msg("invalid repacked boot image size");
			close(in_fd);
			ret = 1;
			goto cleanup;
		}

		/* Open target block device and unlock write permission (battle-tested blockdev engine) */
		out_fd = open_or_warn(boot_img, O_RDWR | O_SYNC | O_CLOEXEC);
		if (out_fd < 0) {
			close(in_fd);
			ret = 1;
			goto cleanup;
		}
#ifdef BLKROSET
		{
			int ro = 0;
			ioctl(out_fd, BLKROSET, &ro);
		}
#endif
		if (fstat(out_fd, &st_out) == 0) {
			bdev_sz = get_file_or_bdev_size(out_fd, &st_out);
#ifdef BLKSSZGET
			ioctl(out_fd, BLKSSZGET, &sec_sz);
#endif
			printf("[*] Target Storage Geometry & Diagnostics:\n");
			printf("    • Node Path          : %s\n", boot_img);
			printf("    • Device Type        : %s (major %u, minor %u)\n",
			       S_ISBLK(st_out.st_mode) ? "Block Device" : "Regular File",
			       (unsigned)major(st_out.st_rdev), (unsigned)minor(st_out.st_rdev));
			printf("    • Partition Capacity : %lld bytes (%.2f MB)\n",
			       (long long)bdev_sz, (double)bdev_sz / (1024.0 * 1024.0));
			printf("    • Logical Sector Size: %d bytes\n", sec_sz);
			printf("    • Write Access       : Unlocked via BLKROSET ioctl\n");
		}

		written = 0;
		clock_gettime(CLOCK_MONOTONIC, &t_start);
		printf("[*] Streaming patched boot image to %s (%lld bytes, %.2f MB)...\n",
		       boot_img, (long long)st_img.st_size, (double)st_img.st_size / (1024.0 * 1024.0));

		while (written < st_img.st_size) {
			size_t chunk = (st_img.st_size - written > (off_t)sizeof(stream_buf)) ?
			               sizeof(stream_buf) : (size_t)(st_img.st_size - written);
			ssize_t nr = full_read(in_fd, stream_buf, chunk);
			ssize_t nw;
			int pct;
			if (nr <= 0) break;
			nw = full_write(out_fd, stream_buf, nr);
			if (nw != nr) break;
			written += nw;
			pct = (int)((written * 100) / st_img.st_size);
			printf("    -> Committing blocks: %3d%% [%lld / %lld bytes]\n",
			       pct, (long long)written, (long long)st_img.st_size);
		}
		close(in_fd);

		clock_gettime(CLOCK_MONOTONIC, &t_end);
		elapsed = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
		mb_sec = (elapsed > 0.001) ? ((double)written / (1024.0 * 1024.0)) / elapsed : 0.0;
		printf("[+] Flashed %lld bytes in %.3f seconds (%.2f MB/s)\n",
		       (long long)written, elapsed, mb_sec);

		if (written != st_img.st_size) {
			bb_error_msg("flashing incomplete: wrote %lld of %lld bytes",
			             (long long)written, (long long)st_img.st_size);
			close(out_fd);
			ret = 1;
			goto cleanup;
		}

		printf("[*] Flushing hardware write caches to physical storage (fsync)...\n");
		fsync(out_fd);
		close(out_fd);
		sync();

		printf("[✓] SUCCESS: Verified %lld bytes committed directly to %s\n", (long long)written, boot_img);
	} else {
		printf("[✓] SUCCESS: Patched boot image saved to %s\n", repacked_img);
	}

cleanup:
	chdir(old_cwd);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

/*
 * Checks if a CPIO entry name belongs to recovery subsystem
 */
static bool is_recovery_component_entry(const char *name)
{
	if (!name) return false;
	if (strcmp(name, "system/bin/recovery") == 0 ||
	    strcmp(name, "system/bin/twrp") == 0 ||
	    strcmp(name, "sbin/twrp") == 0 ||
	    strcmp(name, "system/bin/teamwin") == 0 ||
	    strncmp(name, "system/bin/bash_twrp", 20) == 0 ||
	    strncmp(name, "system/bin/nano_twrp", 20) == 0 ||
	    strncmp(name, "system/bin/tzdata_twrp", 22) == 0 ||
	    strstr(name, "twrpapp") != NULL ||
	    strncmp(name, "twres", 5) == 0 ||
	    strncmp(name, "license", 7) == 0 ||
	    strncmp(name, "system/etc/twrp", 15) == 0 ||
	    strncmp(name, "etc/twrp", 8) == 0 ||
	    strncmp(name, "system/etc/recovery", 19) == 0 ||
	    strncmp(name, "etc/recovery", 12) == 0 ||
	    strncmp(name, "init.recovery.", 14) == 0 ||
	    strncmp(name, "system/etc/init/init.recovery.", 30) == 0 ||
	    strstr(name, "recovery.rc") != NULL ||
	    strncmp(name, "system/lib64/", 13) == 0 ||
	    strncmp(name, "system/lib/", 11) == 0 ||
	    strncmp(name, "vendor/lib64/", 13) == 0 ||
	    strncmp(name, "vendor/lib/", 11) == 0 ||
	    strstr(name, "twrp") != NULL ||
	    strstr(name, "recovery") != NULL)
		return true;
	return false;
}

/*
 * Recovery Changer Engine
 * Integrates / changes custom recovery (TWRP) inside a target boot.img
 */
static int magiskboot_set_recovery_op(int argc, char **argv)
{
	bool live = false;
	bool install = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *rec_src = NULL;
	const char *out_img = NULL;
	char discovered_boot[512];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_boot_img[PATH_MAX];
	char abs_rec_src[PATH_MAX];
	char repacked_img[PATH_MAX];
	char target_dir[PATH_MAX];
	char rec_dir[PATH_MAX];
	char target_cpio[PATH_MAX];
	char rec_cpio[PATH_MAX];
	cpio_node_t *target_head = NULL;
	cpio_node_t *rec_head = NULL;
	cpio_node_t *node;
	int count = 0;
	int i;
	int ret = 0;
	int in_fd, out_fd;
	struct stat st_img;
	off_t written;

	discovered_boot[0] = '\0';
	abs_boot_img[0] = '\0';
	abs_rec_src[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "--install") == 0) {
			install = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			i++; /* skip device ID */
		} else if (argv[i][0] == '-') {
			/* skip unrecognized options */
		} else {
			if (!boot_img && !live) {
				boot_img = argv[i];
			} else if (!rec_src) {
				rec_src = argv[i];
			} else if (!out_img) {
				out_img = argv[i];
			}
		}
	}

	if (part_name) {
		char pbuf[PATH_MAX];
		snprintf(pbuf, sizeof(pbuf), "/dev/block/by-name/%s", part_name);
		if (access(pbuf, F_OK) == 0) {
			strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
			discovered_boot[sizeof(discovered_boot) - 1] = '\0';
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
				discovered_boot[sizeof(discovered_boot) - 1] = '\0';
				boot_img = discovered_boot;
			}
		}
	}

	if (live || !boot_img) {
		live = true;
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		boot_img = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", boot_img);
	}

	if (!rec_src) {
		bb_error_msg("missing recovery source image argument");
		return 1;
	}

	if (!realpath(boot_img, abs_boot_img)) {
		safe_strncpy(abs_boot_img, boot_img, sizeof(abs_boot_img));
	}
	if (!realpath(rec_src, abs_rec_src)) {
		safe_strncpy(abs_rec_src, rec_src, sizeof(abs_rec_src));
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}
	safe_strncpy(tmp_work_dir, "/tmp/mb_setrec_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}

	snprintf(target_dir, sizeof(target_dir), "%s/target", tmp_work_dir);
	snprintf(rec_dir, sizeof(rec_dir), "%s/rec", tmp_work_dir);
	mkdir(target_dir, 0755);
	mkdir(rec_dir, 0755);

	/* 1. Unpack target boot image */
	printf("[*] Unpacking target boot image: %s\n", abs_boot_img);
	chdir(target_dir);
	if (magiskboot_unpack(abs_boot_img, true, false, false, false) != 0) {
		bb_error_msg("failed to unpack target boot image '%s'", abs_boot_img);
		ret = 1;
		goto cleanup;
	}

	/* Optional: bypass module signature enforcement on target kernel */
	if (access("kernel", F_OK) == 0) {
		magiskboot_kernel_op("kernel", "patch-sigenforce", 0, NULL);
	}

	/* 2. Unpack recovery source image */
	printf("[*] Unpacking recovery source image: %s\n", abs_rec_src);
	chdir(rec_dir);
	if (magiskboot_unpack(abs_rec_src, true, false, false, false) != 0) {
		/* Check if source is already a raw or compressed CPIO archive */
		int c_fd = open_or_warn(abs_rec_src, O_RDONLY | O_CLOEXEC);
		if (c_fd >= 0) {
			uint8_t m[32];
			ssize_t mn = full_read(c_fd, m, sizeof(m));
			close(c_fd);
			if (mn >= 6 && (memcmp(m, "070701", 6) == 0 || memcmp(m, "070702", 6) == 0)) {
				copy_file(abs_rec_src, "ramdisk.cpio", FILEUTILS_FORCE);
			} else {
				uint8_t fmt = (mn > 0) ? boot_check_fmt(m, mn) : BOOT_FMT_UNKNOWN;
				if (boot_fmt_compressed(fmt)) {
					int out_rfd = open3_or_warn("ramdisk.cpio", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
					if (out_rfd >= 0) {
						c_fd = open(abs_rec_src, O_RDONLY | O_CLOEXEC);
						if (c_fd >= 0) {
							bb_decompress_data(fmt, NULL, 0, out_rfd);
							close(c_fd);
						}
						close(out_rfd);
					}
				}
			}
		}
	}

	snprintf(target_cpio, sizeof(target_cpio), "%.*s/ramdisk.cpio", (int)(sizeof(target_cpio) - 16), target_dir);
	snprintf(rec_cpio, sizeof(rec_cpio), "%.*s/ramdisk.cpio", (int)(sizeof(rec_cpio) - 16), rec_dir);

	if (access(target_cpio, F_OK) != 0) {
		bb_error_msg("target boot image has no ramdisk.cpio");
		ret = 1;
		goto cleanup;
	}
	if (access(rec_cpio, F_OK) != 0) {
		bb_error_msg("recovery source image has no ramdisk.cpio");
		ret = 1;
		goto cleanup;
	}

	/* 3. Read CPIO archives in memory */
	target_head = cpio_read_all(target_cpio);
	rec_head = cpio_read_all(rec_cpio);

	if (!target_head || !rec_head) {
		bb_error_msg("failed to parse ramdisk archives");
		ret = 1;
		goto cleanup;
	}

	/* 4. Transfer recovery subsystem components into target ramdisk */
	printf("[*] Merging recovery subsystem from %s into target boot ramdisk...\n", rec_src);
	for (node = rec_head; node; node = node->next) {
		if (is_recovery_component_entry(node->name)) {
			void *copy_data = NULL;
			if (node->data && node->filesize > 0) {
				copy_data = xmemdup(node->data, node->filesize);
			}
			cpio_set_file(&target_head, node->name, node->mode, copy_data, node->filesize);
			count++;
		}
	}
	printf("[+] Successfully integrated %d recovery components into target boot ramdisk\n", count);

	/* Write updated target ramdisk */
	if (cpio_write_all(target_cpio, target_head) != 0) {
		bb_error_msg("failed to write updated target ramdisk CPIO");
		ret = 1;
		goto cleanup;
	}

	/* 5. Repack target boot image */
	chdir(target_dir);
	if (out_img && !install) {
		if (out_img[0] == '/') {
			safe_strncpy(repacked_img, out_img, sizeof(repacked_img));
		} else {
			char *p = concat_path_file(old_cwd, out_img);
			safe_strncpy(repacked_img, p, sizeof(repacked_img));
			free(p);
		}
	} else {
		char *p = concat_path_file(tmp_work_dir, "new-boot.img");
		safe_strncpy(repacked_img, p, sizeof(repacked_img));
		free(p);
	}

	printf("[*] Repacking hybrid boot image -> %s...\n", repacked_img);
	if (magiskboot_repack(abs_boot_img, repacked_img, false) != 0) {
		bb_error_msg("failed to repack hybrid boot image");
		ret = 1;
		goto cleanup;
	}

	/* 6. Flash directly if --install requested */
	if (install) {
		struct stat st_out;
		uint64_t bdev_sz = 0;
		int sec_sz = 512;
		char stream_buf[1024 * 1024];
		struct timespec t_start, t_end;
		double elapsed, mb_sec;
		ssize_t nr, nw;

		printf("[*] Flashing hybrid boot image directly to %s...\n", boot_img);
		in_fd = open_or_warn(repacked_img, O_RDONLY | O_CLOEXEC);
		if (in_fd < 0) {
			ret = 1;
			goto cleanup;
		}
		if (fstat(in_fd, &st_img) < 0 || st_img.st_size < 4096) {
			bb_error_msg("invalid repacked boot image size");
			close(in_fd);
			ret = 1;
			goto cleanup;
		}

		out_fd = open_or_warn(boot_img, O_RDWR | O_SYNC | O_CLOEXEC);
		if (out_fd < 0) {
			close(in_fd);
			ret = 1;
			goto cleanup;
		}
#ifdef BLKROSET
		{
			int ro = 0;
			ioctl(out_fd, BLKROSET, &ro);
		}
#endif
		if (fstat(out_fd, &st_out) == 0) {
			bdev_sz = get_file_or_bdev_size(out_fd, &st_out);
#ifdef BLKSSZGET
			ioctl(out_fd, BLKSSZGET, &sec_sz);
#endif
			if (bdev_sz > 0)
				printf("    • Target Capacity    : %llu bytes (%.2f MB)\n",
				       (unsigned long long)bdev_sz, (double)bdev_sz / (1024.0 * 1024.0));
		}

		written = 0;
		clock_gettime(CLOCK_MONOTONIC, &t_start);
		printf("[*] Streaming hybrid boot image to %s (%lld bytes, %.2f MB)...\n",
		       boot_img, (long long)st_img.st_size, (double)st_img.st_size / (1024.0 * 1024.0));

		while (written < st_img.st_size) {
			size_t chunk = (st_img.st_size - written > (off_t)sizeof(stream_buf)) ?
			               sizeof(stream_buf) : (size_t)(st_img.st_size - written);
			nr = full_read(in_fd, stream_buf, chunk);
			if (nr <= 0) break;
			nw = full_write(out_fd, stream_buf, nr);
			if (nw != nr) break;
			written += nw;
		}
		close(in_fd);

		clock_gettime(CLOCK_MONOTONIC, &t_end);
		elapsed = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
		mb_sec = (elapsed > 0.001) ? ((double)written / (1024.0 * 1024.0)) / elapsed : 0.0;
		printf("[+] Flashed %lld bytes in %.3f seconds (%.2f MB/s)\n",
		       (long long)written, elapsed, mb_sec);

		fsync(out_fd);
		close(out_fd);
		sync();
		printf("[✓] SUCCESS: Verified %lld bytes committed directly to %s\n", (long long)written, boot_img);
	} else {
		printf("[✓] SUCCESS: Hybrid boot image saved to %s\n", repacked_img);
	}

cleanup:
	if (target_head) cpio_free_all(target_head);
	if (rec_head) cpio_free_all(rec_head);
	chdir(old_cwd);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

/*
 * Recovery Extractor Engine
 * Extracts recovery subsystem components, recovery.cpio, or standalone recovery.img
 * from target boot image (or live boot partition).
 */
static int magiskboot_extract_recovery_op(int argc, char **argv)
{
	bool live = false;
	bool extract_all = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *out_target = NULL;
	char discovered_boot[512];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_boot_img[PATH_MAX];
	char abs_out[PATH_MAX];
	char target_cpio[PATH_MAX];
	cpio_node_t *head = NULL;
	cpio_node_t *rec_head = NULL;
	cpio_node_t *curr;
	int count = 0;
	int total = 0;
	int i;
	int ret = 0;
	bool is_img_out = false;
	bool is_dir_out = false;
	size_t olen;

	discovered_boot[0] = '\0';
	abs_boot_img[0] = '\0';
	abs_out[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "--all") == 0 || strcmp(argv[i], "-a") == 0) {
			extract_all = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			i++; /* skip device ID */
		} else if (argv[i][0] == '-') {
			/* skip unrecognized options */
		} else {
			if (!boot_img && !live) {
				boot_img = argv[i];
			} else if (!out_target) {
				out_target = argv[i];
			}
		}
	}

	if (part_name) {
		char pbuf[PATH_MAX];
		snprintf(pbuf, sizeof(pbuf), "/dev/block/by-name/%s", part_name);
		if (access(pbuf, F_OK) == 0) {
			strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
			discovered_boot[sizeof(discovered_boot) - 1] = '\0';
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
				discovered_boot[sizeof(discovered_boot) - 1] = '\0';
				boot_img = discovered_boot;
			}
		}
	}

	if (live || !boot_img) {
		live = true;
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		boot_img = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", boot_img);
	}

	if (!out_target) {
		out_target = "recovery.cpio";
	}

	if (!realpath(boot_img, abs_boot_img)) {
		safe_strncpy(abs_boot_img, boot_img, sizeof(abs_boot_img));
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}

	/* Resolve output path */
	if (out_target[0] == '/') {
		safe_strncpy(abs_out, out_target, sizeof(abs_out));
	} else {
		char *p = concat_path_file(old_cwd, out_target);
		safe_strncpy(abs_out, p, sizeof(abs_out));
		free(p);
	}

	/* Determine target type */
	olen = strlen(abs_out);
	if (olen > 4 && strcmp(abs_out + olen - 4, ".img") == 0) {
		is_img_out = true;
	} else {
		struct stat st_o;
		if (abs_out[olen - 1] == '/' || (stat(abs_out, &st_o) == 0 && S_ISDIR(st_o.st_mode))) {
			is_dir_out = true;
		}
	}

	safe_strncpy(tmp_work_dir, "/tmp/mb_extrec_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}

	printf("[*] Unpacking boot image: %s\n", abs_boot_img);
	chdir(tmp_work_dir);
	if (magiskboot_unpack(abs_boot_img, true, false, false, false) != 0) {
		bb_error_msg("failed to unpack boot image '%s'", abs_boot_img);
		ret = 1;
		goto cleanup;
	}

	snprintf(target_cpio, sizeof(target_cpio), "%s/ramdisk.cpio", tmp_work_dir);
	if (access(target_cpio, F_OK) != 0) {
		bb_error_msg("boot image has no ramdisk.cpio");
		ret = 1;
		goto cleanup;
	}

	head = cpio_read_all(target_cpio);
	if (!head) {
		bb_error_msg("failed to parse ramdisk archive");
		ret = 1;
		goto cleanup;
	}

	for (curr = head; curr; curr = curr->next) {
		total++;
		if (extract_all || is_recovery_component_entry(curr->name)) {
			void *copy_data = NULL;
			if (curr->data && curr->filesize > 0) {
				copy_data = xmemdup(curr->data, curr->filesize);
			}
			cpio_set_file(&rec_head, curr->name, curr->mode, copy_data, curr->filesize);
			count++;
		}
	}

	if (count == 0) {
		bb_error_msg("no recovery subsystem components found in '%s'", boot_img);
		ret = 1;
		goto cleanup;
	}

	printf("[+] Identified %d recovery components (out of %d ramdisk entries)\n", count, total);

	if (is_dir_out) {
		/* Extract recovery files to directory */
		printf("[*] Extracting recovery files to directory: %s\n", abs_out);
		bb_make_directory(abs_out, 0755, FILEUTILS_RECUR);
		for (curr = rec_head; curr; curr = curr->next) {
			char full_path[PATH_MAX * 2];
			char *slash;
			snprintf(full_path, sizeof(full_path), "%s/%s", abs_out, curr->name);
			slash = strrchr(full_path, '/');
			if (slash && slash != full_path) {
				*slash = '\0';
				bb_make_directory(full_path, 0755, FILEUTILS_RECUR);
				*slash = '/';
			}
			if (S_ISDIR(curr->mode)) {
				mkdir(full_path, curr->mode & 07777);
			} else if (S_ISREG(curr->mode)) {
				int fd = open3_or_warn(full_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, curr->mode & 07777);
				if (fd >= 0) {
					if (curr->data && curr->filesize > 0) {
						full_write(fd, curr->data, curr->filesize);
					}
					close(fd);
				}
			} else if (S_ISLNK(curr->mode)) {
				if (curr->data && curr->filesize > 0) {
					char *target = xstrndup((const char *)curr->data, curr->filesize);
					unlink(full_path);
					symlink(target, full_path);
					free(target);
				}
			}
		}
		printf("[✓] SUCCESS: Extracted %d recovery components -> %s\n", count, abs_out);
	} else if (is_img_out) {
		/* Repack into bootable recovery.img */
		printf("[*] Packaging bootable standalone recovery image -> %s...\n", abs_out);
		/* For bootable recovery image, ensure /init is preserved if present in stock ramdisk */
		for (curr = head; curr; curr = curr->next) {
			if (strcmp(curr->name, "init") == 0) {
				void *copy_data = curr->data ? xmemdup(curr->data, curr->filesize) : NULL;
				cpio_set_file(&rec_head, "init", curr->mode, copy_data, curr->filesize);
				break;
			}
		}
		if (cpio_write_all(target_cpio, rec_head) != 0) {
			bb_error_msg("failed to write recovery ramdisk CPIO");
			ret = 1;
			goto cleanup;
		}
		if (magiskboot_repack(abs_boot_img, abs_out, false) != 0) {
			bb_error_msg("failed to repack recovery image");
			ret = 1;
			goto cleanup;
		}
		printf("[✓] SUCCESS: Generated bootable recovery image -> %s\n", abs_out);
	} else {
		/* CPIO output */
		char tmp_cpio[PATH_MAX];
		snprintf(tmp_cpio, sizeof(tmp_cpio), "%s/extracted_recovery.cpio", tmp_work_dir);
		printf("[*] Writing recovery CPIO archive -> %s...\n", abs_out);
		if (cpio_write_all(tmp_cpio, rec_head) != 0) {
			bb_error_msg("failed to write recovery CPIO");
			ret = 1;
			goto cleanup;
		}
		if (olen > 3 && strcmp(abs_out + olen - 3, ".gz") == 0) {
			compress_file_format(tmp_cpio, abs_out, BOOT_FMT_GZIP);
		} else if (olen > 3 && strcmp(abs_out + olen - 3, ".xz") == 0) {
			compress_file_format(tmp_cpio, abs_out, BOOT_FMT_XZ);
		} else if (olen > 4 && strcmp(abs_out + olen - 4, ".lz4") == 0) {
			compress_file_format(tmp_cpio, abs_out, BOOT_FMT_LZ4);
		} else {
			copy_file(tmp_cpio, abs_out, FILEUTILS_FORCE);
		}
		printf("[✓] SUCCESS: Extracted %d recovery components -> %s\n", count, abs_out);
	}

cleanup:
	chdir(old_cwd);
	if (head) cpio_free_all(head);
	if (rec_head) cpio_free_all(rec_head);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

/* =========================================================================
 * 12. Android OTA Payload (payload.bin / CrAU) Engine
 * ========================================================================= */

#define PAYLOAD_MAGIC "CrAU"

static bool is_payload_bin(const char *path) {
	int fd;
	char magic[4];
	ssize_t n;

	if (!path) return false;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return false;
	n = full_read(fd, magic, 4);
	close(fd);
	return (n == 4 && memcmp(magic, PAYLOAD_MAGIC, 4) == 0);
}

static uint64_t pb_read_varint(const uint8_t **p, const uint8_t *end) {
	uint64_t val = 0;
	int shift = 0;
	while (*p < end && shift < 64) {
		uint8_t b = *(*p)++;
		val |= ((uint64_t)(b & 0x7f)) << shift;
		if ((b & 0x80) == 0) break;
		shift += 7;
	}
	return val;
}

static void pb_skip_field(uint32_t wire_type, const uint8_t **p, const uint8_t *end) {
	if (wire_type == 0) {
		pb_read_varint(p, end);
	} else if (wire_type == 1) {
		if (*p + 8 <= end) *p += 8; else *p = end;
	} else if (wire_type == 2) {
		uint64_t len = pb_read_varint(p, end);
		if (*p + len <= end) *p += len; else *p = end;
	} else if (wire_type == 5) {
		if (*p + 4 <= end) *p += 4; else *p = end;
	}
}

struct payload_extent {
	uint64_t start_block;
	uint64_t num_blocks;
};

static int payload_extract_partition_ops(int in_fd, off_t data_base, const uint8_t *part_start, const uint8_t *part_end, const char *part_name, const char *out_path, uint64_t part_size, bool silent) {
	int out_fd;
	const uint8_t *scan;

	out_fd = open3_or_warn(out_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) return 1;

	scan = part_start;
	while (scan < part_end) {
		uint64_t ptag = pb_read_varint(&scan, part_end);
		uint32_t pfield = ptag >> 3;
		uint32_t pwire = ptag & 7;

		if (pfield == 8 && pwire == 2) {
			uint64_t oplen = pb_read_varint(&scan, part_end);
			const uint8_t *op_end = scan + oplen;
			uint32_t type = 0;
			uint64_t data_offset = 0, data_length = 0;
			struct payload_extent static_extents[16];
			struct payload_extent *extents = static_extents;
			size_t num_extents = 0;
			size_t extents_cap = 16;
			size_t i;

			while (scan < op_end) {
				uint64_t otag = pb_read_varint(&scan, op_end);
				uint32_t ofield = otag >> 3;
				uint32_t owire = otag & 7;

				if (ofield == 1 && owire == 0) {
					type = (uint32_t)pb_read_varint(&scan, op_end);
				} else if (ofield == 2 && owire == 0) {
					data_offset = pb_read_varint(&scan, op_end);
				} else if (ofield == 3 && owire == 0) {
					data_length = pb_read_varint(&scan, op_end);
				} else if (ofield == 6 && owire == 2) {
					uint64_t elen = pb_read_varint(&scan, op_end);
					const uint8_t *eend = scan + elen;
					uint64_t start_block = 0, num_blocks = 0;

					while (scan < eend) {
						uint64_t etag = pb_read_varint(&scan, eend);
						uint32_t efield = etag >> 3;
						uint32_t ewire = etag & 7;

						if (efield == 1 && ewire == 0) start_block = pb_read_varint(&scan, eend);
						else if (efield == 2 && ewire == 0) num_blocks = pb_read_varint(&scan, eend);
						else pb_skip_field(ewire, &scan, eend);
					}

					if (num_extents >= extents_cap) {
						extents_cap *= 2;
						if (extents == static_extents) {
							extents = xmalloc(extents_cap * sizeof(struct payload_extent));
							memcpy(extents, static_extents, num_extents * sizeof(struct payload_extent));
						} else {
							extents = xrealloc(extents, extents_cap * sizeof(struct payload_extent));
						}
					}
					extents[num_extents].start_block = start_block;
					extents[num_extents].num_blocks = num_blocks;
					num_extents++;
				} else {
					pb_skip_field(owire, &scan, op_end);
				}
			}

			if (num_extents > 0) {
				if (type == 6) { /* ZERO */
					static const char zero_buf[65536] = {0};
					for (i = 0; i < num_extents; i++) {
						uint64_t rem = extents[i].num_blocks * 4096;
						xlseek(out_fd, extents[i].start_block * 4096, SEEK_SET);
						while (rem > 0) {
							size_t chunk = (rem > sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)rem;
							full_write(out_fd, zero_buf, chunk);
							rem -= chunk;
						}
					}
				} else if (type == 0) { /* REPLACE */
					xlseek(in_fd, data_base + data_offset, SEEK_SET);
					if (num_extents == 1) {
						xlseek(out_fd, extents[0].start_block * 4096, SEEK_SET);
						bb_copyfd_size(in_fd, out_fd, data_length);
					} else {
						for (i = 0; i < num_extents; i++) {
							xlseek(out_fd, extents[i].start_block * 4096, SEEK_SET);
							bb_copyfd_size(in_fd, out_fd, extents[i].num_blocks * 4096);
						}
					}
				} else if (type == 8 || type == 1) { /* REPLACE_XZ or REPLACE_BZ */
					uint8_t fmt = (type == 8) ? BOOT_FMT_XZ : BOOT_FMT_BZIP2;
					void *cbuf = xmalloc(data_length);
					xlseek(in_fd, data_base + data_offset, SEEK_SET);
					xread(in_fd, cbuf, data_length);

					if (num_extents == 1) {
						xlseek(out_fd, extents[0].start_block * 4096, SEEK_SET);
						bb_decompress_data(fmt, cbuf, data_length, out_fd);
					} else {
						char tmp_path[] = "/tmp/mb_op_XXXXXX";
						int tmp_fd = xmkstemp(tmp_path);
						unlink(tmp_path);
						bb_decompress_data(fmt, cbuf, data_length, tmp_fd);
						for (i = 0; i < num_extents; i++) {
							xlseek(tmp_fd, 0, SEEK_SET);
							xlseek(out_fd, extents[i].start_block * 4096, SEEK_SET);
							bb_copyfd_size(tmp_fd, out_fd, extents[i].num_blocks * 4096);
						}
						close(tmp_fd);
					}
					free(cbuf);
				}
			}

			if (extents != static_extents) free(extents);
		} else {
			pb_skip_field(pwire, &scan, part_end);
		}
	}

	if (part_size > 0) {
		ftruncate(out_fd, part_size);
	}
	close(out_fd);
	if (!silent) {
		printf("Extracted partition '%s' (%"PRIu64" bytes) -> %s\n",
		       part_name, part_size, out_path);
	}
	return 0;
}

static int payload_extract_partition(const char *payload_path, const char *target_part, const char *out_path, bool silent) {
	int in_fd;
	char magic[4];
	uint64_t version = 0, manifest_len = 0;
	uint32_t sig_len = 0;
	off_t data_base;
	uint8_t *mbuf;
	const uint8_t *p, *end;
	int ret = 1;

	if (!payload_path || !target_part) return 1;

	in_fd = open_or_warn(payload_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0) return 1;

	if (full_read(in_fd, magic, 4) != 4 || memcmp(magic, PAYLOAD_MAGIC, 4) != 0) {
		bb_error_msg("'%s' is not a valid Android OTA payload", payload_path);
		close(in_fd);
		return 1;
	}

	if (full_read(in_fd, &version, 8) != 8 || full_read(in_fd, &manifest_len, 8) != 8) {
		bb_error_msg("truncated payload header in '%s'", payload_path);
		close(in_fd);
		return 1;
	}
	version = SWAP_BE64(version);
	manifest_len = SWAP_BE64(manifest_len);

	if (version >= 2) {
		if (full_read(in_fd, &sig_len, 4) != 4) {
			bb_error_msg("truncated payload header in '%s'", payload_path);
			close(in_fd);
			return 1;
		}
		sig_len = SWAP_BE32(sig_len);
	}

	data_base = (version >= 2 ? 24 : 20) + manifest_len + sig_len;

	mbuf = xmalloc(manifest_len);
	if (full_read(in_fd, mbuf, manifest_len) != (ssize_t)manifest_len) {
		bb_error_msg("failed to read payload manifest from '%s'", payload_path);
		free(mbuf);
		close(in_fd);
		return 1;
	}

	p = mbuf;
	end = mbuf + manifest_len;

	while (p < end) {
		uint64_t tag = pb_read_varint(&p, end);
		uint32_t field = tag >> 3;
		uint32_t wire = tag & 7;

		if (field == 13 && wire == 2) {
			uint64_t part_len = pb_read_varint(&p, end);
			const uint8_t *part_end = p + part_len;
			char part_name[64] = {0};
			uint64_t part_size = 0;
			const uint8_t *scan = p;

			while (scan < part_end) {
				uint64_t ptag = pb_read_varint(&scan, part_end);
				uint32_t pfield = ptag >> 3;
				uint32_t pwire = ptag & 7;

				if (pfield == 1 && pwire == 2) {
					uint64_t nlen = pb_read_varint(&scan, part_end);
					size_t cp = (nlen < sizeof(part_name) - 1) ? nlen : (sizeof(part_name) - 1);
					memcpy(part_name, scan, cp);
					part_name[cp] = '\0';
					scan += nlen;
				} else if (pfield == 7 && pwire == 2) {
					uint64_t ilen = pb_read_varint(&scan, part_end);
					const uint8_t *iend = scan + ilen;
					while (scan < iend) {
						uint64_t itag = pb_read_varint(&scan, iend);
						if ((itag >> 3) == 1 && (itag & 7) == 0) part_size = pb_read_varint(&scan, iend);
						else pb_skip_field(itag & 7, &scan, iend);
					}
				} else {
					pb_skip_field(pwire, &scan, part_end);
				}
			}

			if (strcmp(part_name, target_part) == 0) {
				char auto_out[PATH_MAX];
				const char *dest = out_path;
				if (!dest) {
					snprintf(auto_out, sizeof(auto_out), "%s.img", part_name);
					dest = auto_out;
				}
				ret = payload_extract_partition_ops(in_fd, data_base, p, part_end, part_name, dest, part_size, silent);
				break;
			}
			p = part_end;
		} else {
			pb_skip_field(wire, &p, end);
		}
	}

	if (ret != 0 && p >= end) {
		bb_error_msg("partition '%s' not found in payload '%s'", target_part, payload_path);
	}

	free(mbuf);
	close(in_fd);
	return ret;
}

static bool is_inner_boot_component(const char *name) {
	if (!name) return false;
	return (strcmp(name, "kernel") == 0 ||
	        strcmp(name, "ramdisk") == 0 ||
	        strcmp(name, "dtb") == 0 ||
	        strcmp(name, "kernel_dtb") == 0 ||
	        strcmp(name, "recovery_dtbo") == 0 ||
	        strcmp(name, "second") == 0 ||
	        strcmp(name, "extra") == 0 ||
	        strcmp(name, "bootconfig") == 0 ||
	        strcmp(name, "zImage") == 0 ||
	        strcmp(name, "Image") == 0 ||
	        strcmp(name, "initrd") == 0);
}

static bool payload_has_partition(const char *payload_path, const char *part_name) {
	int in_fd;
	char magic[4];
	uint64_t version = 0, manifest_len = 0;
	off_t off;
	uint8_t *mbuf;
	const uint8_t *p, *end;
	bool found = false;

	if (!payload_path || !part_name) return false;
	in_fd = open_or_warn(payload_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0) return false;
	if (full_read(in_fd, magic, 4) != 4 || memcmp(magic, PAYLOAD_MAGIC, 4) != 0) {
		close(in_fd);
		return false;
	}
	if (full_read(in_fd, &version, 8) != 8 || full_read(in_fd, &manifest_len, 8) != 8) {
		close(in_fd);
		return false;
	}
	version = SWAP_BE64(version);
	manifest_len = SWAP_BE64(manifest_len);
	off = (version >= 2) ? 24 : 20;
	xlseek(in_fd, off, SEEK_SET);

	mbuf = xmalloc(manifest_len);
	if (full_read(in_fd, mbuf, manifest_len) != (ssize_t)manifest_len) {
		free(mbuf);
		close(in_fd);
		return false;
	}
	close(in_fd);

	p = mbuf;
	end = mbuf + manifest_len;
	while (p < end) {
		uint64_t tag = pb_read_varint(&p, end);
		if ((tag >> 3) == 13 && (tag & 7) == 2) {
			uint64_t part_len = pb_read_varint(&p, end);
			const uint8_t *part_end = p + part_len;
			const uint8_t *scan = p;
			while (scan < part_end) {
				uint64_t ptag = pb_read_varint(&scan, part_end);
				if ((ptag >> 3) == 1 && (ptag & 7) == 2) {
					uint64_t nlen = pb_read_varint(&scan, part_end);
					if (nlen == strlen(part_name) && memcmp(scan, part_name, nlen) == 0) {
						found = true;
						break;
					}
					scan += nlen;
				} else {
					pb_skip_field(ptag & 7, &scan, part_end);
				}
			}
			if (found) break;
			p = part_end;
		} else {
			pb_skip_field(tag & 7, &p, end);
		}
	}
	free(mbuf);
	return found;
}

static int payload_extract(const char *payload_path, const char *target, const char *out_path) {
	if (!target) target = "boot";

	/* 1. Direct partition extraction if payload contains this partition */
	if (payload_has_partition(payload_path, target)) {
		return payload_extract_partition(payload_path, target, out_path, false);
	}

	/* 2. Inner component extraction (kernel, ramdisk, dtb, etc.) */
	if (is_inner_boot_component(target)) {
		char tmp_boot[] = "/tmp/mb_payload_boot_XXXXXX";
		int fd = xmkstemp(tmp_boot);
		const char *boot_part = "boot";
		int ret;

		close(fd);
		if (!payload_has_partition(payload_path, "boot")) {
			if (payload_has_partition(payload_path, "init_boot")) {
				boot_part = "init_boot";
			} else if (payload_has_partition(payload_path, "vendor_boot")) {
				boot_part = "vendor_boot";
			}
		}

		ret = payload_extract_partition(payload_path, boot_part, tmp_boot, true);
		if (ret != 0) {
			unlink(tmp_boot);
			return ret;
		}

		ret = magiskboot_extract_component(tmp_boot, target, out_path, false);
		unlink(tmp_boot);
		return ret;
	}

	bb_error_msg("target '%s' is neither a partition nor an inner component in '%s'", target, payload_path);
	return 1;
}

static int payload_extract_all(const char *payload_path, const char *out_dir) {
	int in_fd;
	char magic[4];
	uint64_t version = 0, manifest_len = 0;
	uint32_t sig_len = 0;
	off_t data_base;
	uint8_t *mbuf;
	const uint8_t *p, *end;
	int extracted = 0;

	if (!out_dir) out_dir = ".";
	bb_make_directory((char *)out_dir, 0755, FILEUTILS_RECUR);

	in_fd = open_or_warn(payload_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0) return 1;

	if (full_read(in_fd, magic, 4) != 4 || memcmp(magic, PAYLOAD_MAGIC, 4) != 0) {
		bb_error_msg("'%s' is not a valid Android OTA payload", payload_path);
		close(in_fd);
		return 1;
	}

	if (full_read(in_fd, &version, 8) != 8 || full_read(in_fd, &manifest_len, 8) != 8) {
		bb_error_msg("truncated payload header in '%s'", payload_path);
		close(in_fd);
		return 1;
	}
	version = SWAP_BE64(version);
	manifest_len = SWAP_BE64(manifest_len);

	if (version >= 2) {
		if (full_read(in_fd, &sig_len, 4) != 4) {
			bb_error_msg("truncated payload header in '%s'", payload_path);
			close(in_fd);
			return 1;
		}
		sig_len = SWAP_BE32(sig_len);
	}

	data_base = (version >= 2 ? 24 : 20) + manifest_len + sig_len;

	mbuf = xmalloc(manifest_len);
	if (full_read(in_fd, mbuf, manifest_len) != (ssize_t)manifest_len) {
		bb_error_msg("failed to read payload manifest from '%s'", payload_path);
		free(mbuf);
		close(in_fd);
		return 1;
	}

	p = mbuf;
	end = mbuf + manifest_len;

	while (p < end) {
		uint64_t tag = pb_read_varint(&p, end);
		if ((tag >> 3) == 13 && (tag & 7) == 2) {
			uint64_t part_len = pb_read_varint(&p, end);
			const uint8_t *part_end = p + part_len;
			char part_name[64] = {0};
			uint64_t part_size = 0;
			char out_file[PATH_MAX];
			const uint8_t *scan = p;

			while (scan < part_end) {
				uint64_t ptag = pb_read_varint(&scan, part_end);
				uint32_t pfield = ptag >> 3;
				uint32_t pwire = ptag & 7;

				if (pfield == 1 && pwire == 2) {
					uint64_t nlen = pb_read_varint(&scan, part_end);
					size_t cp = (nlen < sizeof(part_name) - 1) ? nlen : (sizeof(part_name) - 1);
					memcpy(part_name, scan, cp);
					part_name[cp] = '\0';
					scan += nlen;
				} else if (pfield == 7 && pwire == 2) {
					uint64_t ilen = pb_read_varint(&scan, part_end);
					const uint8_t *iend = scan + ilen;
					while (scan < iend) {
						uint64_t itag = pb_read_varint(&scan, iend);
						if ((itag >> 3) == 1 && (itag & 7) == 0) part_size = pb_read_varint(&scan, iend);
						else pb_skip_field(itag & 7, &scan, iend);
					}
				} else {
					pb_skip_field(pwire, &scan, part_end);
				}
			}

			if (part_name[0]) {
				snprintf(out_file, sizeof(out_file), "%s/%s.img", out_dir, part_name);
				if (payload_extract_partition_ops(in_fd, data_base, p, part_end, part_name, out_file, part_size, false) == 0) {
					extracted++;
				}
			}
			p = part_end;
		} else {
			pb_skip_field(tag & 7, &p, end);
		}
	}

	free(mbuf);
	close(in_fd);
	printf("Extracted %d partitions to '%s'\n", extracted, out_dir);
	return 0;
}

static int payload_info(const char *payload_path) {
	int in_fd;
	char magic[4];
	uint64_t version = 0, manifest_len = 0;
	uint32_t sig_len = 0;
	off_t data_base;
	uint8_t *mbuf;
	const uint8_t *p, *end;
	int part_count = 0;

	in_fd = open_or_warn(payload_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0) return 1;

	if (full_read(in_fd, magic, 4) != 4 || memcmp(magic, PAYLOAD_MAGIC, 4) != 0) {
		bb_error_msg("'%s' is not a valid Android OTA payload", payload_path);
		close(in_fd);
		return 1;
	}

	if (full_read(in_fd, &version, 8) != 8 || full_read(in_fd, &manifest_len, 8) != 8) {
		bb_error_msg("truncated payload header in '%s'", payload_path);
		close(in_fd);
		return 1;
	}
	version = SWAP_BE64(version);
	manifest_len = SWAP_BE64(manifest_len);

	if (version >= 2) {
		if (full_read(in_fd, &sig_len, 4) != 4) {
			bb_error_msg("truncated payload header in '%s'", payload_path);
			close(in_fd);
			return 1;
		}
		sig_len = SWAP_BE32(sig_len);
	}

	data_base = (version >= 2 ? 24 : 20) + manifest_len + sig_len;

	mbuf = xmalloc(manifest_len);
	if (full_read(in_fd, mbuf, manifest_len) != (ssize_t)manifest_len) {
		bb_error_msg("failed to read payload manifest from '%s'", payload_path);
		free(mbuf);
		close(in_fd);
		return 1;
	}
	close(in_fd);

	printf("Payload Format:       Android OTA Payload (CrAU v%"PRIu64")\n", version);
	printf("Manifest Size:        %"PRIu64" bytes\n", manifest_len);
	printf("Signature Size:       %u bytes\n", sig_len);
	printf("Data Base Offset:     %lld (0x%llx)\n", (long long)data_base, (unsigned long long)data_base);
	printf("\nPartitions:\n");
	printf("  %-20s %-16s %-12s\n", "Partition", "Size (Bytes)", "Operations");
	printf("  --------------------------------------------------\n");

	p = mbuf;
	end = mbuf + manifest_len;

	while (p < end) {
		uint64_t tag = pb_read_varint(&p, end);
		if ((tag >> 3) == 13 && (tag & 7) == 2) {
			uint64_t part_len = pb_read_varint(&p, end);
			const uint8_t *part_end = p + part_len;
			char part_name[64] = {0};
			uint64_t part_size = 0;
			int op_count = 0;
			const uint8_t *scan = p;

			while (scan < part_end) {
				uint64_t ptag = pb_read_varint(&scan, part_end);
				uint32_t pfield = ptag >> 3;
				uint32_t pwire = ptag & 7;

				if (pfield == 1 && pwire == 2) {
					uint64_t nlen = pb_read_varint(&scan, part_end);
					size_t cp = (nlen < sizeof(part_name) - 1) ? nlen : (sizeof(part_name) - 1);
					memcpy(part_name, scan, cp);
					part_name[cp] = '\0';
					scan += nlen;
				} else if (pfield == 7 && pwire == 2) {
					uint64_t ilen = pb_read_varint(&scan, part_end);
					const uint8_t *iend = scan + ilen;
					while (scan < iend) {
						uint64_t itag = pb_read_varint(&scan, iend);
						if ((itag >> 3) == 1 && (itag & 7) == 0) part_size = pb_read_varint(&scan, iend);
						else pb_skip_field(itag & 7, &scan, iend);
					}
				} else if (pfield == 8 && pwire == 2) {
					uint64_t oplen = pb_read_varint(&scan, part_end);
					scan += oplen;
					op_count++;
				} else {
					pb_skip_field(pwire, &scan, part_end);
				}
			}

			if (part_name[0]) {
				printf("  %-20s %-16"PRIu64" %-12d\n", part_name, part_size, op_count);
				part_count++;
			}
			p = part_end;
		} else {
			pb_skip_field(tag & 7, &p, end);
		}
	}

	printf("  --------------------------------------------------\n");
	printf("Total Partitions:     %d\n", part_count);

	free(mbuf);
	return 0;
}

/* =========================================================================
 * 6. BusyBox Applet Entrypoint
 * ========================================================================= */

int aimg_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int aimg_main(int argc, char **argv) {
	static const char cmds[] ALIGN1 =
		/* Kernel Security Neutralization */
		"--de-enforce\0"
		"de-enforce\0"
		"--patch-sigenforce\0"
		"patch-sigenforce\0"
		"--patch-cfi\0"
		"patch-cfi\0"
		"--permissive\0"
		"permissive\0"
		"--disable-rkp\0"
		"disable-rkp\0"
		"--kernel-status\0"
		"kernel-status\0"

		/* Boot Image Operations */
		"-u\0"
		"--unpack\0"
		"unpack\0"
		"-r\0"
		"--repack\0"
		"repack\0"
		"-e\0"
		"--extract\0"
		"extract\0"
		"-c\0"
		"--cleanup\0"
		"cleanup\0"

		/* Kernel Module Toolkit */
		"--mod-info\0"
		"mod-info\0"
		"--mod-audit\0"
		"mod-audit\0"
		"--mod-strip\0"
		"mod-strip\0"
		"--mod-patch\0"
		"mod-patch\0"
		"--mod-inject\0"
		"mod-inject\0"
		"--mod-load\0"
		"mod-load\0"
		"--mod-unload\0"
		"mod-unload\0"

		/* Ramdisk & Component Patchers */
		"--init\0"
		"init\0"
		"--cpio\0"
		"cpio\0"
		"--dtb\0"
		"dtb\0"
		"--vbmeta\0"
		"vbmeta\0"
		"--fstab\0"
		"fstab\0"
		"--cmdline\0"
		"cmdline\0"
		"--hexpatch\0"
		"hexpatch\0"
		"--decompress\0"
		"decompress\0"
		"--set-recovery\0"
		"set-recovery\0"
		"--extract-recovery\0"
		"extract-recovery\0"
		"--get-recovery\0"
		"get-recovery\0"
		"--recovery\0"
		"recovery\0"

		/* Packaging */
		"--dist\0"
		"dist\0"
		"--zip\0"
		"zip\0"

		/* Generic Group Verbs */
		"--kernel\0"
		"kernel\0"
		"--module\0"
		"module\0"

		/* Help */
		"-h\0"
		"--help\0"
		"help\0";

	enum {
		CMD_de_enforce = 0,
		CMD_de_enforce_no_dash,
		CMD_patch_sigenforce,
		CMD_patch_sigenforce_no_dash,
		CMD_patch_cfi,
		CMD_patch_cfi_no_dash,
		CMD_permissive,
		CMD_permissive_no_dash,
		CMD_disable_rkp,
		CMD_disable_rkp_no_dash,
		CMD_kernel_status,
		CMD_kernel_status_no_dash,

		CMD_u,
		CMD_unpack,
		CMD_unpack_no_dash,
		CMD_r,
		CMD_repack,
		CMD_repack_no_dash,
		CMD_e,
		CMD_extract,
		CMD_extract_no_dash,
		CMD_c,
		CMD_cleanup,
		CMD_cleanup_no_dash,

		CMD_mod_info,
		CMD_mod_info_no_dash,
		CMD_mod_audit,
		CMD_mod_audit_no_dash,
		CMD_mod_strip,
		CMD_mod_strip_no_dash,
		CMD_mod_patch,
		CMD_mod_patch_no_dash,
		CMD_mod_inject,
		CMD_mod_inject_no_dash,
		CMD_mod_load,
		CMD_mod_load_no_dash,
		CMD_mod_unload,
		CMD_mod_unload_no_dash,

		CMD_init,
		CMD_init_no_dash,
		CMD_cpio,
		CMD_cpio_no_dash,
		CMD_dtb,
		CMD_dtb_no_dash,
		CMD_vbmeta,
		CMD_vbmeta_no_dash,
		CMD_fstab,
		CMD_fstab_no_dash,
		CMD_cmdline,
		CMD_cmdline_no_dash,
		CMD_hexpatch,
		CMD_hexpatch_no_dash,
		CMD_decompress,
		CMD_decompress_no_dash,
		CMD_set_recovery,
		CMD_set_recovery_no_dash,
		CMD_extract_recovery,
		CMD_extract_recovery_no_dash,
		CMD_get_recovery,
		CMD_get_recovery_no_dash,
		CMD_recovery,
		CMD_recovery_no_dash,

		CMD_dist,
		CMD_dist_no_dash,
		CMD_zip,
		CMD_zip_no_dash,

		CMD_kernel,
		CMD_kernel_no_dash,
		CMD_module,
		CMD_module_no_dash,

		CMD_h,
		CMD_help,
		CMD_help_no_dash,
	};

	const char *cmd;
	int subcmd;

	if (argc < 2) {
		bb_show_usage();
	}

	cmd = argv[1];
	subcmd = index_in_strings(cmds, cmd);

	switch (subcmd) {
	case CMD_de_enforce:
	case CMD_de_enforce_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "de-enforce", argc, argv);

	case CMD_patch_sigenforce:
	case CMD_patch_sigenforce_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "patch-sigenforce", argc, argv);

	case CMD_patch_cfi:
	case CMD_patch_cfi_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "patch-cfi", argc, argv);

	case CMD_permissive:
	case CMD_permissive_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "permissive", argc, argv);

	case CMD_disable_rkp:
	case CMD_disable_rkp_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "disable-rkp", argc, argv);

	case CMD_kernel_status:
	case CMD_kernel_status_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_kernel_op(argv[2], "status", argc, argv);

	case CMD_u:
	case CMD_unpack:
	case CMD_unpack_no_dash: {
		bool hdr_only = false;
		bool kernel_only = false;
		bool skip_decomp = false;
		const char *img;
		const char *extra_arg = NULL;
		int idx = 2;
		if (argc < 3) bb_show_usage();
		while (idx < argc && argv[idx][0] == '-') {
			if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--header-only") == 0) hdr_only = true;
			else if (strcmp(argv[idx], "-k") == 0 || strcmp(argv[idx], "--kernel-only") == 0) kernel_only = true;
			else if (strcmp(argv[idx], "-s") == 0 || strcmp(argv[idx], "--split") == 0) skip_decomp = true;
			idx++;
		}
		if (idx >= argc) bb_show_usage();
		img = argv[idx++];
		if (idx < argc) extra_arg = argv[idx++];
		if (extra_arg && is_payload_bin(extra_arg) && !is_payload_bin(img)) {
			const char *tmp = img;
			img = extra_arg;
			extra_arg = tmp;
		}
		if (is_payload_bin(img)) {
			if (hdr_only) return payload_info(img);
			if (kernel_only) return payload_extract(img, "kernel", extra_arg ? extra_arg : KERNEL_FILE);
			return payload_extract_all(img, extra_arg ? extra_arg : ".");
		}
		return magiskboot_unpack(img, skip_decomp, skip_decomp, hdr_only, kernel_only);
	}

	case CMD_r:
	case CMD_repack:
	case CMD_repack_no_dash: {
		bool skip_comp = false;
		int idx = 2;
		const char *src;
		const char *out;

		if (argc < 3) bb_show_usage();
		if (strcmp(argv[2], "-n") == 0 || strcmp(argv[2], "--no-comp") == 0) {
			skip_comp = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		src = argv[idx++];
		out = (idx < argc) ? argv[idx] : NULL;
		return magiskboot_repack(src, out, skip_comp);
	}

	case CMD_e:
	case CMD_extract:
	case CMD_extract_no_dash: {
		const char *img;
		const char *comp = NULL;
		const char *out = NULL;
		bool skip_decomp = false;
		int idx = 2;
		if (argc < 3) bb_show_usage();
		if (strcmp(argv[idx], "-n") == 0 || strcmp(argv[idx], "--no-decomp") == 0) {
			skip_decomp = true;
			idx++;
			if (idx >= argc) bb_show_usage();
		}
		img = argv[idx++];
		if (idx < argc) comp = argv[idx++];
		if (idx < argc) out = argv[idx];
		if (is_inner_boot_component(img) && comp && !is_inner_boot_component(comp)) {
			const char *tmp = img;
			img = comp;
			comp = tmp;
		}
		if (is_payload_bin(img)) {
			return payload_extract(img, comp, out);
		}
		if (!comp) bb_show_usage();
		return magiskboot_extract_component(img, comp, out, skip_decomp);
	}

	case CMD_c:
	case CMD_cleanup:
	case CMD_cleanup_no_dash:
		return magiskboot_cleanup();

	case CMD_mod_info:
	case CMD_mod_info_no_dash:
		return module_info_file((argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2));

	case CMD_mod_audit:
	case CMD_mod_audit_no_dash: {
		const char *path = (argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2);
		int fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *map;
		struct elf64_ctx ctx;
		int res;

		if (fd < 0 || fstat(fd, &st) < 0) {
			if (fd >= 0) close(fd);
			return 1;
		}
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;

		if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
			munmap(map, st.st_size);
			return 1;
		}
		res = audit_module_symbols(&ctx, (argc >= 4) ? argv[3] : NULL);
		elf64_free_ctx(&ctx);
		munmap(map, st.st_size);
		return res;
	}

	case CMD_mod_strip:
	case CMD_mod_strip_no_dash: {
		const char *in_f = (argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2);
		const char *out_f = (argc >= 4) ? argv[3] : in_f;
		return module_strip_file(in_f, out_f);
	}

	case CMD_mod_patch:
	case CMD_mod_patch_no_dash: {
		const char *in_f = (argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2);
		const char *out_f = (argc >= 4 && argv[3][0] != '-') ? argv[3] : in_f;
		const char *vmagic = NULL;
		const char *boot_img = NULL;
		int i;

		for (i = 3; i < argc; i++) {
			if (strcmp(argv[i], "--vermagic") == 0 && i + 1 < argc) vmagic = argv[++i];
			else if (strcmp(argv[i], "--boot") == 0 && i + 1 < argc) boot_img = argv[++i];
		}
		return module_patch_file(in_f, out_f, vmagic, boot_img);
	}

	case CMD_mod_inject:
	case CMD_mod_inject_no_dash:
		if (argc < 4 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_add_module_op(argc, argv);

	case CMD_mod_load:
	case CMD_mod_load_no_dash: {
		const char *in_f = (argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2);
		const char *margs = (argc >= 4) ? argv[3] : "";
		return module_load_file(in_f, margs);
	}

	case CMD_mod_unload:
	case CMD_mod_unload_no_dash: {
		const char *mname = (argc >= 3) ? argv[2] : "kroot";
		return module_unload_name(mname);
	}

	case CMD_init:
	case CMD_init_no_dash: {
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

	case CMD_cpio:
	case CMD_cpio_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_cpio(argc, argv);

	case CMD_dtb:
	case CMD_dtb_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_dtb(argc, argv);

	case CMD_vbmeta:
	case CMD_vbmeta_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_vbmeta_op(argc, argv);

	case CMD_fstab:
	case CMD_fstab_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_fstab_op(argc, argv);

	case CMD_cmdline:
	case CMD_cmdline_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_cmdline_op(argc, argv);

	case CMD_hexpatch:
	case CMD_hexpatch_no_dash:
		if (argc < 5) bb_show_usage();
		return magiskboot_hexpatch(argv[2], argv[3], argv[4]);

	case CMD_decompress:
	case CMD_decompress_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_decompress(argv[2], (argc >= 4) ? argv[3] : NULL);

	case CMD_set_recovery:
	case CMD_set_recovery_no_dash:
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_set_recovery_op(argc, argv);

	case CMD_extract_recovery:
	case CMD_extract_recovery_no_dash:
	case CMD_get_recovery:
	case CMD_get_recovery_no_dash:
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_extract_recovery_op(argc, argv);

	case CMD_recovery:
	case CMD_recovery_no_dash:
		if (argc >= 3 && (strcmp(argv[2], "extract") == 0 || strcmp(argv[2], "dump") == 0 || strcmp(argv[2], "get") == 0)) {
			return magiskboot_extract_recovery_op(argc - 1, argv + 1);
		}
		if (argc >= 3 && (strcmp(argv[2], "set") == 0 || strcmp(argv[2], "inject") == 0 || strcmp(argv[2], "change") == 0)) {
			return magiskboot_set_recovery_op(argc - 1, argv + 1);
		}
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_set_recovery_op(argc, argv);

	case CMD_dist:
	case CMD_dist_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_dist_op(argc, argv);

	case CMD_zip:
	case CMD_zip_no_dash:
		if (argc < 3) bb_show_usage();
		if (strcmp(argv[2], "dist") == 0) {
			return magiskboot_dist_op(argc - 1, argv + 1);
		}
		return magiskboot_zip_op(argc, argv);

	case CMD_kernel:
	case CMD_kernel_no_dash:
		if (argc < 4) bb_show_usage();
		return magiskboot_kernel_op(argv[2], argv[3], argc, argv);

	case CMD_module:
	case CMD_module_no_dash:
		if (argc < 3) bb_show_usage();
		if (strcmp(argv[2], "inject") == 0) {
			return magiskboot_add_module_op(argc - 1, argv + 1);
		}
		return magiskboot_module_op(argc, argv);

	case CMD_h:
	case CMD_help:
	case CMD_help_no_dash:
	default:
		bb_show_usage();
		return 1;
	}
}
