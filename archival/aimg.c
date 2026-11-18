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
//usage:     "\n	-i, --info <file>             Deep metrics for boot images, super, sparse, filesystems, vbmeta, DTB"
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
//usage:     "\n	--cpio <rd|boot> <act> [...]  CPIO tool (ls, cat, extract, add, rm, chmod, chown, mv, stat, exists)"
//usage:     "\n	--ramdisk-ls <boot|rd>        List entries inside boot ramdisk"
//usage:     "\n	--ramdisk-cat <boot|rd> <ent> Output entry from boot ramdisk to stdout"
//usage:     "\n	--ramdisk-stat <boot|rd> <en> Display file stat metrics inside boot ramdisk"
//usage:     "\n	--ramdisk-test <boot|rd>      Verify ramdisk archive integrity"
//usage:     "\n	--dtb <file> [test|print|patch] [-f] DTB inspector and AVB/fstab verity patcher"
//usage:     "\n	--vbmeta <file> [status|disable|restore|update-hash <part> <img>] VBMeta flags & hash updater"
//usage:     "\n	--fstab <file> <print|patch>  In-place fstab configuration tool"
//usage:     "\n	--cmdline <file> <print|patch> Kernel cmdline configuration tool"
//usage:     "\n	--hexpatch <file> <from> <to> In-place binary hex string patch"
//usage:     "\n	--decompress <in> [out]       Decompress kernel/ramdisk image"
//usage:     "\n	--set-recovery <boot> <rec>   Inject custom recovery (TWRP) into boot image (--live, --install)"
//usage:     "\n	--extract-recovery <boot> [o] Extract recovery subsystem (cpio, img, or dir) from boot image"
//usage:     "\n	--set-ramdisk <boot> <rd>     Inject/replace ramdisk in boot image (--live, --install)"
//usage:     "\n	--extract-ramdisk <boot> [o]  Extract ramdisk (auto-decompress to cpio) from boot image"
//usage:     "\n"
//usage:     "\nAndroid Build Flags & Production Personality Engine:"
//usage:     "\n	--build-status <boot|--live>  Inspect production/debug build flags and properties"
//usage:     "\n	--set-build-type <b|live> <p> Set build personality (user, userdebug, eng)"
//usage:     "\n	--set-debuggable <b|live> <v> Set ro.debuggable and cmdline flags (1 or 0)"
//usage:     "\n	--set-insecure-adb <b|live> <v> Set ro.secure=0 and ro.adb.secure=0 (1 or 0)"
//usage:     "\n"
//usage:     "\nAnyKernel & Live Partition Operations:"
//usage:     "\n	--flash-kernel <img|rec> [prt] Spliced live kernel flashing with AVB & DTB preservation"
//usage:     "\n	--patch-cmdline [boot|file]   In-place boot header cmdline modifier (+add, -rm, key=val)"
//usage:     "\n	--patch-fstab <boot|file>     In-place fstab modifier (boot ramdisk or text file)"
//usage:     "\n"
//usage:     "\nPackaging:"
//usage:     "\n	--dist <out.zip> [opts]       Create universal AnyKernel3 or Magisk/KSU module ZIP"
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
#include "flash_engine.h"

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
	if (len >= 4 && memcmp(b, "\x28\xb5\x2f\xfd", 4) == 0) return BOOT_FMT_ZSTD;
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
	if (len >= 4 && memcmp(b, "\xd7\xb7\xab\x1e", 4) == 0) return BOOT_FMT_DTBO;
	if (len >= 4 && memcmp(b, "\x3a\xff\x26\xed", 4) == 0) return BOOT_FMT_SPARSE;
	if (len >= 4 && memcmp(b, "AVB0", 4) == 0) return BOOT_FMT_VBMETA;
	if (len >= 4 && memcmp(b, "CrAU", 4) == 0) return BOOT_FMT_PAYLOAD;
	if (len >= 8 && memcmp(b, "\x44\x48\x54\x42\x01\x00\x00\x00", 8) == 0) return BOOT_FMT_DHTB;
	if (len >= 20 && memcmp(b, "-SIGNED-BY-SIGNBLOB-", 20) == 0) return BOOT_FMT_BLOB;
	if (len >= 4 && memcmp(b, "\x18\x28\x6f\x01", 4) == 0) return BOOT_FMT_ZIMAGE;
	if (len >= 64 && memcmp(b + 56, "ARM\x64", 4) == 0) return BOOT_FMT_ARM64_IMAGE;
	if (len >= 6 && (memcmp(b, "070701", 6) == 0 || memcmp(b, "070702", 6) == 0 || memcmp(b, "070707", 6) == 0)) return BOOT_FMT_CPIO;
	if (len >= 2 && (memcmp(b, "\xc7\x71", 2) == 0 || memcmp(b, "\x71\xc7", 2) == 0)) return BOOT_FMT_CPIO;
	if (len >= 1024 + 4 && memcmp(b + 1024, "\xe2\xe1\xf5\xe0", 4) == 0) return BOOT_FMT_EROFS;
	if (len >= 1024 + 4 && memcmp(b + 1024, "\x10\x20\xf5\xf2", 4) == 0) return BOOT_FMT_F2FS;
	if (len >= 1080 + 2 && memcmp(b + 1080, "\x53\xef", 2) == 0) return BOOT_FMT_EXT4;
	if (len >= 4096 + 4 && memcmp(b + 4096, "gDla", 4) == 0) return BOOT_FMT_SUPER;
	if (len >= 4 && (memcmp(b, "gDla", 4) == 0 || memcmp(b, "0PLA", 4) == 0)) return BOOT_FMT_SUPER;
	if (len >= 4 && (memcmp(b, "hsqs", 4) == 0 || memcmp(b, "sqsh", 4) == 0)) return BOOT_FMT_SQUASHFS;
	if (len >= 4 && memcmp(b, "\x88\x16\x88\x58", 4) == 0) return BOOT_FMT_MTK;

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
	case BOOT_FMT_ZSTD:        return "zstd";
	case BOOT_FMT_DTB:         return "dtb";
	case BOOT_FMT_DTBO:        return "dtbo";
	case BOOT_FMT_ZIMAGE:      return "zimage";
	case BOOT_FMT_ARM64_IMAGE: return "arm64_image";
	case BOOT_FMT_CPIO:        return "cpio";
	case BOOT_FMT_SPARSE:      return "sparse";
	case BOOT_FMT_EROFS:       return "erofs";
	case BOOT_FMT_F2FS:        return "f2fs";
	case BOOT_FMT_EXT4:        return "ext4";
	case BOOT_FMT_SUPER:       return "super";
	case BOOT_FMT_SQUASHFS:    return "squashfs";
	case BOOT_FMT_VBMETA:      return "vbmeta";
	case BOOT_FMT_PAYLOAD:     return "payload";
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
	case BOOT_FMT_ZSTD:
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

/* =========================================================================
 * 3. Streaming Decompression via BusyBox libarchive & Zstandard
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

	if (fmt == BOOT_FMT_ZSTD) {
		pid_t pid = fork();
		if (pid == 0) {
			char *args[4];
			dup2(in_fd, STDIN_FILENO);
			dup2(out_fd, STDOUT_FILENO);
			close(in_fd);
			args[0] = (char *)"zstd";
			args[1] = (char *)"-dc";
			args[2] = NULL;
			BB_EXECVP("zstd", args);
			_exit(127);
		}
		if (pid > 0) {
			int status;
			waitpid(pid, &status, 0);
			ret = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
		} else {
			ret = -1;
		}
		close(in_fd);
		return ret;
	}

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
 * 4. Rich Boot Component & Image Inspection Engine
 * ========================================================================= */

static bool scan_linux_version_banner(const void *buf, size_t len, char *out, size_t out_sz) {
	static const char needle[] = "Linux version ";
	const uint8_t *p = (const uint8_t *)buf;
	const uint8_t *end;

	if (!buf || len < sizeof(needle) || !out || out_sz == 0) return false;
	out[0] = '\0';
	end = p + len - sizeof(needle);

	while (p <= end) {
		if (memcmp(p, needle, sizeof(needle) - 1) == 0) {
			size_t i = 0;
			while (i < out_sz - 1 && p[i] != '\0' && p[i] != '\n' && p[i] != '\r') {
				if (p[i] < 32 || p[i] > 126) break;
				out[i] = (char)p[i];
				i++;
			}
			out[i] = '\0';
			if (i > sizeof(needle) && strstr(out, "%s") == NULL) return true;
		}
		p++;
	}
	return false;
}

static bool extract_kernel_banner(const void *buf, size_t len, uint8_t fmt, char *out, size_t out_sz) {
	int fds[2];
	pid_t pid;
	char *decomp_buf;
	ssize_t nr = 0;
	bool found = false;

	if (!buf || len == 0 || !out || out_sz == 0) return false;
	if (!boot_fmt_compressed(fmt)) {
		return scan_linux_version_banner(buf, len, out, out_sz);
	}

	if (pipe(fds) < 0) return false;
	pid = fork();
	if (pid == 0) {
		close(fds[0]);
		bb_decompress_data(fmt, buf, len, fds[1]);
		close(fds[1]);
		_exit(0);
	}
	close(fds[1]);

	decomp_buf = malloc(1048576);
	if (decomp_buf) {
		nr = full_read(fds[0], decomp_buf, 1048576);
	}
	close(fds[0]);
	if (pid > 0) {
		kill(pid, SIGPIPE);
		waitpid(pid, NULL, 0);
	}

	if (decomp_buf && nr > 0) {
		found = scan_linux_version_banner(decomp_buf, (size_t)nr, out, out_sz);
	}
	free(decomp_buf);
	return found;
}

static void inspect_arm64_image(const void *buf, size_t len, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	uint64_t text_offset, image_size, flags;
	uint8_t endian, page_sz_code, phys_placement;
	const char *ps_str = "unspecified";

	if (!buf || len < 64) return;
	if (memcmp(b + 56, "ARM\x64", 4) != 0) return;

	text_offset = SWAP_LE64(*(const uint64_t *)(b + 8));
	image_size = SWAP_LE64(*(const uint64_t *)(b + 16));
	flags = SWAP_LE64(*(const uint64_t *)(b + 24));
	endian = flags & 1;
	page_sz_code = (flags >> 1) & 3;
	phys_placement = (flags >> 3) & 1;

	if (page_sz_code == 1) ps_str = "4KB";
	else if (page_sz_code == 2) ps_str = "16KB";
	else if (page_sz_code == 3) ps_str = "64KB";

	printf("%sArch:                 AArch64 (ARM64)\n", prefix);
	printf("%sText Offset:          0x%016llx\n", prefix, (unsigned long long)text_offset);
	printf("%sEffective Image Sz:   %llu bytes (0x%llx)\n", prefix, (unsigned long long)image_size, (unsigned long long)image_size);
	printf("%sEndianness:           %s\n", prefix, endian ? "Big Endian" : "Little Endian");
	printf("%sPage Size Support:    %s\n", prefix, ps_str);
	printf("%sPhysical Placement:   %s\n", prefix, phys_placement ? "2MB aligned at DRAM base" : "2MB aligned anywhere in DRAM");
}

static void inspect_arm32_zimage(const void *buf, size_t len, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	uint32_t start, end;

	if (!buf || len < 48) return;
	if (memcmp(b + 36, "\x18\x28\x6f\x01", 4) != 0) return;

	start = SWAP_LE32(*(const uint32_t *)(b + 40));
	end = SWAP_LE32(*(const uint32_t *)(b + 44));

	printf("%sArch:                 ARM 32-bit (zImage)\n", prefix);
	printf("%szImage Start:         0x%08x\n", prefix, start);
	printf("%szImage End:           0x%08x\n", prefix, end);
	if (end > start) {
		printf("%szImage Raw Size:      %u bytes\n", prefix, end - start);
	}
}

static void inspect_fdt_details(const void *buf, size_t len, const char *prefix) {
	const struct fdt_header *fdt;
	uint32_t magic, totalsize, off_struct, off_strings, version;
	const uint8_t *b = (const uint8_t *)buf;

	if (!buf || len < sizeof(struct fdt_header)) return;
	fdt = (const struct fdt_header *)buf;
	magic = SWAP_BE32(fdt->magic);
	if (magic != FDT_MAGIC) return;

	totalsize = SWAP_BE32(fdt->totalsize);
	off_struct = SWAP_BE32(fdt->off_dt_struct);
	off_strings = SWAP_BE32(fdt->off_dt_strings);
	version = SWAP_BE32(fdt->version);

	printf("%sFDT Version:          %u\n", prefix, version);
	printf("%sFDT Total Size:       %u bytes\n", prefix, totalsize);

	if (off_struct < len && off_strings < len) {
		const uint32_t *p = (const uint32_t *)(b + off_struct);
		const uint32_t *end = (const uint32_t *)(b + len);
		const char *strings = (const char *)(b + off_strings);
		size_t strings_sz = len - off_strings;

		if (p < end && SWAP_BE32(*p) == 1) {
			const char *name;
			size_t nlen;
			p++;
			name = (const char *)p;
			nlen = strlen(name) + 1;
			p += (nlen + 3) / 4;

			while (p < end) {
				uint32_t token = SWAP_BE32(*p++);
				if (token == 3) {
					uint32_t plen = SWAP_BE32(*p++);
					uint32_t nameoff = SWAP_BE32(*p++);
					const char *prop_name = (nameoff < strings_sz) ? (strings + nameoff) : "";
					const char *prop_data = (const char *)p;
					p += (plen + 3) / 4;

					if (strcmp(prop_name, "model") == 0 && plen > 0) {
						char model_buf[256];
						size_t cpy_sz = plen < sizeof(model_buf) ? plen : sizeof(model_buf) - 1;
						memcpy(model_buf, prop_data, cpy_sz);
						model_buf[cpy_sz] = '\0';
						printf("%sPlatform Model:       %s\n", prefix, model_buf);
					} else if (strcmp(prop_name, "compatible") == 0 && plen > 0) {
						char compat_buf[512];
						size_t ci = 0, di = 0;
						compat_buf[0] = '\0';
						while (di < plen && ci < sizeof(compat_buf) - 2) {
							if (prop_data[di] == '\0') {
								if (di + 1 < plen && prop_data[di + 1] != '\0') {
									compat_buf[ci++] = ',';
									compat_buf[ci++] = ' ';
								}
							} else {
								compat_buf[ci++] = prop_data[di];
							}
							di++;
						}
						compat_buf[ci] = '\0';
						printf("%sPlatform Compatible:  %s\n", prefix, compat_buf);
					}
				} else if (token == 1 || token == 2 || token == 9) {
					break;
				}
			}
		}
	}
}

static void inspect_dtbo_details(const void *buf, size_t len, const char *prefix) {
	const struct dt_table_header *dtb_hdr;
	if (!buf || len < sizeof(struct dt_table_header)) return;
	dtb_hdr = (const struct dt_table_header *)buf;
	if (SWAP_BE32(dtb_hdr->magic) == DT_TABLE_MAGIC || SWAP_LE32(dtb_hdr->magic) == DT_TABLE_MAGIC) {
		uint32_t entries = (dtb_hdr->magic == DT_TABLE_MAGIC) ? dtb_hdr->dt_entry_count : SWAP_BE32(dtb_hdr->dt_entry_count);
		uint32_t page_sz = (dtb_hdr->magic == DT_TABLE_MAGIC) ? dtb_hdr->page_size : SWAP_BE32(dtb_hdr->page_size);
		printf("%sFormat:               DTBO Table\n", prefix);
		printf("%sEntries Count:        %u\n", prefix, entries);
		if (page_sz) printf("%sPage Size:            %u bytes\n", prefix, page_sz);
	} else if (len >= 4 && SWAP_BE32(*(const uint32_t *)buf) == FDT_MAGIC) {
		inspect_fdt_details(buf, len, prefix);
	}
}

static void inspect_cpio_buffer(const void *buf, size_t len, const char *prefix) {
	const char *b = (const char *)buf;
	const char *fmt_str = "Unknown CPIO";
	bool is_svr4 = false;
	bool has_init = false;
	bool has_recovery = false;
	bool has_magisk = false;
	bool has_modules = false;
	size_t file_count = 0;
	size_t off = 0;

	if (!buf || len < 6) return;

	if (memcmp(b, "070701", 6) == 0) {
		fmt_str = "SVR4 new portable format without CRC (070701)";
		is_svr4 = true;
	} else if (memcmp(b, "070702", 6) == 0) {
		fmt_str = "SVR4 new portable format with CRC (070702)";
		is_svr4 = true;
	} else if (memcmp(b, "070707", 6) == 0) {
		fmt_str = "POSIX portable format (070707 odc)";
	} else if (memcmp(b, "\xc7\x71", 2) == 0 || memcmp(b, "\x71\xc7", 2) == 0) {
		fmt_str = "CPIO old binary format";
	}

	printf("%sCPIO Variant:         %s\n", prefix, fmt_str);

	if (is_svr4) {
		while (off + 110 <= len) {
			const char *hdr = b + off;
			char namesize_str[9] = {0};
			char filesize_str[9] = {0};
			unsigned long namesize = 0;
			unsigned long filesize = 0;
			const char *filename;

			if (memcmp(hdr, "070701", 6) != 0 && memcmp(hdr, "070702", 6) != 0) break;

			memcpy(filesize_str, hdr + 54, 8);
			memcpy(namesize_str, hdr + 94, 8);
			filesize = strtoul(filesize_str, NULL, 16);
			namesize = strtoul(namesize_str, NULL, 16);

			off += 110;
			if (namesize == 0 || off + namesize > len) break;

			filename = b + off;
			if (strcmp(filename, "TRAILER!!!") == 0) break;

			file_count++;
			if (strcmp(filename, "init") == 0 || strcmp(filename, "init.rc") == 0) has_init = true;
			if (strstr(filename, "recovery") != NULL) has_recovery = true;
			if (strstr(filename, "magisk") != NULL || strstr(filename, "overlay.d") != NULL) has_magisk = true;
			if (strstr(filename, ".ko") != NULL || strstr(filename, "modules") != NULL) has_modules = true;

			off += (namesize + 3) / 4 * 4;
			off += (filesize + 3) / 4 * 4;
			if (file_count >= 100) break;
		}

		{
			const char *role = "Generic Ramdisk";
			if (has_recovery) role = "Recovery / TWRP Environment";
			else if (has_magisk) role = "Magisk-Patched Rootfs";
			else if (has_init) role = "First-Stage Android Rootfs (init)";
			else if (has_modules) role = "Vendor DLKM / Modules Ramdisk";

			printf("%sRamdisk Role:         %s\n", prefix, role);
		}
	}
}

static void inspect_ramdisk_details(const void *buf, size_t len, uint8_t fmt, const char *prefix) {
	if (fmt == BOOT_FMT_CPIO) {
		inspect_cpio_buffer(buf, len, prefix);
	} else if (boot_fmt_compressed(fmt)) {
		int fds[2];
		pid_t pid;
		char decomp_buf[65536];
		ssize_t nr = 0;

		if (pipe(fds) < 0) return;
		pid = fork();
		if (pid == 0) {
			close(fds[0]);
			bb_decompress_data(fmt, buf, len, fds[1]);
			close(fds[1]);
			_exit(0);
		}
		close(fds[1]);
		nr = full_read(fds[0], decomp_buf, sizeof(decomp_buf));
		close(fds[0]);
		if (pid > 0) {
			kill(pid, SIGPIPE);
			waitpid(pid, NULL, 0);
		}
		if (nr > 110) {
			inspect_cpio_buffer(decomp_buf, (size_t)nr, prefix);
		}
	}
}

static void inspect_vendor_ramdisk_table(const void *buf, size_t len, uint32_t entry_num, uint32_t entry_sz, const char *prefix) {
	const uint8_t *p = (const uint8_t *)buf;
	uint32_t i;
	if (!buf || len < entry_sz) return;
	printf("%sEntries (%u):\n", prefix, entry_num);
	for (i = 0; i < entry_num && (i + 1) * entry_sz <= len; i++) {
		const struct vendor_ramdisk_table_entry_v4 *e = (const struct vendor_ramdisk_table_entry_v4 *)(p + i * entry_sz);
		printf("%s  [%u] Name: %-16s Size: %-8u Offset: 0x%08x Type: %u\n",
		       prefix, i, e->ramdisk_name, e->ramdisk_size, e->ramdisk_offset, e->ramdisk_type);
	}
}

static void print_bootconfig_preview(const void *buf, size_t len, const char *prefix) {
	const char *b = (const char *)buf;
	size_t i, start = 0;
	int line_count = 0, shown = 0;
	if (!buf || len == 0) return;

	for (i = 0; i < len; i++) {
		if (b[i] == '\n') line_count++;
	}
	printf("%sParameters Count:   %d\n", prefix, line_count);
	printf("%sPreview (first 5 parameters):\n", prefix);
	for (i = 0; i <= len && shown < 5; i++) {
		if (i == len || b[i] == '\n') {
			size_t llen = i - start;
			if (llen > 0 && b[start] != '#') {
				printf("%s  %.*s\n", prefix, (int)llen, b + start);
				shown++;
			}
			start = i + 1;
		}
	}
}

/* =========================================================================
 * Comprehensive Image & Compression Inspection Engine
 * ========================================================================= */

static void inspect_compression_details(const void *buf, size_t len, uint8_t fmt, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	if (!buf || len < 4) return;

	switch (fmt) {
	case BOOT_FMT_GZIP:
		if (len >= 10 && b[0] == 0x1f && (b[1] == 0x8b || b[1] == 0x9e)) {
			uint8_t flg = b[3];
			uint32_t mtime = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
			uint8_t xfl = b[8];
			uint8_t os = b[9];
			const char *os_name = (os == 0) ? "FAT" : (os == 3) ? "Unix/Linux" : (os == 255) ? "Unknown" : "Other";
			const char *level_str = (xfl == 2) ? "Maximum compression" : (xfl == 4) ? "Fastest algorithm" : "Default";

			printf("%sCompression Algorithm: GZIP (Deflate)\n", prefix);
			printf("%sCompression Level:     %s (XFL 0x%02x)\n", prefix, level_str, xfl);
			printf("%sTarget OS:             %s (OS 0x%02x)\n", prefix, os_name, os);
			if (mtime > 0) {
				time_t t = (time_t)mtime;
				struct tm tm_val;
				char time_buf[64];
				if (gmtime_r(&t, &tm_val)) {
					strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC", &tm_val);
					printf("%sTimestamp (MTime):    %s\n", prefix, time_buf);
				}
			}
			if (flg & 0x08) { /* FNAME */
				size_t fn_off = 10;
				if (flg & 0x04) { /* FEXTRA */
					if (fn_off + 2 <= len) {
						uint16_t xlen = (uint16_t)b[fn_off] | ((uint16_t)b[fn_off + 1] << 8);
						fn_off += 2 + xlen;
					}
				}
				if (fn_off < len) {
					char orig_name[128];
					size_t k = 0;
					while (fn_off < len && b[fn_off] != 0 && k < sizeof(orig_name) - 1) {
						orig_name[k++] = (char)b[fn_off++];
					}
					orig_name[k] = '\0';
					if (k > 0) printf("%sOriginal Filename:    %s\n", prefix, orig_name);
				}
			}
			if (len >= 18) {
				uint32_t isize = (uint32_t)b[len - 4] | ((uint32_t)b[len - 3] << 8) | ((uint32_t)b[len - 2] << 16) | ((uint32_t)b[len - 1] << 24);
				uint32_t crc32_val = (uint32_t)b[len - 8] | ((uint32_t)b[len - 7] << 8) | ((uint32_t)b[len - 6] << 16) | ((uint32_t)b[len - 5] << 24);
				printf("%sCRC32 Checksum:       0x%08x\n", prefix, crc32_val);
				if (isize > 0) {
					double ratio = ((double)len / (double)isize) * 100.0;
					printf("%sUncompressed Size:    %u bytes (%.2f MB)\n", prefix, isize, (double)isize / (1024 * 1024));
					printf("%sCompression Ratio:    %.1f%% (Saved %.1f%%)\n", prefix, ratio, 100.0 - ratio);
				}
			}
		}
		break;

	case BOOT_FMT_ZSTD:
		if (len >= 5 && memcmp(b, "\x28\xb5\x2f\xfd", 4) == 0) {
			uint8_t fhd = b[4];
			uint8_t fcs_flag = (fhd >> 6) & 3;
			bool single_seg = (fhd & (1 << 5)) != 0;
			bool content_chk = (fhd & (1 << 2)) != 0;
			uint8_t dict_flag = fhd & 3;
			size_t off = 5;
			uint64_t win_sz = 0;
			uint64_t uncomp_sz = 0;

			printf("%sCompression Algorithm: Zstandard (ZSTD RFC 8478)\n", prefix);
			if (!single_seg && off < len) {
				uint8_t wb = b[off++];
				uint8_t exp = wb >> 3;
				uint8_t mant = wb & 7;
				win_sz = (1ULL << (10 + exp)) + (mant << (7 + exp));
				printf("%sWindow Size:          %llu KB\n", prefix, (unsigned long long)(win_sz / 1024));
			}
			if (dict_flag) {
				size_t dlen = (dict_flag == 1) ? 1 : (dict_flag == 2) ? 2 : 4;
				off += dlen;
			}
			if (single_seg && fcs_flag == 0) {
				if (off < len) uncomp_sz = b[off++];
			} else if (fcs_flag == 1 && off + 2 <= len) {
				uncomp_sz = ((uint64_t)b[off] | ((uint64_t)b[off + 1] << 8)) + 256;
				off += 2;
			} else if (fcs_flag == 2 && off + 4 <= len) {
				uncomp_sz = (uint64_t)b[off] | ((uint64_t)b[off + 1] << 8) | ((uint64_t)b[off + 2] << 16) | ((uint64_t)b[off + 3] << 24);
				off += 4;
			} else if (fcs_flag == 3 && off + 8 <= len) {
				memcpy(&uncomp_sz, b + off, 8);
				off += 8;
			}
			if (uncomp_sz > 0) {
				double ratio = ((double)len / (double)uncomp_sz) * 100.0;
				printf("%sUncompressed Size:    %llu bytes (%.2f MB)\n", prefix, (unsigned long long)uncomp_sz, (double)uncomp_sz / (1024 * 1024));
				printf("%sCompression Ratio:    %.1f%% (Saved %.1f%%)\n", prefix, ratio, 100.0 - ratio);
			}
			printf("%sContent Checksum:     %s\n", prefix, content_chk ? "Enabled (XXH64)" : "Disabled");
		}
		break;

	case BOOT_FMT_LZ4:
		if (len >= 7 && (memcmp(b, "\x04\x22\x4d\x18", 4) == 0 || memcmp(b, "\x03\x21\x4c\x18", 4) == 0)) {
			uint8_t flg = b[4];
			uint8_t bd = b[5];
			uint8_t ver = (flg >> 6) & 3;
			bool blk_indep = (flg & (1 << 5)) != 0;
			bool blk_chk = (flg & (1 << 4)) != 0;
			bool content_sz = (flg & (1 << 3)) != 0;
			bool content_chk = (flg & (1 << 2)) != 0;
			uint32_t blk_max = (bd >> 4) & 7;
			const char *blk_str = (blk_max == 4) ? "64 KB" : (blk_max == 5) ? "256 KB" : (blk_max == 6) ? "1 MB" : (blk_max == 7) ? "4 MB" : "Default";

			printf("%sCompression Algorithm: LZ4 Frame (v%u)\n", prefix, ver);
			printf("%sMax Block Size:       %s\n", prefix, blk_str);
			printf("%sBlock Independence:   %s\n", prefix, blk_indep ? "Independent" : "Linked");
			printf("%sChecksums:            Block: %s, Content: %s\n", prefix, blk_chk ? "Yes" : "No", content_chk ? "Yes" : "No");
			if (content_sz && len >= 15) {
				uint64_t uncomp_sz = 0;
				memcpy(&uncomp_sz, b + 6, 8);
				if (uncomp_sz > 0) {
					double ratio = ((double)len / (double)uncomp_sz) * 100.0;
					printf("%sUncompressed Size:    %llu bytes (%.2f MB)\n", prefix, (unsigned long long)uncomp_sz, (double)uncomp_sz / (1024 * 1024));
					printf("%sCompression Ratio:    %.1f%% (Saved %.1f%%)\n", prefix, ratio, 100.0 - ratio);
				}
			}
		}
		break;

	case BOOT_FMT_LZ4_LEGACY:
	case BOOT_FMT_LZ4_LG:
		printf("%sCompression Algorithm: LZ4 Legacy Stream (%s)\n", prefix, (fmt == BOOT_FMT_LZ4_LG) ? "LG Format" : "Standard Legacy");
		break;

	case BOOT_FMT_XZ:
		if (len >= 12 && memcmp(b, "\xfd" "7zXZ\x00", 6) == 0) {
			uint8_t check_type = b[7] & 0x0f;
			const char *chk_str = (check_type == 0) ? "None" : (check_type == 1) ? "CRC32" : (check_type == 4) ? "CRC64" : (check_type == 10) ? "SHA-256" : "Unknown";
			printf("%sCompression Algorithm: XZ (LZMA2)\n", prefix);
			printf("%sIntegrity Check:      %s (Type %u)\n", prefix, chk_str, check_type);
		}
		break;

	case BOOT_FMT_BZIP2:
		if (len >= 4 && memcmp(b, "BZh", 3) == 0) {
			char lvl = b[3];
			printf("%sCompression Algorithm: BZIP2 (Block level %c = %d KB)\n", prefix, lvl, (lvl - '0') * 100);
		}
		break;

	case BOOT_FMT_LZOP:
		if (len >= 9 && memcmp(b, "\x89LZO", 4) == 0) {
			uint16_t ver = (uint16_t)b[4] << 8 | b[5];
			printf("%sCompression Algorithm: LZO / LZO1X (Version 0x%04x)\n", prefix, ver);
		}
		break;

	case BOOT_FMT_LZMA:
		if (len >= 13 && b[0] == 0x5d) {
			uint32_t dict_sz = (uint32_t)b[1] | ((uint32_t)b[2] << 8) | ((uint32_t)b[3] << 16) | ((uint32_t)b[4] << 24);
			uint64_t uncomp_sz = 0;
			memcpy(&uncomp_sz, b + 5, 8);
			printf("%sCompression Algorithm: Raw LZMA\n", prefix);
			printf("%sDictionary Size:      %u bytes (%u KB)\n", prefix, dict_sz, dict_sz / 1024);
			if (uncomp_sz != 0xFFFFFFFFFFFFFFFFULL && uncomp_sz > 0) {
				double ratio = ((double)len / (double)uncomp_sz) * 100.0;
				printf("%sUncompressed Size:    %llu bytes (%.2f MB)\n", prefix, (unsigned long long)uncomp_sz, (double)uncomp_sz / (1024 * 1024));
				printf("%sCompression Ratio:    %.1f%% (Saved %.1f%%)\n", prefix, ratio, 100.0 - ratio);
			}
		}
		break;

	default:
		break;
	}
}

static void inspect_kernel_embedded_details(const void *buf, size_t len, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	const uint8_t *end;
	const uint8_t *p;

	if (!buf || len < 64) return;
	end = b + len - 16;

	/* Scan for IKCONFIG (embedded /proc/config.gz) */
	p = b;
	while (p <= end) {
		if (memcmp(p, "IKCFG_ST", 8) == 0) {
			size_t off = p - b;
			const uint8_t *gz_start = p + 8;
			if (gz_start + 10 <= b + len && gz_start[0] == 0x1f && gz_start[1] == 0x8b) {
				printf("%sEmbedded Kernel Config: Present (IKCONFIG /proc/config.gz at offset 0x%zx)\n", prefix, off);
			}
			break;
		}
		p++;
	}

	/* Scan for Vermagic */
	p = b;
	while (p <= end) {
		if (memcmp(p, "vermagic=", 9) == 0) {
			char vm[128];
			size_t k = 0;
			const uint8_t *s = p + 9;
			while (s < b + len && *s >= 0x20 && *s <= 0x7e && k < sizeof(vm) - 1) {
				vm[k++] = *s++;
			}
			vm[k] = '\0';
			if (k > 0) printf("%sKernel Vermagic:        %s\n", prefix, vm);
			break;
		}
		p++;
	}
}

static void inspect_filesystem_details(const void *buf, size_t len, uint8_t fmt, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	if (!buf || len < 1024 + 128) return;

	if (fmt == BOOT_FMT_EROFS) {
		const uint8_t *sb = b + 1024;
		uint32_t magic = (uint32_t)sb[0] | ((uint32_t)sb[1] << 8) | ((uint32_t)sb[2] << 16) | ((uint32_t)sb[3] << 24);
		if (magic == EROFS_SUPER_MAGIC_V1) {
			uint8_t blkszbits = sb[8];
			uint32_t blk_sz = 1U << blkszbits;
			uint32_t blocks = (uint32_t)sb[24] | ((uint32_t)sb[25] << 8) | ((uint32_t)sb[26] << 16) | ((uint32_t)sb[27] << 24);
			uint64_t inos = 0;
			char vol[17] = {0};
			uint32_t feat_incompat = (uint32_t)sb[48] | ((uint32_t)sb[49] << 8) | ((uint32_t)sb[50] << 16) | ((uint32_t)sb[51] << 24);
			uint64_t total_sz = (uint64_t)blocks * blk_sz;

			memcpy(&inos, sb + 16, 8);
			memcpy(vol, sb + 32, 16);

			printf("%sType:                 EROFS (Enhanced Read-Only File System)\n", prefix);
			printf("%sBlock Size:           %u bytes\n", prefix, blk_sz);
			printf("%sTotal Blocks:         %u\n", prefix, blocks);
			printf("%sFilesystem Size:      %llu bytes (%.2f MB)\n", prefix, (unsigned long long)total_sz, (double)total_sz / (1024 * 1024));
			if (inos) printf("%sInodes Count:         %llu\n", prefix, (unsigned long long)inos);
			if (vol[0]) printf("%sVolume Label:         %s\n", prefix, vol);
			printf("%sCompression Features: %s%s\n", prefix,
			       (feat_incompat & 1) ? "LZ4 " : "",
			       (feat_incompat & 2) ? "LZMA/MicroLZMA " : "");
		}
	} else if (fmt == BOOT_FMT_EXT4) {
		const uint8_t *sb = b + 1024;
		uint16_t magic = (uint16_t)sb[56] | ((uint16_t)sb[57] << 8);
		if (magic == 0xef53) {
			uint32_t inodes_cnt = (uint32_t)sb[0] | ((uint32_t)sb[1] << 8) | ((uint32_t)sb[2] << 16) | ((uint32_t)sb[3] << 24);
			uint32_t blocks_cnt = (uint32_t)sb[4] | ((uint32_t)sb[5] << 8) | ((uint32_t)sb[6] << 16) | ((uint32_t)sb[7] << 24);
			uint32_t free_blocks = (uint32_t)sb[12] | ((uint32_t)sb[13] << 8) | ((uint32_t)sb[14] << 16) | ((uint32_t)sb[15] << 24);
			uint32_t free_inodes = (uint32_t)sb[16] | ((uint32_t)sb[17] << 8) | ((uint32_t)sb[18] << 16) | ((uint32_t)sb[19] << 24);
			uint32_t log_blk_sz = (uint32_t)sb[24] | ((uint32_t)sb[25] << 8) | ((uint32_t)sb[26] << 16) | ((uint32_t)sb[27] << 24);
			uint32_t blk_sz = 1024U << log_blk_sz;
			uint64_t total_sz = (uint64_t)blocks_cnt * blk_sz;
			char vol[17] = {0};
			memcpy(vol, sb + 120, 16);

			printf("%sType:                 EXT4 File System\n", prefix);
			printf("%sBlock Size:           %u bytes\n", prefix, blk_sz);
			printf("%sTotal Blocks:         %u (Free: %u)\n", prefix, blocks_cnt, free_blocks);
			printf("%sFilesystem Size:      %llu bytes (%.2f MB)\n", prefix, (unsigned long long)total_sz, (double)total_sz / (1024 * 1024));
			printf("%sInodes:               %u (Free: %u)\n", prefix, inodes_cnt, free_inodes);
			if (vol[0]) printf("%sVolume Label:         %s\n", prefix, vol);
		}
	} else if (fmt == BOOT_FMT_F2FS) {
		const uint8_t *sb = b + 1024;
		uint32_t magic = (uint32_t)sb[0] | ((uint32_t)sb[1] << 8) | ((uint32_t)sb[2] << 16) | ((uint32_t)sb[3] << 24);
		if (magic == 0xf2f52010) {
			uint16_t major = (uint16_t)sb[4] | ((uint16_t)sb[5] << 8);
			uint16_t minor = (uint16_t)sb[6] | ((uint16_t)sb[7] << 8);
			uint32_t log_blksz = (uint32_t)sb[12] | ((uint32_t)sb[13] << 8) | ((uint32_t)sb[14] << 16) | ((uint32_t)sb[15] << 24);
			uint32_t blk_sz = 1U << log_blksz;
			uint64_t block_count = 0;
			uint64_t total_sz;
			memcpy(&block_count, sb + 32, 8);
			total_sz = block_count * blk_sz;

			printf("%sType:                 F2FS (Flash-Friendly File System)\n", prefix);
			printf("%sVersion:              %u.%u\n", prefix, major, minor);
			printf("%sBlock Size:           %u bytes\n", prefix, blk_sz);
			printf("%sTotal Blocks:         %llu\n", prefix, (unsigned long long)block_count);
			printf("%sFilesystem Size:      %llu bytes (%.2f MB)\n", prefix, (unsigned long long)total_sz, (double)total_sz / (1024 * 1024));
		}
	}
}

static void inspect_super_details(const void *buf, size_t len, const char *prefix) {
	const uint8_t *b = (const uint8_t *)buf;
	const struct lp_metadata_geometry *geom = NULL;
	const struct lp_metadata_header *hdr = NULL;
	size_t geom_off = 0;
	size_t hdr_off = 0;
	uint32_t i;

	if (!buf || len < 4096 + sizeof(struct lp_metadata_geometry)) return;

	if (memcmp(b + 4096, "gDla", 4) == 0) {
		geom = (const struct lp_metadata_geometry *)(b + 4096);
		geom_off = 4096;
	} else if (memcmp(b, "gDla", 4) == 0) {
		geom = (const struct lp_metadata_geometry *)b;
		geom_off = 0;
	} else {
		return;
	}

	printf("%sType:                 Android Dynamic Partitions (Super / liblp)\n", prefix);
	printf("%sLogical Block Size:   %u bytes\n", prefix, geom->logical_block_size);
	printf("%sMetadata Max Size:    %u bytes\n", prefix, geom->metadata_max_size);
	printf("%sMetadata Slots:       %u\n", prefix, geom->metadata_slot_count);

	/* Look for primary metadata header:
	 * In standard Android dynamic partitions (liblp), offset 0 is 4KB reserved,
	 * offset 4096 is primary geometry (4KB), offset 8192 is backup geometry (4KB),
	 * and offset 12288 (4096 + 2 * 4096) is metadata slot 0 (0PLA).
	 * In metadata-only images where geom_off == 0, slot 0 is at offset 8192.
	 */
	if (geom_off == 4096 && len >= 12288 + sizeof(struct lp_metadata_header) && memcmp(b + 12288, "0PLA", 4) == 0) {
		hdr = (const struct lp_metadata_header *)(b + 12288);
		hdr_off = 12288;
	} else if (geom_off == 0 && len >= 8192 + sizeof(struct lp_metadata_header) && memcmp(b + 8192, "0PLA", 4) == 0) {
		hdr = (const struct lp_metadata_header *)(b + 8192);
		hdr_off = 8192;
	} else {
		size_t scan;
		for (scan = 0; scan + sizeof(struct lp_metadata_header) <= len && scan < 262144; scan += 512) {
			if (memcmp(b + scan, "0PLA", 4) == 0) {
				hdr = (const struct lp_metadata_header *)(b + scan);
				hdr_off = scan;
				break;
			}
		}
	}

	if (hdr && hdr_off + hdr->header_size <= len) {
		const uint8_t *tables_base = b + hdr_off + hdr->header_size;
		printf("%sMetadata Version:     %u.%u\n", prefix, hdr->major_version, hdr->minor_version);
		printf("%sTables Size:          %u bytes\n", prefix, hdr->tables_size);

		/* Block Devices */
		if (hdr->block_devices.num_entries > 0 &&
		    hdr->block_devices.offset + hdr->block_devices.num_entries * hdr->block_devices.entry_size <= hdr->tables_size) {
			printf("%sBlock Devices (%u):\n", prefix, hdr->block_devices.num_entries);
			for (i = 0; i < hdr->block_devices.num_entries; i++) {
				const struct lp_metadata_block_device *bdev =
					(const struct lp_metadata_block_device *)(tables_base + hdr->block_devices.offset + i * hdr->block_devices.entry_size);
				printf("%s  [%u] Device: %-16s Size: %llu bytes (%.2f GB) Alignment: %u\n",
				       prefix, i, bdev->partition_name, (unsigned long long)bdev->size,
				       (double)bdev->size / (1024.0 * 1024.0 * 1024.0), bdev->alignment);
			}
		}

		/* Partition Groups */
		if (hdr->groups.num_entries > 0 &&
		    hdr->groups.offset + hdr->groups.num_entries * hdr->groups.entry_size <= hdr->tables_size) {
			printf("%sPartition Groups (%u):\n", prefix, hdr->groups.num_entries);
			for (i = 0; i < hdr->groups.num_entries; i++) {
				const struct lp_metadata_group *grp =
					(const struct lp_metadata_group *)(tables_base + hdr->groups.offset + i * hdr->groups.entry_size);
				if (grp->maximum_size > 0) {
					printf("%s  [%u] Group: %-24s Max Size: %llu bytes (%.2f MB)\n",
					       prefix, i, grp->name, (unsigned long long)grp->maximum_size,
					       (double)grp->maximum_size / (1024.0 * 1024.0));
				} else {
					printf("%s  [%u] Group: %-24s Max Size: Unlimited\n", prefix, i, grp->name);
				}
			}
		}

		/* Partitions & Extents */
		if (hdr->partitions.num_entries > 0 &&
		    hdr->partitions.offset + hdr->partitions.num_entries * hdr->partitions.entry_size <= hdr->tables_size) {
			printf("%sLogical Partitions (%u):\n", prefix, hdr->partitions.num_entries);
			printf("%s  %-24s %-16s %-14s %-12s %s\n", prefix, "Partition", "Size (Bytes)", "Size (MB)", "Group", "Attributes");
			printf("%s  --------------------------------------------------------------------------------\n", prefix);

			for (i = 0; i < hdr->partitions.num_entries; i++) {
				const struct lp_metadata_partition *part =
					(const struct lp_metadata_partition *)(tables_base + hdr->partitions.offset + i * hdr->partitions.entry_size);
				uint64_t total_sectors = 0;
				uint64_t part_bytes;
				uint32_t e;
				const char *grp_name = "unknown";
				char attr_buf[64];

				attr_buf[0] = '\0';
				if (hdr->groups.num_entries > 0 && part->group_index < hdr->groups.num_entries) {
					const struct lp_metadata_group *grp =
						(const struct lp_metadata_group *)(tables_base + hdr->groups.offset + part->group_index * hdr->groups.entry_size);
					grp_name = grp->name;
				}

				if (hdr->extents.num_entries > 0) {
					for (e = 0; e < part->num_extents; e++) {
						uint32_t eidx = part->first_extent_index + e;
						if (eidx < hdr->extents.num_entries) {
							const struct lp_metadata_extent *ext =
								(const struct lp_metadata_extent *)(tables_base + hdr->extents.offset + eidx * hdr->extents.entry_size);
							total_sectors += ext->num_sectors;
						}
					}
				}
				part_bytes = total_sectors * 512;

				if (part->attributes & 1) strcat(attr_buf, "RO ");
				if (part->attributes & 2) strcat(attr_buf, "SLOT_SUFFIXED ");
				if (part->attributes & 4) strcat(attr_buf, "UPDATED ");
				if (part->attributes & 8) strcat(attr_buf, "DISABLED ");
				if (attr_buf[0] == '\0') strcpy(attr_buf, "none");

				printf("%s  %-24s %-16llu %-14.2f %-12s %s\n", prefix, part->name,
				       (unsigned long long)part_bytes, (double)part_bytes / (1024.0 * 1024.0), grp_name, attr_buf);
			}
		}
	}
}

static void inspect_sparse_details(const void *buf, size_t len, const char *prefix) {
	const struct sparse_header *sph;
	uint64_t unsparse_sz;
	const uint8_t *p;
	const uint8_t *end;
	uint32_t chunk_idx;
	uint32_t raw_chunks = 0, fill_chunks = 0, dont_care_chunks = 0, crc_chunks = 0;
	uint64_t data_bytes = 0;
	const uint8_t *first_raw_payload = NULL;
	size_t first_raw_len = 0;

	if (!buf || len < sizeof(struct sparse_header)) return;
	sph = (const struct sparse_header *)buf;
	unsparse_sz = (uint64_t)sph->total_blks * sph->blk_sz;

	printf("%sType:                 Android Sparse Image (simg)\n", prefix);
	printf("%sSparse Version:       %u.%u\n", prefix, sph->major_version, sph->minor_version);
	printf("%sBlock Size:           %u bytes\n", prefix, sph->blk_sz);
	printf("%sTotal Blocks:         %u\n", prefix, sph->total_blks);
	printf("%sUnsparse Raw Size:    %llu bytes (%.2f MB)\n", prefix, (unsigned long long)unsparse_sz, (double)unsparse_sz / (1024 * 1024));
	printf("%sTotal Chunks:         %u\n", prefix, sph->total_chunks);
	if (sph->image_checksum) printf("%sImage Checksum:       0x%08x\n", prefix, sph->image_checksum);

	/* Chunk scan */
	p = (const uint8_t *)buf + sph->file_hdr_sz;
	end = (const uint8_t *)buf + len;

	for (chunk_idx = 0; chunk_idx < sph->total_chunks && p + sph->chunk_hdr_sz <= end; chunk_idx++) {
		const struct chunk_header *ch = (const struct chunk_header *)p;
		uint16_t ctype = ch->chunk_type;
		uint32_t cblocks = ch->chunk_sz;
		uint32_t ctot = ch->total_sz;

		if (ctype == CHUNK_TYPE_RAW) {
			raw_chunks++;
			data_bytes += (uint64_t)cblocks * sph->blk_sz;
			if (!first_raw_payload && ctot > sph->chunk_hdr_sz) {
				first_raw_payload = p + sph->chunk_hdr_sz;
				first_raw_len = ctot - sph->chunk_hdr_sz;
			}
		} else if (ctype == CHUNK_TYPE_FILL) {
			fill_chunks++;
		} else if (ctype == CHUNK_TYPE_DONT_CARE) {
			dont_care_chunks++;
		} else if (ctype == CHUNK_TYPE_CRC32) {
			crc_chunks++;
		}

		if (ctot < sph->chunk_hdr_sz) break;
		p += ctot;
	}

	printf("%sChunk Breakdown:      RAW: %u, FILL: %u, DONT_CARE: %u, CRC32: %u\n",
	       prefix, raw_chunks, fill_chunks, dont_care_chunks, crc_chunks);
	printf("%sData Payload Size:    %llu bytes (%.2f MB)\n", prefix, (unsigned long long)data_bytes, (double)data_bytes / (1024.0 * 1024.0));
	if (unsparse_sz > 0) {
		double efficiency = ((double)len / (double)unsparse_sz) * 100.0;
		printf("%sStorage Reduction:    %.1f%% of raw size (Saved %.1f%%)\n", prefix, efficiency, 100.0 - efficiency);
	}

	/* Probe inner payload */
	if (first_raw_payload && first_raw_len >= 1024) {
		uint8_t inner_fmt = boot_check_fmt(first_raw_payload, first_raw_len);
		if (inner_fmt != BOOT_FMT_UNKNOWN) {
			printf("%sInner Payload:        %s\n", prefix, boot_fmt2name(inner_fmt));
			if (inner_fmt == BOOT_FMT_EROFS || inner_fmt == BOOT_FMT_EXT4 || inner_fmt == BOOT_FMT_F2FS) {
				inspect_filesystem_details(first_raw_payload, first_raw_len, inner_fmt, prefix);
			} else if (inner_fmt == BOOT_FMT_SUPER) {
				inspect_super_details(first_raw_payload, first_raw_len, prefix);
			}
		}
	}
}

static void inspect_avb_vbmeta_details(const void *buf, size_t len, const char *prefix) {
	const struct avb_vbmeta_image_header *vbh;
	const uint8_t *aux_base;
	size_t aux_sz;
	size_t off = 0;
	uint32_t desc_count = 0;

	if (!buf || len < sizeof(struct avb_vbmeta_image_header)) return;
	vbh = (const struct avb_vbmeta_image_header *)buf;

	printf("%sType:                 AVB 2.0 VBMeta Image\n", prefix);
	printf("%sAVB Version:          %u.%u\n", prefix,
	       SWAP_BE32(vbh->required_libavb_version_major), SWAP_BE32(vbh->required_libavb_version_minor));
	printf("%sRollback Index:       %llu\n", prefix, (unsigned long long)SWAP_BE64(vbh->rollback_index));
	printf("%sRelease String:       %s\n", prefix, vbh->release_string);

	{
		uint32_t flg = SWAP_BE32(vbh->flags);
		printf("%sFlags:                0x%08x%s%s\n", prefix, flg,
		       (flg & 1) ? " [HASHTREE_DISABLED (dm-verity off)]" : "",
		       (flg & 2) ? " [VERIFICATION_DISABLED (avb off)]" : "");
	}

	aux_sz = (size_t)SWAP_BE64(vbh->auxiliary_data_block_size);
	aux_base = (const uint8_t *)buf + sizeof(struct avb_vbmeta_image_header) + SWAP_BE64(vbh->authentication_data_block_size);

	if (aux_base + aux_sz <= (const uint8_t *)buf + len) {
		size_t desc_off = (size_t)SWAP_BE64(vbh->descriptors_offset);
		size_t desc_sz = (size_t)SWAP_BE64(vbh->descriptors_size);
		size_t desc_end = desc_off + desc_sz;

		if (desc_end > aux_sz) desc_end = aux_sz;
		off = desc_off;

		if (desc_sz > 0) {
			printf("%sAVB Descriptors:\n", prefix);
			while (off + sizeof(struct avb_descriptor) <= desc_end) {
				const struct avb_descriptor *d = (const struct avb_descriptor *)(aux_base + off);
				uint64_t tag = SWAP_BE64(d->tag);
				uint64_t nbf = SWAP_BE64(d->num_bytes_following);
				const uint8_t *d_data = aux_base + off + sizeof(struct avb_descriptor);

				if (off + sizeof(struct avb_descriptor) + nbf > desc_end) break;

			if (tag == AVB_DESCRIPTOR_TAG_HASH) {
				const struct avb_hash_descriptor *hd = (const struct avb_hash_descriptor *)d;
				uint32_t nlen = SWAP_BE32(hd->partition_name_len);
				uint32_t dlen = SWAP_BE32(hd->digest_len);
				uint32_t slen = SWAP_BE32(hd->salt_len);
				const char *pname = (const char *)(d_data + sizeof(*hd) - sizeof(*d));
				const uint8_t *salt = (const uint8_t *)pname + nlen;
				const uint8_t *digest = salt + slen;
				char part_name[64] = {0};
				char digest_hex[128] = {0};
				uint32_t k;

				if (nlen < sizeof(part_name)) memcpy(part_name, pname, nlen);
				for (k = 0; k < dlen && k < 32; k++) {
					sprintf(digest_hex + k * 2, "%02x", digest[k]);
				}

				printf("%s  [Hash] Partition: %-16s Algo: %-10s Size: %-10llu Digest: %s\n",
				       prefix, part_name, (const char *)hd->hash_algorithm,
				       (unsigned long long)SWAP_BE64(hd->image_size), digest_hex);
				desc_count++;
			} else if (tag == AVB_DESCRIPTOR_TAG_HASHTREE) {
				const struct avb_hashtree_descriptor *htd = (const struct avb_hashtree_descriptor *)d;
				uint32_t nlen = SWAP_BE32(htd->partition_name_len);
				uint32_t rdlen = SWAP_BE32(htd->root_digest_len);
				uint32_t slen = SWAP_BE32(htd->salt_len);
				const char *pname = (const char *)(d_data + sizeof(*htd) - sizeof(*d));
				const uint8_t *salt = (const uint8_t *)pname + nlen;
				const uint8_t *rdigest = salt + slen;
				char part_name[64] = {0};
				char rdigest_hex[128] = {0};
				uint32_t k;

				if (nlen < sizeof(part_name)) memcpy(part_name, pname, nlen);
				for (k = 0; k < rdlen && k < 32; k++) {
					sprintf(rdigest_hex + k * 2, "%02x", rdigest[k]);
				}

				printf("%s  [Hashtree] Partition: %-12s Tree: %-8llu Algo: %-8s Root Digest: %s\n",
				       prefix, part_name, (unsigned long long)SWAP_BE64(htd->tree_size),
				       (const char *)htd->hash_algorithm, rdigest_hex);
				desc_count++;
			} else if (tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION) {
				const struct avb_chain_partition_descriptor *cpd = (const struct avb_chain_partition_descriptor *)d;
				uint32_t nlen = SWAP_BE32(cpd->partition_name_len);
				const char *pname = (const char *)(d_data + sizeof(*cpd) - sizeof(*d));
				char part_name[64] = {0};
				if (nlen < sizeof(part_name)) memcpy(part_name, pname, nlen);

				printf("%s  [Chain] Partition: %-16s Rollback Index Location: %u Key Size: %u\n",
				       prefix, part_name, SWAP_BE32(cpd->rollback_index_location), SWAP_BE32(cpd->public_key_len));
				desc_count++;
			} else if (tag == AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE) {
				const struct avb_kernel_cmdline_descriptor *kcd = (const struct avb_kernel_cmdline_descriptor *)d;
				uint32_t clen = SWAP_BE32(kcd->kernel_cmdline_length);
				const char *cmd = (const char *)(d_data + sizeof(*kcd) - sizeof(*d));
				printf("%s  [Kernel Cmdline] %.*s\n", prefix, (int)clen, cmd);
				desc_count++;
			} else if (tag == AVB_DESCRIPTOR_TAG_PROPERTY) {
				const struct avb_property_descriptor *pd = (const struct avb_property_descriptor *)d;
				uint64_t klen = SWAP_BE64(pd->key_num_bytes);
				uint64_t vlen = SWAP_BE64(pd->value_num_bytes);
				const char *key = (const char *)(d_data + sizeof(*pd) - sizeof(*d));
				const char *val = key + klen + 1;
				printf("%s  [Property] %.*s=%.*s\n", prefix, (int)klen, key, (int)vlen, val);
				desc_count++;
			}

			off += sizeof(struct avb_descriptor) + nbf;
		}
		}
		if (desc_count > 0) {
			printf("%sTotal Descriptors:    %u\n", prefix, desc_count);
		}
	}
}

static void boot_img_print_info(const boot_img_t *img, const char *path) {
	uint32_t ver;
	bool is_vnd;
	bool is_init_boot = false;
	uint32_t page_sz;
	uint32_t os_ver = 0;
	char banner[256];

	if (!img || !img->hdr.raw) return;

	ver = dyn_hdr_version(&img->hdr);
	is_vnd = dyn_hdr_is_vendor(&img->hdr);
	page_sz = dyn_hdr_page_size(&img->hdr);

	if (!is_vnd && (ver == 3 || ver == 4) && img->kernel_size == 0 && img->ramdisk_size > 0) {
		is_init_boot = true;
	}

	printf("====================================================================\n");
	printf("Image:                %s\n", path);
	if (is_init_boot) {
		printf("Format:               Android Generic Ramdisk Image (init_boot.img, v%u)\n", ver);
	} else if (is_vnd) {
		printf("Format:               Android Vendor Boot Image (vendor_boot.img, v%u)\n", ver);
	} else {
		printf("Format:               Android Boot Image (v%u)\n", ver);
	}

	if (ver < 3) {
		os_ver = ((struct boot_img_hdr_v0 *)img->hdr.raw)->os_version;
	} else if (!is_vnd) {
		os_ver = ((struct boot_img_hdr_v3 *)img->hdr.raw)->os_version;
	}
	if (os_ver) {
		int a = 0, b = 0, c = 0, y = 0, m = 0;
		boot_hdr_decode_os_version(os_ver, &a, &b, &c, &y, &m);
		printf("OS Version:           %d.%d.%d\n", a, b, c);
		printf("OS Patch Level:       %d-%02d\n", y, m);
	}
	printf("Page Size:            %u bytes\n", page_sz);

	if (ver < 3) {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)img->hdr.raw;
		printf("Kernel Address:       0x%08x\n", h0->kernel_addr);
		printf("Ramdisk Address:      0x%08x\n", h0->ramdisk_addr);
		if (h0->second_size) printf("Second Address:       0x%08x\n", h0->second_addr);
		printf("Tags Address:         0x%08x\n", h0->tags_addr);
	} else if (is_vnd) {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)img->hdr.raw;
		printf("Kernel Address:       0x%08x\n", hv->kernel_addr);
		printf("Ramdisk Address:      0x%08x\n", hv->ramdisk_addr);
		printf("Tags Address:         0x%08x\n", hv->tags_addr);
		if (hv->dtb_size) printf("DTB Address:          0x%016llx\n", (unsigned long long)hv->dtb_addr);
	}

	{
		const char *name = NULL;
		if (ver < 3) name = ((struct boot_img_hdr_v0 *)img->hdr.raw)->name;
		else if (is_vnd) name = ((struct boot_img_hdr_vnd_v3 *)img->hdr.raw)->name;
		if (name && name[0]) printf("Product Name:         %s\n", name);
	}

	if (!is_vnd && img->kernel_size > 0) {
		printf("--------------------------------------------------------------------\n");
		printf("Kernel:\n");
		printf("  Size:               %u bytes (%.2f MB)\n", img->kernel_size, (double)img->kernel_size / (1024 * 1024));
		printf("  Format:             %s\n", boot_fmt2name(img->k_fmt));
		if (boot_fmt_compressed(img->k_fmt)) {
			inspect_compression_details(img->kernel, img->kernel_size, img->k_fmt, "  ");
		}
		if (img->k_fmt == BOOT_FMT_ARM64_IMAGE) {
			inspect_arm64_image(img->kernel, img->kernel_size, "  ");
		} else if (img->k_fmt == BOOT_FMT_ZIMAGE) {
			inspect_arm32_zimage(img->kernel, img->kernel_size, "  ");
		}
		if (extract_kernel_banner(img->kernel, img->kernel_size, img->k_fmt, banner, sizeof(banner))) {
			printf("  Banner:             %s\n", banner);
		}
		inspect_kernel_embedded_details(img->kernel, img->kernel_size, "  ");
	}

	if (img->kernel_dtb_size > 0 && img->kernel_dtb) {
		printf("--------------------------------------------------------------------\n");
		printf("Kernel DTB (appended):\n");
		printf("  Size:               %zu bytes\n", img->kernel_dtb_size);
		inspect_fdt_details(img->kernel_dtb, img->kernel_dtb_size, "  ");
	}

	if (img->ramdisk_size > 0 && img->ramdisk) {
		printf("--------------------------------------------------------------------\n");
		printf("Ramdisk:\n");
		printf("  Size:               %u bytes (%.2f MB)\n", img->ramdisk_size, (double)img->ramdisk_size / (1024 * 1024));
		printf("  Format:             %s\n", boot_fmt2name(img->r_fmt));
		if (boot_fmt_compressed(img->r_fmt)) {
			inspect_compression_details(img->ramdisk, img->ramdisk_size, img->r_fmt, "  ");
		}
		inspect_ramdisk_details(img->ramdisk, img->ramdisk_size, img->r_fmt, "  ");
	}

	if (img->second_size > 0) {
		printf("--------------------------------------------------------------------\n");
		printf("Second Stage:\n");
		printf("  Size:               %u bytes\n", img->second_size);
	}

	if (img->extra_size > 0) {
		printf("--------------------------------------------------------------------\n");
		printf("Extra Component:\n");
		printf("  Size:               %u bytes (%s)\n", img->extra_size, boot_fmt2name(img->e_fmt));
	}

	if (img->recovery_dtbo_size > 0 && img->recovery_dtbo) {
		printf("--------------------------------------------------------------------\n");
		printf("Recovery DTBO:\n");
		printf("  Size:               %u bytes\n", img->recovery_dtbo_size);
		if (ver == 1 || ver == 2) {
			struct boot_img_hdr_v1 *h1 = (struct boot_img_hdr_v1 *)img->hdr.raw;
			printf("  Offset:             0x%llx\n", (unsigned long long)h1->recovery_dtbo_offset);
		}
		inspect_dtbo_details(img->recovery_dtbo, img->recovery_dtbo_size, "  ");
	}

	if (img->dtb_size > 0 && img->dtb) {
		printf("--------------------------------------------------------------------\n");
		printf("DTB (Device Tree):\n");
		printf("  Size:               %u bytes\n", img->dtb_size);
		inspect_fdt_details(img->dtb, img->dtb_size, "  ");
	}

	if (img->vendor_ramdisk_table_size > 0 && img->vendor_ramdisk_table) {
		printf("--------------------------------------------------------------------\n");
		printf("Vendor Ramdisk Table (v4):\n");
		printf("  Size:               %u bytes\n", img->vendor_ramdisk_table_size);
		if (img->hdr.type == BOOT_HDR_VND_V4) {
			struct boot_img_hdr_vnd_v4 *v4 = (struct boot_img_hdr_vnd_v4 *)img->hdr.raw;
			inspect_vendor_ramdisk_table(img->vendor_ramdisk_table, img->vendor_ramdisk_table_size,
			                             v4->vendor_ramdisk_table_entry_num,
			                             v4->vendor_ramdisk_table_entry_size, "  ");
		}
	}

	if (img->bootconfig_size > 0 && img->bootconfig) {
		printf("--------------------------------------------------------------------\n");
		printf("Bootconfig:\n");
		printf("  Size:               %u bytes\n", img->bootconfig_size);
		print_bootconfig_preview(img->bootconfig, img->bootconfig_size, "  ");
	}

	if (img->signature_size > 0) {
		printf("--------------------------------------------------------------------\n");
		printf("Boot Signature (v4):  %u bytes\n", img->signature_size);
	}

	{
		const char *cmd = NULL;
		const char *extra = NULL;
		if (ver < 3) {
			struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)img->hdr.raw;
			cmd = h0->cmdline;
			extra = h0->extra_cmdline;
		} else if (is_vnd) {
			cmd = ((struct boot_img_hdr_vnd_v3 *)img->hdr.raw)->cmdline;
		} else {
			cmd = ((struct boot_img_hdr_v3 *)img->hdr.raw)->cmdline;
		}
		if ((cmd && cmd[0]) || (extra && extra[0])) {
			printf("--------------------------------------------------------------------\n");
			printf("Command Line:\n");
			if (cmd && cmd[0]) printf("  cmdline:            %s\n", cmd);
			if (extra && extra[0]) printf("  extra_cmdline:      %s\n", extra);
		}
	}

	if (img->flags & BOOT_FLAG_AVB) {
		printf("--------------------------------------------------------------------\n");
		printf("AVB 2.0:\n");
		printf("  Footer:             PRESENT\n");
		if (img->avb_footer) {
			printf("  Original Image Sz:  %llu bytes (%.2f MB)\n",
			       (unsigned long long)img->avb_footer->original_image_size,
			       (double)img->avb_footer->original_image_size / (1024 * 1024));
			printf("  VBMeta Offset:      0x%llx (%llu)\n",
			       (unsigned long long)img->avb_footer->vbmeta_offset,
			       (unsigned long long)img->avb_footer->vbmeta_offset);
			printf("  VBMeta Size:        %llu bytes\n", (unsigned long long)img->avb_footer->vbmeta_size);
			if (img->map_ptr && img->avb_footer->vbmeta_offset < img->map_sz &&
			    img->avb_footer->vbmeta_offset + img->avb_footer->vbmeta_size <= img->map_sz) {
				const void *vb_ptr = (const uint8_t *)img->map_ptr + img->avb_footer->vbmeta_offset;
				if (memcmp(vb_ptr, "AVB0", 4) == 0) {
					inspect_avb_vbmeta_details(vb_ptr, (size_t)img->avb_footer->vbmeta_size, "  ");
				}
			}
		}
	}
	printf("====================================================================\n");
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

static bool boot_img_parse_full(boot_img_t *img, const char *path, bool silent) {
	int fd;
	struct stat st;
	off_t real_sz;
	const uint8_t *start;
	const uint8_t *end;
	const uint8_t *hdr_ptr = NULL;
	const uint8_t *addr;
	const uint8_t *scan_limit;
	uint32_t page_sz;
	size_t off;

	memset(img, 0, sizeof(*img));

	fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return false;

	if (fstat(fd, &st) < 0) {
		if (!silent) bb_perror_msg("cannot stat '%s'", path);
		close(fd);
		return false;
	}

	real_sz = get_file_or_bdev_size(fd, &st);
	if (real_sz < 1024) {
		if (!silent) bb_error_msg("file '%s' is too small or invalid (%lld bytes)", path, (long long)real_sz);
		close(fd);
		return false;
	}

	img->map_sz = (size_t)real_sz;
	img->map_ptr = map_or_read_image(fd, img->map_sz, false);
	close(fd);

	if (img->map_ptr == MAP_FAILED || !img->map_ptr) {
		if (!silent) bb_perror_msg("mmap failed for '%s'", path);
		return false;
	}

	start = (const uint8_t *)img->map_ptr;
	end = start + img->map_sz;

	scan_limit = start + 131072;
	if (scan_limit > end) scan_limit = end;

	for (addr = start; addr + sizeof(struct boot_img_hdr_v0) <= scan_limit; ++addr) {
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
		if (!silent) bb_error_msg("no valid boot image header found in '%s'", path);
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
	if (page_sz < 2048 || page_sz > 65536 || (page_sz & (page_sz - 1)) != 0) {
		if (!silent) bb_error_msg("invalid boot page size (%u)", page_sz);
		free(img->hdr.raw);
		img->hdr.raw = NULL;
		munmap(img->map_ptr, img->map_sz);
		return false;
	}
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

	if (img->hdr.type == BOOT_HDR_VND_V4) {
		struct boot_img_hdr_vnd_v4 *v4 = (struct boot_img_hdr_vnd_v4 *)img->hdr.raw;
		img->vendor_ramdisk_table_size = v4->vendor_ramdisk_table_size;
		if (img->vendor_ramdisk_table_size > 0 && hdr_ptr + off + img->vendor_ramdisk_table_size <= end) {
			img->vendor_ramdisk_table = hdr_ptr + off;
			off += align_to(img->vendor_ramdisk_table_size, page_sz);
		}
	}

	img->bootconfig_size = *dyn_hdr_bootconfig_size(&img->hdr);
	if (img->bootconfig_size > 0 && hdr_ptr + off + img->bootconfig_size <= end) {
		img->bootconfig = hdr_ptr + off;
		off += align_to(img->bootconfig_size, page_sz);
	}

	if (img->hdr.type == BOOT_HDR_V4) {
		struct boot_img_hdr_v4 *b4 = (struct boot_img_hdr_v4 *)img->hdr.raw;
		img->signature_size = b4->signature_size;
		if (img->signature_size > 0 && hdr_ptr + off + img->signature_size <= end) {
			img->signature = hdr_ptr + off;
			off += align_to(img->signature_size, 4096);
		}
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

static inline bool boot_img_parse(boot_img_t *img, const char *path) {
	return boot_img_parse_full(img, path, false);
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

static int magiskboot_info_image(const char *path);

static int magiskboot_unpack(const char *image, bool skip_kernel_decomp, bool skip_ramdisk_decomp, bool hdr_only, bool kernel_only) {
	boot_img_t boot;
	if (!boot_img_parse(&boot, image)) {
		if (hdr_only) return magiskboot_info_image(image);
		return 1;
	}

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
	if (boot.vendor_ramdisk_table && boot.vendor_ramdisk_table_size > 0) {
		write_to_disk("vendor_ramdisk_table", boot.vendor_ramdisk_table, boot.vendor_ramdisk_table_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.bootconfig && boot.bootconfig_size > 0) {
		write_to_disk(BOOTCONFIG_FILE, boot.bootconfig, boot.bootconfig_size, BOOT_FMT_UNKNOWN, true);
	}
	if (boot.signature && boot.signature_size > 0) {
		write_to_disk("boot_signature", boot.signature, boot.signature_size, BOOT_FMT_UNKNOWN, true);
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
	} else if (fmt == BOOT_FMT_ZSTD) {
		prog = "zstd";
		arg = "-19c";
	}

	out_tfd = open3_or_warn(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_tfd < 0) return -1;

	pid = fork();
	if (pid == 0) {
		char *args[4];
		if (out_tfd != STDOUT_FILENO) {
			dup2(out_tfd, STDOUT_FILENO);
			close(out_tfd);
		}
		args[0] = (char *)prog;
		args[1] = (char *)arg;
		args[2] = (char *)src;
		args[3] = NULL;
#ifndef BUILD_INDIVIDUAL
		{
			int applet = find_applet_by_name(prog);
			if (applet >= 0) {
				run_applet_no_and_exit(applet, prog, args);
			}
		}
#endif
		BB_EXECVP(prog, args);
		_exit(127);
	}
	if (out_tfd != STDOUT_FILENO)
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
	if (access("ramdisk.cpio.zst", R_OK) == 0) return "ramdisk.cpio.zst";

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
	if (boot.hdr.type == BOOT_HDR_VND_V4 && access("vendor_ramdisk_table", R_OK) == 0) {
		uint32_t table_sz = 0;
		copy_file_section(out_fd, "vendor_ramdisk_table", page_sz, &table_sz);
		((struct boot_img_hdr_vnd_v4 *)boot.hdr.raw)->vendor_ramdisk_table_size = table_sz;
	}
	if (access(BOOTCONFIG_FILE, R_OK) == 0) {
		copy_file_section(out_fd, BOOTCONFIG_FILE, page_sz, &bootconfig_sz);
		*dyn_hdr_bootconfig_size(&boot.hdr) = bootconfig_sz;
	}
	if (boot.hdr.type == BOOT_HDR_V4 && access("boot_signature", R_OK) == 0) {
		uint32_t sig_sz = 0;
		copy_file_section(out_fd, "boot_signature", 4096, &sig_sz);
		((struct boot_img_hdr_v4 *)boot.hdr.raw)->signature_size = sig_sz;
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
		"vendor_ramdisk_table\0"
		"signature\0"
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
		COMP_vendor_ramdisk_table,
		COMP_signature,
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
	case COMP_vendor_ramdisk_table:
		data = boot.vendor_ramdisk_table;
		sz = boot.vendor_ramdisk_table_size;
		dest = outfile ? outfile : "vendor_ramdisk_table";
		break;
	case COMP_signature:
		data = boot.signature;
		sz = boot.signature_size;
		dest = outfile ? outfile : "boot_signature";
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

static void cpio_add_dir_entries(cpio_node_t ***tail_ptr, const char *base_path, const char *rel_path) {
	DIR *dir;
	struct dirent *de;
	char full_path[PATH_MAX * 2];

	if (rel_path && rel_path[0]) {
		snprintf(full_path, sizeof(full_path), "%s/%s", base_path, rel_path);
	} else {
		safe_strncpy(full_path, base_path, sizeof(full_path));
	}

	dir = opendir(full_path);
	if (!dir) return;

	while ((de = readdir(dir)) != NULL) {
		char entry_rel[PATH_MAX];
		char entry_full[PATH_MAX * 2];
		struct stat st;
		cpio_node_t *node;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

		if (rel_path && rel_path[0]) {
			snprintf(entry_rel, sizeof(entry_rel), "%s/%s", rel_path, de->d_name);
		} else {
			safe_strncpy(entry_rel, de->d_name, sizeof(entry_rel));
		}
		snprintf(entry_full, sizeof(entry_full), "%s/%s", base_path, entry_rel);

		if (lstat(entry_full, &st) != 0) continue;

		node = xzalloc(sizeof(*node));
		node->name = xstrdup(entry_rel);
		node->mode = st.st_mode;
		node->uid = st.st_uid;
		node->gid = st.st_gid;
		node->nlink = st.st_nlink;
		node->mtime = st.st_mtime;

		if (S_ISDIR(st.st_mode)) {
			node->filesize = 0;
			node->data = NULL;
			**tail_ptr = node;
			*tail_ptr = &node->next;
			cpio_add_dir_entries(tail_ptr, base_path, entry_rel);
		} else if (S_ISLNK(st.st_mode)) {
			char link_target[PATH_MAX];
			ssize_t llen = readlink(entry_full, link_target, sizeof(link_target) - 1);
			if (llen > 0) {
				link_target[llen] = '\0';
				node->data = xstrdup(link_target);
				node->filesize = (uint32_t)llen;
			}
			**tail_ptr = node;
			*tail_ptr = &node->next;
		} else if (S_ISREG(st.st_mode)) {
			size_t sz = 0;
			node->data = magiskboot_read_file(entry_full, &sz);
			node->filesize = (uint32_t)sz;
			**tail_ptr = node;
			*tail_ptr = &node->next;
		} else {
			free(node->name);
			free(node);
		}
	}
	closedir(dir);
}

static int cpio_pack_from_dir(const char *dir_path, const char *out_cpio) {
	cpio_node_t *head = NULL;
	cpio_node_t **tail = &head;
	int ret;

	cpio_add_dir_entries(&tail, dir_path, "");
	if (!head) {
		bb_error_msg("directory '%s' is empty or could not be read", dir_path);
		return -1;
	}
	ret = cpio_write_all(out_cpio, head);
	cpio_free_all(head);
	return ret;
}

static int cpio_exec_cmd(cpio_node_t **head_ptr, int argc, char **argv, bool *modified) {
	static const char cpio_acts[] ALIGN1 =
		"mkdir\0"
		"add\0"
		"ln\0"
		"rm\0"
		"extract\0"
		"ls\0"
		"cat\0"
		"chmod\0"
		"chown\0"
		"mv\0"
		"rename\0"
		"stat\0"
		"exists\0"
		"repack\0";
	enum {
		CPIO_ACT_mkdir = 0,
		CPIO_ACT_add,
		CPIO_ACT_ln,
		CPIO_ACT_rm,
		CPIO_ACT_extract,
		CPIO_ACT_ls,
		CPIO_ACT_cat,
		CPIO_ACT_chmod,
		CPIO_ACT_chown,
		CPIO_ACT_mv,
		CPIO_ACT_rename,
		CPIO_ACT_stat,
		CPIO_ACT_exists,
		CPIO_ACT_repack,
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

	case CPIO_ACT_cat: {
		const char *entry_name;
		cpio_node_t *curr;
		bool found = false;
		if (argc < 2) return 1;
		entry_name = argv[1];
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				if (curr->data && curr->filesize > 0) {
					full_write(STDOUT_FILENO, curr->data, curr->filesize);
				}
				found = true;
				break;
			}
		}
		if (!found) bb_error_msg("entry '%s' not found in cpio", entry_name);
		return 2;
	}

	case CPIO_ACT_chmod: {
		uint32_t mode;
		const char *entry_name;
		cpio_node_t *curr;
		bool found = false;
		if (argc < 3) return 1;
		mode = bb_strtou(argv[1], NULL, 8);
		entry_name = argv[2];
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				curr->mode = (curr->mode & ~07777) | (mode & 07777);
				*modified = true;
				found = true;
				break;
			}
		}
		if (!found) bb_error_msg("entry '%s' not found in cpio", entry_name);
		return 3;
	}

	case CPIO_ACT_chown: {
		const char *ug_str;
		const char *entry_name;
		uint32_t uid = 0, gid = 0;
		char *colon;
		cpio_node_t *curr;
		bool found = false;
		if (argc < 3) return 1;
		ug_str = argv[1];
		entry_name = argv[2];
		uid = bb_strtou(ug_str, &colon, 10);
		if (colon && *colon == ':') {
			gid = bb_strtou(colon + 1, NULL, 10);
		}
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				curr->uid = uid;
				curr->gid = gid;
				*modified = true;
				found = true;
				break;
			}
		}
		if (!found) bb_error_msg("entry '%s' not found in cpio", entry_name);
		return 3;
	}

	case CPIO_ACT_mv:
	case CPIO_ACT_rename: {
		const char *from;
		const char *to;
		cpio_node_t *curr;
		bool found = false;
		if (argc < 3) return 1;
		from = argv[1];
		to = argv[2];
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, from) == 0) {
				free(curr->name);
				curr->name = xstrdup(to);
				*modified = true;
				found = true;
				break;
			}
		}
		if (!found) bb_error_msg("entry '%s' not found in cpio", from);
		return 3;
	}

	case CPIO_ACT_stat: {
		const char *entry_name;
		cpio_node_t *curr;
		bool found = false;
		if (argc < 2) return 1;
		entry_name = argv[1];
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				const char *type_str = S_ISDIR(curr->mode) ? "Directory" : S_ISLNK(curr->mode) ? "Symbolic Link" : "Regular File";
				printf("  Entry:     %s\n", curr->name);
				printf("  Type:      %s\n", type_str);
				printf("  Mode:      0%o\n", curr->mode & 07777);
				printf("  Size:      %u bytes\n", curr->filesize);
				printf("  UID/GID:   %u / %u\n", curr->uid, curr->gid);
				printf("  Links:     %u\n", curr->nlink);
				if (S_ISLNK(curr->mode) && curr->data) {
					printf("  Target:    %.*s\n", curr->filesize, (char *)curr->data);
				}
				found = true;
				break;
			}
		}
		if (!found) bb_error_msg("entry '%s' not found in cpio", entry_name);
		return 2;
	}

	case CPIO_ACT_exists: {
		const char *entry_name;
		cpio_node_t *curr;
		if (argc < 2) return 1;
		entry_name = argv[1];
		for (curr = *head_ptr; curr; curr = curr->next) {
			if (strcmp(curr->name, entry_name) == 0) {
				return 2;
			}
		}
		return -1;
	}

	case CPIO_ACT_repack: {
		const char *out_cpio;
		if (argc < 2) return 1;
		out_cpio = argv[1];
		cpio_write_all(out_cpio, *head_ptr);
		printf("Repacked cpio to '%s'\n", out_cpio);
		return 2;
	}

	default:
		bb_error_msg("unknown cpio action '%s' (supported: test, ls, cat, extract, mkdir, add, ln, rm, chmod, chown, mv, stat, exists, repack)", act);
		return 1;
	}
}

static int boot_img_write_repacked_with_ramdisk(boot_img_t *boot, const char *new_rd, const char *final_target) {
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

	if (!boot || !new_rd || !final_target) return 1;

	snprintf(tmp_out_boot, sizeof(tmp_out_boot), "%s.tmp.%d", final_target, (int)getpid());
	out_fd = open3_or_warn(tmp_out_boot, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0) return 1;

	page_sz = dyn_hdr_page_size(&boot->hdr);
	hdr_pad = align_to(boot->hdr.raw_sz, page_sz);
	lseek(out_fd, hdr_pad, SEEK_SET);

	/* 1. Write kernel section */
	if (!dyn_hdr_is_vendor(&boot->hdr) && boot->kernel && boot->kernel_size > 0) {
		size_t rem;
		kernel_sz = (uint32_t)boot->kernel_size;
		full_write(out_fd, boot->kernel, kernel_sz);
		if (boot->kernel_dtb && boot->kernel_dtb_size > 0) {
			full_write(out_fd, boot->kernel_dtb, boot->kernel_dtb_size);
			kernel_sz += (uint32_t)boot->kernel_dtb_size;
		}
		rem = kernel_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
		*dyn_hdr_kernel_size(&boot->hdr) = kernel_sz;
	}

	/* 2. Write new ramdisk */
	copy_file_section(out_fd, new_rd, page_sz, &ramdisk_sz);
	*dyn_hdr_ramdisk_size(&boot->hdr) = ramdisk_sz;

	/* 3. Write remaining sections */
	second_sz = (uint32_t)boot->second_size;
	if (boot->second && second_sz > 0) {
		size_t rem;
		full_write(out_fd, boot->second, second_sz);
		rem = second_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
	}

	extra_sz = (uint32_t)boot->extra_size;
	if (boot->extra && extra_sz > 0) {
		size_t rem;
		full_write(out_fd, boot->extra, extra_sz);
		rem = extra_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
	}

	recov_dtbo_sz = (uint32_t)boot->recovery_dtbo_size;
	if (boot->recovery_dtbo && recov_dtbo_sz > 0) {
		size_t rem;
		full_write(out_fd, boot->recovery_dtbo, recov_dtbo_sz);
		rem = recov_dtbo_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
	}

	dtb_sz = (uint32_t)boot->dtb_size;
	if (boot->dtb && dtb_sz > 0) {
		size_t rem;
		full_write(out_fd, boot->dtb, dtb_sz);
		rem = dtb_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
	}

	bootconfig_sz = (uint32_t)boot->bootconfig_size;
	if (boot->bootconfig && bootconfig_sz > 0) {
		size_t rem;
		full_write(out_fd, boot->bootconfig, bootconfig_sz);
		rem = bootconfig_sz % page_sz;
		if (rem > 0) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, page_sz - rem);
		}
	}

	/* 4. Recalculate SHA ID */
	dyn_hdr_recalc_id(&boot->hdr, out_fd, hdr_pad, page_sz,
	                  kernel_sz, ramdisk_sz, second_sz, extra_sz,
	                  recov_dtbo_sz, dtb_sz);

	/* 5. Handle AVB footer */
	if ((boot->flags & BOOT_FLAG_AVB) && boot->avb_footer) {
		uint64_t orig_vbmeta_off = SWAP_BE64(boot->avb_footer->vbmeta_offset);
		uint64_t orig_vbmeta_sz = SWAP_BE64(boot->avb_footer->vbmeta_size);
		if (orig_vbmeta_sz > 0 && orig_vbmeta_off + orig_vbmeta_sz <= boot->map_sz) {
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
			full_write(out_fd, (const uint8_t *)boot->map_ptr + orig_vbmeta_off, orig_vbmeta_sz);
			rem = (size_t)orig_vbmeta_sz % 4096;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, 4096 - rem);
			}
			memcpy(&new_footer, boot->avb_footer, sizeof(new_footer));
			new_footer.original_image_size = SWAP_BE64((uint64_t)aosp_img_size);
			new_footer.vbmeta_offset = SWAP_BE64((uint64_t)new_vbmeta_off);
			new_footer.vbmeta_size = boot->avb_footer->vbmeta_size;
			full_write(out_fd, &new_footer, sizeof(new_footer));
		}
	}

	/* 6. Write finalized header at offset 0 */
	lseek(out_fd, 0, SEEK_SET);
	full_write(out_fd, boot->hdr.raw, boot->hdr.raw_sz);

	if (hdr_pad > boot->hdr.raw_sz) {
		static const uint8_t zeros[4096] = {0};
		full_write(out_fd, zeros, hdr_pad - boot->hdr.raw_sz);
	}

	close(out_fd);

	if (rename(tmp_out_boot, final_target) != 0) {
		if (copy_file(tmp_out_boot, final_target, FILEUTILS_FORCE) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}
		unlink(tmp_out_boot);
	}

	return 0;
}

static int magiskboot_cpio(int argc, char **argv) {
	const char *target_file;
	cpio_node_t *head = NULL;
	bool modified = false;
	int i;
	int ret = 0;
	uint8_t fmt = BOOT_FMT_UNKNOWN;
	int fd;
	char tmp_decomp[PATH_MAX];
	bool is_boot_img = false;
	boot_img_t boot;

	tmp_decomp[0] = '\0';
	if (argc < 4) bb_show_usage();
	target_file = argv[2];

	/* Fast-path test command */
	if (strcmp(argv[3], "test") == 0 && argc == 4) {
		char magic[8];
		ssize_t n;
		fd = open_or_warn(target_file, O_RDONLY | O_CLOEXEC);
		if (fd < 0) return 1;
		n = full_read(fd, magic, 8);
		close(fd);
		if (n >= 6 && (memcmp(magic, "070701", 6) == 0 || memcmp(magic, "070702", 6) == 0)) {
			printf("0\n");
			return 0;
		}
		if (n >= 8 && (memcmp(magic, "ANDROID!", 8) == 0 || memcmp(magic, "VNDRBOOT", 8) == 0)) {
			printf("0\n");
			return 0;
		}
		return 1;
	}

	/* Probe format of target_file */
	fd = open_or_warn(target_file, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		uint8_t probe_hdr[4096];
		ssize_t pn = full_read(fd, probe_hdr, sizeof(probe_hdr));
		close(fd);
		if (pn > 0) fmt = boot_check_fmt(probe_hdr, (size_t)pn);
	}

	if (fmt == BOOT_FMT_AOSP || fmt == BOOT_FMT_AOSP_VENDOR) {
		int tfd;
		is_boot_img = true;
		if (!boot_img_parse_full(&boot, target_file, false)) return 1;
		if (!boot.ramdisk || boot.ramdisk_size == 0) {
			bb_error_msg("no ramdisk found in boot image '%s'", target_file);
			boot_img_free(&boot);
			return 1;
		}
		safe_strncpy(tmp_decomp, "/tmp/mb_cpiord_XXXXXX", sizeof(tmp_decomp));
		tfd = mkstemp(tmp_decomp);
		if (tfd < 0) {
			boot_img_free(&boot);
			return 1;
		}
		if (boot_fmt_compressed(boot.r_fmt)) {
			bb_decompress_data(boot.r_fmt, boot.ramdisk, boot.ramdisk_size, tfd);
		} else {
			full_write(tfd, boot.ramdisk, boot.ramdisk_size);
		}
		close(tfd);
		head = cpio_read_all(tmp_decomp);
	} else if (boot_fmt_compressed(fmt)) {
		void *cbuf;
		size_t csz = 0;
		int tfd;
		cbuf = magiskboot_read_file(target_file, &csz);
		if (!cbuf) return 1;
		safe_strncpy(tmp_decomp, "/tmp/mb_decomp_XXXXXX", sizeof(tmp_decomp));
		tfd = mkstemp(tmp_decomp);
		if (tfd < 0) { free(cbuf); return 1; }
		bb_decompress_data(fmt, cbuf, csz, tfd);
		close(tfd);
		free(cbuf);
		head = cpio_read_all(tmp_decomp);
	} else {
		head = cpio_read_all(target_file);
	}

	if (!head) {
		bb_error_msg("failed to parse CPIO archive '%s'", target_file);
		if (tmp_decomp[0]) unlink(tmp_decomp);
		if (is_boot_img) boot_img_free(&boot);
		return 1;
	}

	i = 3;
	while (i < argc) {
		const char *arg = argv[i];
		if (strchr(arg, ' ')) {
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
			int consumed = cpio_exec_cmd(&head, argc - i, &argv[i], &modified);
			if (consumed < 0) {
				ret = 1;
				break;
			}
			i += (consumed > 0) ? consumed : 1;
		}
	}

	if (modified) {
		if (is_boot_img) {
			char tmp_new_cpio[PATH_MAX];
			char tmp_new_rd[PATH_MAX];

			safe_strncpy(tmp_new_cpio, "/tmp/mb_newcpio_XXXXXX", sizeof(tmp_new_cpio));
			close(xmkstemp(tmp_new_cpio));
			cpio_write_all(tmp_new_cpio, head);

			if (boot_fmt_compressed(boot.r_fmt)) {
				safe_strncpy(tmp_new_rd, "/tmp/mb_newrd_XXXXXX", sizeof(tmp_new_rd));
				close(xmkstemp(tmp_new_rd));
				compress_file_format(tmp_new_cpio, tmp_new_rd, boot.r_fmt);
				unlink(tmp_new_cpio);
			} else {
				safe_strncpy(tmp_new_rd, tmp_new_cpio, sizeof(tmp_new_rd));
			}

			if (boot_img_write_repacked_with_ramdisk(&boot, tmp_new_rd, target_file) != 0) {
				bb_error_msg("failed to update boot image '%s'", target_file);
				ret = 1;
			} else {
				printf("Successfully updated ramdisk inside '%s'\n", target_file);
			}
			unlink(tmp_new_rd);
		} else if (boot_fmt_compressed(fmt)) {
			cpio_write_all(tmp_decomp, head);
			compress_file_format(tmp_decomp, target_file, fmt);
			printf("Updated compressed ramdisk '%s'\n", target_file);
		} else {
			ret = cpio_write_all(target_file, head);
		}
	}

	if (tmp_decomp[0]) unlink(tmp_decomp);
	if (is_boot_img) boot_img_free(&boot);
	cpio_free_all(head);
	return ret;
}

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

/* =========================================================================
 * 7. Device Tree Blob (DTB) Manipulation Engine
 * ========================================================================= */

#define FDT_TAG_BEGIN_NODE  0x00000001U
#define FDT_TAG_END_NODE    0x00000002U
#define FDT_TAG_PROP        0x00000003U
#define FDT_TAG_NOP         0x00000004U
#define FDT_TAG_END         0x00000009U

static size_t fdt_match_verity_pattern(const char *buf, size_t remaining)
{
	static const char *const patterns[] = {
		"verifyatboot",
		"verify",
		"avb_keys",
		"avb",
		"support_scfs",
		"fsverity",
		NULL
	};
	size_t prefix_len = 0;
	size_t i;

	if (remaining == 0) return 0;
	if (buf[0] == ',') prefix_len = 1;

	for (i = 0; patterns[i]; i++) {
		size_t plen = strlen(patterns[i]);
		if (remaining >= prefix_len + plen &&
		    strncmp(buf + prefix_len, patterns[i], plen) == 0) {
			size_t match_len = prefix_len + plen;
			/* If followed by '=...', consume until delimiter */
			if (match_len < remaining && buf[match_len] == '=') {
				while (match_len < remaining) {
					char c = buf[match_len];
					if (c == ' ' || c == '\n' || c == ',' || c == '\0')
						break;
					match_len++;
				}
			}
			return match_len;
		}
	}
	return 0;
}

static bool fdt_strip_verity(char *buf, size_t len)
{
	size_t read_idx = 0;
	size_t write_idx = 0;
	bool modified = false;

	while (read_idx < len && buf[read_idx] != '\0') {
		size_t match_len = fdt_match_verity_pattern(buf + read_idx, len - read_idx);
		if (match_len > 0) {
			read_idx += match_len;
			modified = true;
		} else {
			buf[write_idx++] = buf[read_idx++];
		}
	}

	if (modified) {
		if (write_idx > 0 && buf[0] == ',') {
			memmove(buf, buf + 1, write_idx - 1);
			write_idx--;
		}
		if (write_idx > 0 && buf[write_idx - 1] == ',') {
			write_idx--;
		}
		memset(buf + write_idx, 0, len - write_idx);
	}
	return modified;
}

/*
 * Traverses an individual FDT tree.
 * action: 0 = test, 1 = print (all), 2 = print fstab only, 3 = patch
 */
static int fdt_process_single(uint8_t *dtb, size_t dtb_len, int action, int dtb_num,
                              bool keep_verity, bool *has_system_root, int *patch_count)
{
	const struct fdt_header *fdt;
	uint32_t totalsize, off_struct, off_strings;
	const uint32_t *p, *end;
	const char *strings;
	size_t strings_sz;
	int depth = 0;
	bool in_fstab = false;
	int fstab_depth = -1;
	bool in_chosen = false;
	int chosen_depth = -1;
	char cur_node_name[128];

	cur_node_name[0] = '\0';

	if (dtb_len < sizeof(struct fdt_header)) return 0;
	fdt = (const struct fdt_header *)dtb;
	if (SWAP_BE32(fdt->magic) != FDT_MAGIC) return 0;

	totalsize = SWAP_BE32(fdt->totalsize);
	off_struct = SWAP_BE32(fdt->off_dt_struct);
	off_strings = SWAP_BE32(fdt->off_dt_strings);

	if (totalsize > dtb_len || off_struct >= totalsize || off_strings >= totalsize)
		return 0;

	p = (const uint32_t *)(dtb + off_struct);
	end = (const uint32_t *)(dtb + totalsize);
	strings = (const char *)(dtb + off_strings);
	strings_sz = totalsize - off_strings;

	if (action == 1) {
		printf("=== dtb.%04d (size: %u bytes, ver: %u) ===\n",
		       dtb_num, totalsize, SWAP_BE32(fdt->version));
	}

	while (p < end) {
		uint32_t tag = SWAP_BE32(*p++);

		if (tag == FDT_TAG_BEGIN_NODE) {
			const char *name = (const char *)p;
			size_t nlen = strlen(name) + 1;
			p += (nlen + 3) / 4;

			if (depth < 64) {
				safe_strncpy(cur_node_name, name, sizeof(cur_node_name));
			}

			if (strcmp(name, "fstab") == 0) {
				in_fstab = true;
				fstab_depth = depth;
				if (action == 2) {
					printf("Found fstab in dtb.%04d:\n", dtb_num);
				}
			}
			if (strcmp(name, "chosen") == 0) {
				in_chosen = true;
				chosen_depth = depth;
			}

			if (action == 1 || (action == 2 && in_fstab)) {
				printf("%*s%s {\n", depth * 2, "", name[0] ? name : "/");
			}
			depth++;
		} else if (tag == FDT_TAG_END_NODE) {
			depth--;
			if (depth == fstab_depth) {
				in_fstab = false;
				fstab_depth = -1;
			}
			if (depth == chosen_depth) {
				in_chosen = false;
				chosen_depth = -1;
			}
			if (action == 1 || (action == 2 && (in_fstab || depth == fstab_depth))) {
				printf("%*s};\n", depth * 2, "");
			}
		} else if (tag == FDT_TAG_PROP) {
			uint32_t plen = SWAP_BE32(*p++);
			uint32_t nameoff = SWAP_BE32(*p++);
			uint8_t *prop_data = (uint8_t *)p;
			const char *prop_name = (nameoff < strings_sz) ? (strings + nameoff) : "";
			p += (plen + 3) / 4;

			/* Action 0: Test (detect system_root mount point) */
			if (action == 0 && in_fstab && strcmp(cur_node_name, "system") == 0) {
				if (strcmp(prop_name, "mnt_point") == 0 && plen > 0) {
					if (strcmp((const char *)prop_data, "/system_root") == 0) {
						if (has_system_root) *has_system_root = true;
					}
				}
			}

			/* Action 1 & 2: Print */
			if (action == 1 || (action == 2 && in_fstab)) {
				bool is_str = (plen > 1 && prop_data[plen - 1] == '\0');
				if (is_str) {
					size_t k;
					for (k = 0; k < plen - 1; k++) {
						if (prop_data[k] < 32 || prop_data[k] > 126) {
							is_str = false;
							break;
						}
					}
				}
				if (is_str) {
					printf("%*s%s = \"%s\";\n", (depth + 1) * 2, "", prop_name, (const char *)prop_data);
				} else if (plen == 4) {
					printf("%*s%s = <0x%08x>;\n", (depth + 1) * 2, "", prop_name, SWAP_BE32(*(const uint32_t *)prop_data));
				} else {
					printf("%*s%s = [%u bytes];\n", (depth + 1) * 2, "", prop_name, plen);
				}
			}

			/* Action 3: Patch */
			if (action == 3) {
				/* 1. In /chosen, patch skip_initramfs -> want_initramfs */
				if (in_chosen && strcmp(prop_name, "bootargs") == 0 && plen >= 14) {
					char *cmdline = (char *)prop_data;
					size_t ci;
					for (ci = 0; ci + 14 <= plen; ci++) {
						if (memcmp(cmdline + ci, "skip_initramfs", 14) == 0) {
							memcpy(cmdline + ci, "want_initramfs", 14);
							printf("  [+] dtb.%04d: Patched [skip_initramfs] -> [want_initramfs]\n", dtb_num);
							if (patch_count) (*patch_count)++;
						}
					}
				}

				/* 2. In /fstab child nodes, strip verity/avb flags */
				if (in_fstab && !keep_verity && strcmp(prop_name, "fsmgr_flags") == 0 && plen > 0) {
					if (fdt_strip_verity((char *)prop_data, plen)) {
						printf("  [+] dtb.%04d: Stripped verity/avb from node '%s'\n", dtb_num, cur_node_name);
						if (patch_count) (*patch_count)++;
					}
				}
			}
		} else if (tag == FDT_TAG_NOP) {
			/* NOP token: do nothing */
		} else if (tag == FDT_TAG_END) {
			break;
		} else {
			/* Unknown or corrupt token */
			break;
		}
	}
	return (int)totalsize;
}

static int magiskboot_dtb(int argc, char **argv)
{
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
	int act_idx;
	bool fstab_only = false;
	bool keep_verity = false;
	size_t cur = 0;
	int dtb_num = 0;
	int patch_count = 0;
	bool has_system_root = false;

	if (argc < 3) bb_show_usage();
	dtb_file = argv[2];
	action = (argc >= 4) ? argv[3] : "test";

	if (argc >= 5 && strcmp(argv[4], "-f") == 0) {
		fstab_only = true;
	}

	act_idx = index_in_strings(dtb_acts, action);
	if (act_idx < 0) {
		bb_error_msg("unknown dtb action '%s' (supported: test, print [-f], patch)", action);
		return 1;
	}

	fd = open_or_warn(dtb_file, (act_idx == DTB_ACT_patch) ? (O_RDWR | O_CLOEXEC) : (O_RDONLY | O_CLOEXEC));
	if (fd < 0) return 1;
	if (fstat(fd, &st) < 0 || st.st_size < 16) {
		close(fd);
		return 1;
	}

	p = mmap(NULL, st.st_size, (act_idx == DTB_ACT_patch) ? (PROT_READ | PROT_WRITE) : PROT_READ,
	         (act_idx == DTB_ACT_patch) ? MAP_SHARED : MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED || !p) {
		close(fd);
		return 1;
	}

	if (getenv("KEEPVERITY") && (strcmp(getenv("KEEPVERITY"), "true") == 0 || strcmp(getenv("KEEPVERITY"), "1") == 0)) {
		keep_verity = true;
	}

	while (cur + sizeof(struct fdt_header) <= (size_t)st.st_size) {
		uint32_t magic = SWAP_BE32(*(const uint32_t *)(p + cur));
		if (magic != FDT_MAGIC) {
			cur += 4;
			continue;
		}
		{
			const struct fdt_header *hdr = (const struct fdt_header *)(p + cur);
			uint32_t tsize = SWAP_BE32(hdr->totalsize);
			int action_code;

			if (tsize < 132 || cur + tsize > (size_t)st.st_size) {
				cur += 4;
				continue;
			}
			action_code = (act_idx == DTB_ACT_test) ? 0 :
			              (act_idx == DTB_ACT_print || act_idx == DTB_ACT_dump) ? (fstab_only ? 2 : 1) : 3;

			fdt_process_single(p + cur, tsize, action_code, dtb_num, keep_verity, &has_system_root, &patch_count);
			cur += tsize;
			dtb_num++;
		}
	}

	if (dtb_num == 0) {
		printf("[-] No valid DTB ('\\xd0\\x0d\\xfe\\xed') found in '%s'\n", dtb_file);
	} else if (act_idx == DTB_ACT_patch) {
		msync(p, st.st_size, MS_SYNC);
		printf("[✓] DTB patch complete: %d patches applied across %d DTB(s)\n", patch_count, dtb_num);
	} else if (act_idx == DTB_ACT_test) {
		printf("[✓] DTB test: %d DTB(s) scanned, system_root=%s\n", dtb_num, has_system_root ? "true [2SI]" : "false");
	}

	munmap(p, st.st_size);
	close(fd);

	if (act_idx == DTB_ACT_test && has_system_root) {
		return 1;
	}
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

		if (boot_img_write_repacked_with_ramdisk(&boot, tmp_new_rd, final_target) != 0) {
			unlink(tmp_new_rd);
			boot_img_free(&boot);
			return 1;
		}
		unlink(tmp_new_rd);
		boot_img_free(&boot);
		fprintf(stderr, "[+] Successfully updated boot image init -> '%s'\n", final_target);
		return 0;
	}

	cpio_free_all(head);
	boot_img_free(&boot);
	return ret;
}

/* =========================================================================
 * 11. Kernel Module Toolkit (--mod-info, --mod-audit, --mod-strip, --mod-patch,
 *     --mod-inject, --mod-load, --mod-unload)
 * ========================================================================= */
#include "module.c"

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

static char *replace_and_normalize_commas(const char *line, const char *pos, const char *old_opt, const char *new_opt) {
	size_t prefix_len = pos - line;
	size_t old_len = strlen(old_opt);
	const char *suffix = pos + old_len;
	const char *rep = (new_opt && strcmp(new_opt, "-") != 0 && strcmp(new_opt, "none") != 0) ? new_opt : "";
	char *raw = xasprintf("%.*s%s%s", (int)prefix_len, line, rep, suffix);
	char *clean = xmalloc(strlen(raw) + 1);
	char *r = raw, *w = clean;

	while (*r) {
		if (*r == ',') {
			/* Skip duplicate commas, leading comma, or comma directly preceded by space/tab */
			if (w == clean || *(w - 1) == ' ' || *(w - 1) == '\t' || *(w - 1) == ',') {
				r++;
				continue;
			}
			/* Skip trailing comma before whitespace or at line end */
			if (*(r + 1) == ' ' || *(r + 1) == '\t' || *(r + 1) == '\0') {
				r++;
				continue;
			}
		}
		*w++ = *r++;
	}
	*w = '\0';
	free(raw);
	return clean;
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
		char *copy_line;
		char *mnt;
		bool match = false;

		if (*p == '#' || *p == '\0') {
			fprintf(out_fp, "%s\n", line);
			free(line);
			continue;
		}

		copy_line = xstrdup(line);
		p = skip_whitespace(copy_line);
		strtok(p, " \t"); /* skip block device field */
		mnt = strtok(NULL, " \t");

		if (!target_mnt || strcmp(target_mnt, "*") == 0 || strcmp(target_mnt, "any") == 0) {
			match = true;
		} else if (mnt && strcmp(mnt, target_mnt) == 0) {
			match = true;
		}

		if (match && old_opt && old_opt[0]) {
			char *pos = strstr(line, old_opt);
			if (pos) {
				char *clean = replace_and_normalize_commas(line, pos, old_opt, new_opt);
				fprintf(out_fp, "%s\n", clean);
				count++;
				printf("[+] Patched %s on '%s': '%s' -> '%s'\n", target_mnt ? target_mnt : "*", file, old_opt, new_opt ? new_opt : "");
				free(clean);
				free(copy_line);
				free(line);
				continue;
			}
		}
		free(copy_line);
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
		printf("[-] Notice: Target '%s' with option '%s' not found in '%s'\n", target_mnt ? target_mnt : "*", old_opt, file);
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
		"enable\0"
		"update-hash\0";
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
		VBMETA_ACT_update_hash,
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

	case VBMETA_ACT_update_hash: {
		const char *part_name;
		const char *comp_path;
		int comp_fd;
		struct stat comp_st;
		uint8_t *comp_data;
		uint64_t aux_sz = SWAP_BE64(hdr->auxiliary_data_block_size);
		uint64_t desc_off = SWAP_BE64(hdr->descriptors_offset);
		uint64_t desc_sz = SWAP_BE64(hdr->descriptors_size);
		const uint8_t *aux_base = (const uint8_t *)hdr + sizeof(*hdr) + SWAP_BE64(hdr->authentication_data_block_size);
		uint64_t off;
		bool desc_updated = false;

		if (argc < 6) {
			bb_error_msg("usage: aimg vbmeta <image|vbmeta> update-hash <partition_name> <component_file>");
			munmap(map, map_sz);
			close(fd);
			return 1;
		}
		part_name = argv[4];
		comp_path = argv[5];

		comp_fd = open_or_warn(comp_path, O_RDONLY | O_CLOEXEC);
		if (comp_fd < 0) {
			munmap(map, map_sz);
			close(fd);
			return 1;
		}
		if (fstat(comp_fd, &comp_st) < 0 || comp_st.st_size == 0) {
			bb_perror_msg("invalid component file '%s'", comp_path);
			close(comp_fd);
			munmap(map, map_sz);
			close(fd);
			return 1;
		}

		comp_data = mmap(NULL, comp_st.st_size, PROT_READ, MAP_PRIVATE, comp_fd, 0);
		if (comp_data == MAP_FAILED || !comp_data) {
			bb_perror_msg("failed to mmap component '%s'", comp_path);
			close(comp_fd);
			munmap(map, map_sz);
			close(fd);
			return 1;
		}

		for (off = desc_off; off + sizeof(struct avb_descriptor) <= desc_off + desc_sz && off < aux_sz; ) {
			struct avb_descriptor *d = (struct avb_descriptor *)(aux_base + off);
			uint64_t tag = SWAP_BE64(d->tag);
			uint64_t nbf = SWAP_BE64(d->num_bytes_following);
			uint8_t *d_data = (uint8_t *)aux_base + off + sizeof(struct avb_descriptor);

			if (off + sizeof(struct avb_descriptor) + nbf > desc_off + desc_sz) break;

			if (tag == AVB_DESCRIPTOR_TAG_HASH) {
				struct avb_hash_descriptor *hd = (struct avb_hash_descriptor *)d;
				uint32_t nlen = SWAP_BE32(hd->partition_name_len);
				uint32_t dlen = SWAP_BE32(hd->digest_len);
				uint32_t slen = SWAP_BE32(hd->salt_len);
				const char *pname = (const char *)(d_data + sizeof(*hd) - sizeof(*d));
				const uint8_t *salt = (const uint8_t *)pname + nlen;
				uint8_t *digest = (uint8_t *)salt + slen;

				if (nlen == strlen(part_name) && strncmp(pname, part_name, nlen) == 0) {
					sha256_ctx_t sctx;
					uint8_t new_digest[32];
					char old_hex[65], new_hex[65];
					uint32_t k;

					memset(old_hex, 0, sizeof(old_hex));
					memset(new_hex, 0, sizeof(new_hex));

					for (k = 0; k < dlen && k < 32; k++)
						sprintf(old_hex + k * 2, "%02x", digest[k]);

					sha256_begin(&sctx);
					if (slen > 0)
						sha256_hash(&sctx, salt, slen);
					sha256_hash(&sctx, comp_data, comp_st.st_size);
					sha256_end(&sctx, new_digest);

					for (k = 0; k < dlen && k < 32; k++)
						sprintf(new_hex + k * 2, "%02x", new_digest[k]);

					hd->image_size = SWAP_BE64((uint64_t)comp_st.st_size);
					memcpy(digest, new_digest, (dlen < 32) ? dlen : 32);

					msync(map, map_sz, MS_SYNC);
					pwrite(fd, hdr, sizeof(*hdr), vbmeta_off);

					printf("[✓] SUCCESS: Updated AVB hash descriptor for '%s':\n", part_name);
					printf("    Image Size: %llu bytes\n", (unsigned long long)comp_st.st_size);
					printf("    Old Digest: %s\n", old_hex);
					printf("    New Digest: %s\n", new_hex);
					desc_updated = true;
					break;
				}
			}
			off += sizeof(struct avb_descriptor) + nbf;
		}

		munmap(comp_data, comp_st.st_size);
		close(comp_fd);

		if (!desc_updated) {
			bb_error_msg("AVB hash descriptor for partition '%s' not found", part_name);
			munmap(map, map_sz);
			close(fd);
			return 1;
		}
		break;
	}

	default:
		bb_error_msg("unknown vbmeta action '%s' (supported: status, disable, restore, update-hash)", action);
		munmap(map, map_sz);
		close(fd);
		return 1;
	}

	munmap(map, map_sz);
	close(fd);
	return 0;
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
		printf("[*] Flashing hybrid boot image directly to %s...\n", boot_img);
		if (flash_partition_image(repacked_img, boot_img, FLASH_OPT_VERIFY_READ) != 0) {
			bb_error_msg("failed to flash hybrid boot image to %s", boot_img);
			ret = 1;
			goto cleanup;
		}
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

/*
 * Ramdisk Extractor Engine
 * Extracts ramdisk from target boot image (or live boot partition)
 * with auto-decompression or raw extraction.
 */
static int magiskboot_extract_ramdisk_op(int argc, char **argv)
{
	bool live = false;
	bool raw = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *out_target = NULL;
	char discovered_boot[512];
	char abs_boot_img[PATH_MAX];
	boot_img_t boot;
	int i;
	int ret = 0;

	discovered_boot[0] = '\0';
	abs_boot_img[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-decomp") == 0 || strcmp(argv[i], "--raw") == 0) {
			raw = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
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
			safe_strncpy(discovered_boot, pbuf, sizeof(discovered_boot));
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				safe_strncpy(discovered_boot, pbuf, sizeof(discovered_boot));
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

	if (!realpath(boot_img, abs_boot_img)) {
		safe_strncpy(abs_boot_img, boot_img, sizeof(abs_boot_img));
	}

	if (!boot_img_parse(&boot, abs_boot_img)) {
		bb_error_msg("failed to parse boot image '%s'", abs_boot_img);
		return 1;
	}

	if (!boot.ramdisk || boot.ramdisk_size == 0) {
		bb_error_msg("boot image '%s' contains no ramdisk", abs_boot_img);
		boot_img_free(&boot);
		return 1;
	}

	if (!out_target) {
		if (raw && boot_fmt_compressed(boot.r_fmt)) {
			static char default_out[64];
			snprintf(default_out, sizeof(default_out), "ramdisk.cpio.%s", boot_fmt2name(boot.r_fmt));
			out_target = default_out;
		} else {
			out_target = RAMDISK_FILE;
		}
	}

	printf("[*] Extracting ramdisk from %s (%u bytes, %s)...\n",
	       abs_boot_img, boot.ramdisk_size, boot_fmt2name(boot.r_fmt));

	if (write_to_disk(out_target, boot.ramdisk, boot.ramdisk_size, boot.r_fmt, raw) != 0) {
		bb_error_msg("failed to write ramdisk to '%s'", out_target);
		ret = 1;
	} else {
		struct stat st;
		off_t out_sz = 0;
		if (stat(out_target, &st) == 0) out_sz = st.st_size;
		printf("[✓] SUCCESS: Extracted ramdisk (%lld bytes) -> %s\n",
		       (long long)out_sz, out_target);
	}

	boot_img_free(&boot);
	return ret;
}

/*
 * Ramdisk Setter / Replacer Engine
 * Injects or replaces the ramdisk in a target boot image (or live boot partition)
 */
static int magiskboot_set_ramdisk_op(int argc, char **argv)
{
	bool live = false;
	bool install = false;
	bool skip_comp = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *new_rd = NULL;
	const char *out_img = NULL;
	char discovered_boot[512];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_boot_img[PATH_MAX];
	char abs_new_rd[PATH_MAX];
	char repacked_img[PATH_MAX];
	struct stat st;
	int i;
	int ret = 0;

	discovered_boot[0] = '\0';
	abs_boot_img[0] = '\0';
	abs_new_rd[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "--install") == 0) {
			install = true;
		} else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-comp") == 0) {
			skip_comp = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			i++; /* skip device ID */
		} else if (argv[i][0] == '-') {
			/* skip unrecognized options */
		} else {
			if (!boot_img && !live) {
				boot_img = argv[i];
			} else if (!new_rd) {
				new_rd = argv[i];
			} else if (!out_img) {
				out_img = argv[i];
			}
		}
	}

	if (part_name) {
		char pbuf[PATH_MAX];
		snprintf(pbuf, sizeof(pbuf), "/dev/block/by-name/%s", part_name);
		if (access(pbuf, F_OK) == 0) {
			safe_strncpy(discovered_boot, pbuf, sizeof(discovered_boot));
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				safe_strncpy(discovered_boot, pbuf, sizeof(discovered_boot));
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

	if (!new_rd) {
		bb_error_msg("missing new ramdisk file or directory argument");
		return 1;
	}

	if (!realpath(boot_img, abs_boot_img)) {
		safe_strncpy(abs_boot_img, boot_img, sizeof(abs_boot_img));
	}
	if (!realpath(new_rd, abs_new_rd)) {
		safe_strncpy(abs_new_rd, new_rd, sizeof(abs_new_rd));
	}

	if (stat(abs_new_rd, &st) != 0) {
		bb_perror_msg("cannot access new ramdisk '%s'", abs_new_rd);
		return 1;
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}

	safe_strncpy(tmp_work_dir, "/tmp/mb_setrd_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}

	printf("[*] Unpacking target boot image: %s\n", abs_boot_img);
	chdir(tmp_work_dir);
	if (magiskboot_unpack(abs_boot_img, true, true, false, false) != 0) {
		bb_error_msg("failed to unpack target boot image '%s'", abs_boot_img);
		ret = 1;
		goto cleanup;
	}

	/* Remove previous ramdisk files in staging directory */
	unlink("ramdisk.cpio");
	unlink("ramdisk.cpio.gz");
	unlink("ramdisk.cpio.xz");
	unlink("ramdisk.cpio.lz4");
	unlink("ramdisk.cpio.bz2");
	unlink("ramdisk.cpio.zst");

	/* Install new ramdisk */
	if (S_ISDIR(st.st_mode)) {
		printf("[*] Packing directory %s into ramdisk.cpio...\n", abs_new_rd);
		if (cpio_pack_from_dir(abs_new_rd, "ramdisk.cpio") != 0) {
			bb_error_msg("failed to pack directory '%s' into ramdisk", abs_new_rd);
			ret = 1;
			goto cleanup;
		}
	} else {
		int in_fd = open_or_warn(abs_new_rd, O_RDONLY | O_CLOEXEC);
		uint8_t mbuf[32];
		ssize_t mn = 0;
		uint8_t fmt = BOOT_FMT_UNKNOWN;

		if (in_fd >= 0) {
			mn = full_read(in_fd, mbuf, sizeof(mbuf));
			close(in_fd);
			if (mn > 0) fmt = boot_check_fmt(mbuf, (size_t)mn);
		}

		if (fmt == BOOT_FMT_CPIO || fmt == BOOT_FMT_UNKNOWN) {
			copy_file(abs_new_rd, "ramdisk.cpio", FILEUTILS_FORCE);
		} else if (fmt == BOOT_FMT_GZIP) {
			copy_file(abs_new_rd, "ramdisk.cpio.gz", FILEUTILS_FORCE);
		} else if (fmt == BOOT_FMT_XZ) {
			copy_file(abs_new_rd, "ramdisk.cpio.xz", FILEUTILS_FORCE);
		} else if (fmt == BOOT_FMT_LZ4 || fmt == BOOT_FMT_LZ4_LEGACY || fmt == BOOT_FMT_LZ4_LG) {
			copy_file(abs_new_rd, "ramdisk.cpio.lz4", FILEUTILS_FORCE);
		} else if (fmt == BOOT_FMT_BZIP2) {
			copy_file(abs_new_rd, "ramdisk.cpio.bz2", FILEUTILS_FORCE);
		} else if (fmt == BOOT_FMT_ZSTD) {
			copy_file(abs_new_rd, "ramdisk.cpio.zst", FILEUTILS_FORCE);
		} else {
			copy_file(abs_new_rd, "ramdisk.cpio", FILEUTILS_FORCE);
		}
	}

	printf("[*] Repacking boot image with updated ramdisk...\n");
	snprintf(repacked_img, sizeof(repacked_img), "%s/new-boot.img", tmp_work_dir);
	if (magiskboot_repack(abs_boot_img, repacked_img, skip_comp) != 0) {
		bb_error_msg("failed to repack boot image");
		ret = 1;
		goto cleanup;
	}

	if (install) {
		printf("[*] Flashing updated boot image directly to %s...\n", abs_boot_img);
		if (flash_partition_image(repacked_img, abs_boot_img, FLASH_OPT_VERIFY_READ) != 0) {
			bb_error_msg("failed to flash updated boot image to %s", abs_boot_img);
			ret = 1;
			goto cleanup;
		}
		printf("[✓] SUCCESS: Flashed updated boot image to %s\n", abs_boot_img);
	} else {
		const char *dest = out_img ? out_img : "new-boot.img";
		chdir(old_cwd);
		if (copy_file(repacked_img, dest, FILEUTILS_FORCE) != 0) {
			bb_perror_msg("failed to write output image '%s'", dest);
			ret = 1;
			goto cleanup;
		}
		printf("[✓] SUCCESS: Updated boot image saved to %s\n", dest);
	}

cleanup:
	chdir(old_cwd);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

/* =========================================================================
 * 11b. AnyKernel Native Engine: Live Kernel Flashing, Cmdline & Fstab Patching
 * ========================================================================= */

struct dybuf {
	char *buf;
	size_t len;
	size_t cap;
};

static void dybuf_add_line(struct dybuf *d, const char *line) {
	size_t llen = strlen(line);
	if (d->len + llen + 2 > d->cap) {
		d->cap = (d->len + llen + 2 + 1024) * 2;
		d->buf = xrealloc(d->buf, d->cap);
	}
	memcpy(d->buf + d->len, line, llen);
	d->len += llen;
	d->buf[d->len++] = '\n';
	d->buf[d->len] = '\0';
}

static int fstab_buffer_patch(cpio_node_t *node, const char *target_mnt, const char *old_opt, const char *new_opt) {
	char *orig;
	char *saveptr = NULL;
	char *line;
	struct dybuf out;
	int count = 0;

	if (!node || !node->data || node->filesize == 0) return 0;

	memset(&out, 0, sizeof(out));
	orig = xstrndup((const char *)node->data, node->filesize);
	line = strtok_r(orig, "\r\n", &saveptr);

	while (line) {
		char *p = skip_whitespace(line);
		char *copy_line;
		char *mnt;
		bool match = false;

		if (*p == '#' || *p == '\0') {
			dybuf_add_line(&out, line);
			line = strtok_r(NULL, "\r\n", &saveptr);
			continue;
		}

		copy_line = xstrdup(line);
		p = skip_whitespace(copy_line);
		strtok(p, " \t"); /* skip block device field */
		mnt = strtok(NULL, " \t");

		if (!target_mnt || strcmp(target_mnt, "*") == 0 || strcmp(target_mnt, "any") == 0) {
			match = true;
		} else if (mnt && strcmp(mnt, target_mnt) == 0) {
			match = true;
		}

		if (match && old_opt && old_opt[0]) {
			char *pos = strstr(line, old_opt);
			if (pos) {
				char *new_line = replace_and_normalize_commas(line, pos, old_opt, new_opt);
				dybuf_add_line(&out, new_line);
				free(new_line);
				count++;
				free(copy_line);
				line = strtok_r(NULL, "\r\n", &saveptr);
				continue;
			}
		}

		free(copy_line);
		dybuf_add_line(&out, line);
		line = strtok_r(NULL, "\r\n", &saveptr);
	}

	free(orig);

	if (count > 0 && out.buf) {
		free(node->data);
		node->data = out.buf;
		node->filesize = (uint32_t)out.len;
	} else {
		free(out.buf);
	}

	return count;
}

static bool is_block_device_node(const char *path) {
	struct stat st;
	if (path && stat(path, &st) == 0 && S_ISBLK(st.st_mode))
		return true;
	return false;
}

static int magiskboot_flash_kernel_op(int argc, char **argv) {
	const char *kernel_file = NULL;
	const char *part_name = NULL;
	const char *dtb_file = NULL;
	bool backup = false;
	bool verify = true;
	bool skip_comp = false;
	char target_path[PATH_MAX];
	char repacked_img[PATH_MAX];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_kernel[PATH_MAX];
	char abs_dtb[PATH_MAX];
	struct flash_target_geometry geom;
	struct stat st_k;
	int i;
	int ret = 0;
	bool has_magisk = false;

	target_path[0] = '\0';
	abs_kernel[0] = '\0';
	abs_dtb[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--backup") == 0) {
			backup = true;
		} else if (strcmp(argv[i], "--no-verify") == 0) {
			verify = false;
		} else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--no-comp") == 0) {
			skip_comp = true;
		} else if (strcmp(argv[i], "--dtb") == 0 && i + 1 < argc) {
			dtb_file = argv[++i];
		} else if (argv[i][0] != '-') {
			if (!kernel_file) {
				kernel_file = argv[i];
			} else if (!part_name) {
				part_name = argv[i];
			}
		}
	}

	if (!kernel_file) {
		bb_error_msg("usage: aimg --flash-kernel <kernel_img> [partition_or_auto] [--backup] [--no-verify] [--dtb <dtb>]");
		return 1;
	}

	if (stat(kernel_file, &st_k) != 0 || !S_ISREG(st_k.st_mode) || st_k.st_size < 1024) {
		bb_error_msg("cannot access valid kernel image '%s'", kernel_file);
		return 1;
	}

	if (!realpath(kernel_file, abs_kernel)) {
		safe_strncpy(abs_kernel, kernel_file, sizeof(abs_kernel));
	}
	if (dtb_file && !realpath(dtb_file, abs_dtb)) {
		safe_strncpy(abs_dtb, dtb_file, sizeof(abs_dtb));
	}

	/* Resolve target partition */
	if (!part_name || strcmp(part_name, "auto") == 0 || strcmp(part_name, "boot") == 0) {
		if (flash_find_partition("boot", target_path, sizeof(target_path)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
	} else if (part_name[0] == '/') {
		safe_strncpy(target_path, part_name, sizeof(target_path));
		if (access(target_path, F_OK) != 0) {
			bb_error_msg("target partition node '%s' does not exist", target_path);
			return 1;
		}
	} else {
		if (flash_find_partition(part_name, target_path, sizeof(target_path)) != 0) {
			bb_error_msg("failed to resolve partition '%s'", part_name);
			return 1;
		}
	}

	/* Probe target storage geometry and AVB 2.0 footer */
	if (flash_probe_geometry(target_path, &geom) != 0) {
		bb_error_msg("failed to probe target partition '%s'", target_path);
		return 1;
	}

	printf("======================================================================\n");
	printf("  AnyKernel Flash Engine: Live Kernel Splicing & Flashing\n");
	printf("======================================================================\n");
	printf("  • Source Kernel  : %s (%lld bytes, %.2f MB)\n", abs_kernel,
	       (long long)st_k.st_size, (double)st_k.st_size / (1024.0 * 1024.0));
	if (abs_dtb[0]) {
		printf("  • Source DTB     : %s\n", abs_dtb);
	}
	printf("  • Target Node    : %s (%s)\n", target_path,
	       geom.is_block_device ? "Block Device" : "Image File");
	if (geom.capacity_bytes > 0) {
		printf("  • Target Capacity: %llu bytes (%.2f MB)\n",
		       (unsigned long long)geom.capacity_bytes,
		       (double)geom.capacity_bytes / (1024.0 * 1024.0));
	}
	if (geom.has_avb_footer) {
		printf("  • AVB 2.0 Footer : Detected (VBMeta Offset: 0x%llx)\n",
		       (unsigned long long)geom.avb_vbmeta_offset);
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}

	safe_strncpy(tmp_work_dir, "/tmp/mb_flk_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}

	printf("[*] Unpacking current target boot image...\n");
	chdir(tmp_work_dir);
	if (magiskboot_unpack(target_path, true, true, false, false) != 0) {
		bb_error_msg("failed to unpack target image '%s'", target_path);
		ret = 1;
		goto cleanup_flk;
	}

	/* Check if Magisk is present in the target boot image */
	if (access(".backup/.magisk", F_OK) == 0) {
		has_magisk = true;
	} else if (access(RAMDISK_FILE, R_OK) == 0) {
		int rfd = open(RAMDISK_FILE, O_RDONLY | O_CLOEXEC);
		if (rfd >= 0) {
			char rhead[512];
			ssize_t rn = read(rfd, rhead, sizeof(rhead) - 1);
			close(rfd);
			if (rn > 0) {
				rhead[rn] = '\0';
				if (strstr(rhead, "magisk") || strstr(rhead, "overlay.d"))
					has_magisk = true;
			}
		}
	}

	/* Remove previous kernel and dtb components from staging */
	unlink(KERNEL_FILE);
	unlink("kernel.gz");
	unlink("kernel.xz");
	unlink("kernel.lz4");
	unlink("kernel.bz2");
	unlink("kernel.zst");

	/* Stage new kernel */
	if (copy_file(abs_kernel, KERNEL_FILE, FILEUTILS_FORCE) != 0) {
		bb_perror_msg("failed to stage kernel file");
		ret = 1;
		goto cleanup_flk;
	}

	/* AnyKernel SAR Magisk check: skip_initramfs -> want_initramfs */
	if (has_magisk) {
		printf("[*] Magisk detected in target boot image: auditing kernel for SAR patch...\n");
		if (magiskboot_hexpatch(KERNEL_FILE, "736b69705f696e697472616d6673", "77616e745f696e697472616d6673") == 0) {
			printf("[+] Patched kernel 'skip_initramfs' -> 'want_initramfs' (Magisk SAR preserved)\n");
		}
		if (access(DTB_FILE, R_OK) == 0) {
			char *dtb_args[] = { (char *)"dtb", (char *)DTB_FILE, (char *)"patch", NULL };
			magiskboot_dtb(3, dtb_args);
		}
	}

	/* Stage custom DTB if provided */
	if (abs_dtb[0]) {
		unlink(DTB_FILE);
		unlink(KER_DTB_FILE);
		if (copy_file(abs_dtb, DTB_FILE, FILEUTILS_FORCE) != 0) {
			bb_perror_msg("failed to stage custom DTB file");
			ret = 1;
			goto cleanup_flk;
		}
		printf("[+] Custom DTB staged -> %s\n", DTB_FILE);
	}

	printf("[*] Repacking boot image with updated kernel...\n");
	snprintf(repacked_img, sizeof(repacked_img), "%s/new-boot.img", tmp_work_dir);
	if (magiskboot_repack(target_path, repacked_img, skip_comp) != 0) {
		bb_error_msg("failed to repack boot image");
		ret = 1;
		goto cleanup_flk;
	}

	{
		struct stat st_rep;
		unsigned int flash_flags = 0;

		if (stat(repacked_img, &st_rep) != 0) {
			bb_error_msg("repacked boot image is missing");
			ret = 1;
			goto cleanup_flk;
		}

		if (geom.capacity_bytes > 0 && (uint64_t)st_rep.st_size > geom.capacity_bytes) {
			bb_error_msg("CRITICAL: Repacked boot image size (%lld B) exceeds partition capacity (%llu B)!",
			             (long long)st_rep.st_size, (unsigned long long)geom.capacity_bytes);
			ret = 1;
			goto cleanup_flk;
		}

		if (verify) flash_flags |= FLASH_OPT_VERIFY_READ;
		if (backup) flash_flags |= FLASH_OPT_BACKUP;

		printf("[*] Flashing spliced boot image to %s...\n", target_path);
		if (flash_partition_image(repacked_img, target_path, flash_flags) != 0) {
			bb_error_msg("failed to flash spliced image to %s", target_path);
			ret = 1;
			goto cleanup_flk;
		}

		printf("======================================================================\n");
		printf("[✓] SUCCESS: Kernel spliced and flashed successfully to %s\n", target_path);
		printf("======================================================================\n");
	}

cleanup_flk:
	chdir(old_cwd);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

static int magiskboot_patch_cmdline_op(int argc, char **argv) {
	const char *target = NULL;
	char discovered_boot[PATH_MAX];
	int opt_idx = 2;
	int fd;
	uint8_t hdr_buf[4096];
	ssize_t nr;
	bool is_boot = false;
	bool is_vnd = false;
	uint32_t header_ver = 0;
	uint32_t max_cmd_len = 0;
	char cur_cmdline[4096];
	char **tokens = NULL;
	size_t num_tok = 0, cap_tok = 256;
	char *tok;
	bool modified = false;
	int a;
	char new_cmdline[4096];
	size_t t;
	bool first = true;
	struct stat st_tgt;

	if (argc < 3) {
		bb_error_msg("usage: aimg --patch-cmdline [boot.img|dev|--live] <key=val | +key[=val] | -key>...");
		return 1;
	}

	if (strcmp(argv[2], "--live") == 0) {
		opt_idx = 3;
	} else if (argv[2][0] == '+' || argv[2][0] == '-' || strchr(argv[2], '=')) {
		opt_idx = 2;
	} else if (access(argv[2], F_OK) == 0) {
		target = argv[2];
		opt_idx = 3;
	} else {
		if (flash_find_partition(argv[2], discovered_boot, sizeof(discovered_boot)) == 0) {
			target = discovered_boot;
			opt_idx = 3;
		} else {
			opt_idx = 2;
		}
	}

	if (!target) {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		target = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", target);
	}

	fd = open(target, O_RDWR | O_CLOEXEC);
	if (fd < 0 && (errno == EACCES || errno == EROFS) && is_block_device_node(target)) {
		int ro = 0;
		int rfd = open(target, O_RDONLY | O_CLOEXEC);
		if (rfd >= 0) {
			ioctl(rfd, BLKROSET, &ro);
			close(rfd);
			fd = open(target, O_RDWR | O_CLOEXEC);
		}
	}
	if (fd < 0) {
		fd = open_or_warn(target, O_RDONLY | O_CLOEXEC);
		if (fd < 0) return 1;
	}

	memset(hdr_buf, 0, sizeof(hdr_buf));
	nr = full_read(fd, hdr_buf, sizeof(hdr_buf));
	if (nr < 64) {
		close(fd);
		if (opt_idx >= argc) return cmdline_print(target);
		bb_error_msg("cannot read header from '%s'", target);
		return 1;
	}

	if (memcmp(hdr_buf, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
		is_boot = true;
	} else if (memcmp(hdr_buf, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE) == 0) {
		is_vnd = true;
	}

	/* If not an AOSP boot header, fallback to plain text file handler */
	if (!is_boot && !is_vnd) {
		close(fd);
		if (opt_idx >= argc) return cmdline_print(target);
		for (a = opt_idx; a < argc; a++) {
			const char *expr = argv[a];
			if (expr[0] == '-') {
				cmdline_modify(target, "rm", expr + 1, NULL);
			} else {
				const char *arg_str = (expr[0] == '+') ? expr + 1 : expr;
				const char *eq = strchr(arg_str, '=');
				if (eq) {
					char *k = xstrndup(arg_str, eq - arg_str);
					cmdline_modify(target, "patch", k, eq + 1);
					free(k);
				} else {
					cmdline_modify(target, "add", arg_str, NULL);
				}
			}
		}
		return 0;
	}

	/* Extract current command line from AOSP boot header */
	memset(cur_cmdline, 0, sizeof(cur_cmdline));
	if (is_boot) {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)hdr_buf;
		header_ver = SWAP_LE32(h0->header_version);
		if (header_ver < 3) {
			snprintf(cur_cmdline, sizeof(cur_cmdline), "%.*s%.*s",
			         BOOT_ARGS_SIZE, h0->cmdline,
			         BOOT_EXTRA_ARGS_SIZE, h0->extra_cmdline);
			max_cmd_len = BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE - 2;
		} else {
			struct boot_img_hdr_v3 *h3 = (struct boot_img_hdr_v3 *)hdr_buf;
			snprintf(cur_cmdline, sizeof(cur_cmdline), "%.*s",
			         (int)sizeof(h3->cmdline), h3->cmdline);
			max_cmd_len = sizeof(h3->cmdline) - 1;
		}
	} else {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)hdr_buf;
		snprintf(cur_cmdline, sizeof(cur_cmdline), "%.*s",
		         (int)sizeof(hv->cmdline), hv->cmdline);
		max_cmd_len = sizeof(hv->cmdline) - 1;
	}
	trim(cur_cmdline);

	/* If no modifications provided, print current cmdline */
	if (opt_idx >= argc) {
		printf("======================================================================\n");
		printf("  Kernel Command Line Inspector: %s (Header v%u)\n", target, header_ver);
		printf("======================================================================\n");
		printf("  Raw: %s\n", cur_cmdline);
		printf("======================================================================\n");
		close(fd);
		return 0;
	}

	printf("======================================================================\n");
	printf("  AnyKernel In-Place Command Line Patcher: %s\n", target);
	printf("======================================================================\n");
	printf("  • Original cmdline: %s\n", cur_cmdline);

	tokens = xmalloc(cap_tok * sizeof(char *));
	tok = strtok(cur_cmdline, " \t\r\n");
	while (tok) {
		tokens[num_tok++] = xstrdup(tok);
		tok = strtok(NULL, " \t\r\n");
	}

	for (a = opt_idx; a < argc; a++) {
		const char *expr = argv[a];
		if (expr[0] == '-') {
			const char *key = expr + 1;
			size_t klen = strlen(key);
			for (t = 0; t < num_tok; t++) {
				if (!tokens[t]) continue;
				if (strcmp(tokens[t], key) == 0 ||
				    (strncmp(tokens[t], key, klen) == 0 && tokens[t][klen] == '=')) {
					printf("  [+] Removed parameter: '%s'\n", tokens[t]);
					free(tokens[t]);
					tokens[t] = NULL;
					modified = true;
				}
			}
		} else {
			const char *arg_str = (expr[0] == '+') ? expr + 1 : expr;
			const char *eq = strchr(arg_str, '=');
			char *key;
			size_t klen;
			bool found = false;

			if (eq) {
				klen = eq - arg_str;
				key = xstrndup(arg_str, klen);
			} else {
				key = xstrdup(arg_str);
				klen = strlen(key);
			}

			for (t = 0; t < num_tok; t++) {
				if (!tokens[t]) continue;
				if (strcmp(tokens[t], key) == 0 ||
				    (strncmp(tokens[t], key, klen) == 0 && tokens[t][klen] == '=')) {
					printf("  [+] Replaced parameter: '%s' -> '%s'\n", tokens[t], arg_str);
					free(tokens[t]);
					tokens[t] = xstrdup(arg_str);
					found = true;
					modified = true;
					break;
				}
			}
			if (!found) {
				if (num_tok >= cap_tok) {
					cap_tok *= 2;
					tokens = xrealloc(tokens, cap_tok * sizeof(char *));
				}
				tokens[num_tok++] = xstrdup(arg_str);
				printf("  [+] Added parameter: '%s'\n", arg_str);
				modified = true;
			}
			free(key);
		}
	}

	new_cmdline[0] = '\0';
	for (t = 0; t < num_tok; t++) {
		if (!tokens[t]) continue;
		if (!first) strncat(new_cmdline, " ", sizeof(new_cmdline) - strlen(new_cmdline) - 1);
		strncat(new_cmdline, tokens[t], sizeof(new_cmdline) - strlen(new_cmdline) - 1);
		first = false;
		free(tokens[t]);
	}
	free(tokens);

	if (!modified) {
		printf("[-] Notice: cmdline not modified\n");
		close(fd);
		return 0;
	}

	if (strlen(new_cmdline) > max_cmd_len) {
		bb_error_msg("new cmdline length (%zu) exceeds header capacity (%u)",
		             strlen(new_cmdline), max_cmd_len);
		close(fd);
		return 1;
	}

	/* Store back into header */
	if (is_boot) {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)hdr_buf;
		if (header_ver < 3) {
			memset(h0->cmdline, 0, sizeof(h0->cmdline));
			memset(h0->extra_cmdline, 0, sizeof(h0->extra_cmdline));
			if (strlen(new_cmdline) < sizeof(h0->cmdline)) {
				safe_strncpy(h0->cmdline, new_cmdline, sizeof(h0->cmdline));
			} else {
				safe_strncpy(h0->cmdline, new_cmdline, sizeof(h0->cmdline));
				safe_strncpy(h0->extra_cmdline, new_cmdline + sizeof(h0->cmdline) - 1, sizeof(h0->extra_cmdline));
			}
		} else {
			struct boot_img_hdr_v3 *h3 = (struct boot_img_hdr_v3 *)hdr_buf;
			memset(h3->cmdline, 0, sizeof(h3->cmdline));
			safe_strncpy(h3->cmdline, new_cmdline, sizeof(h3->cmdline));
		}
	} else {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)hdr_buf;
		memset(hv->cmdline, 0, sizeof(hv->cmdline));
		safe_strncpy(hv->cmdline, new_cmdline, sizeof(hv->cmdline));
	}

	if (fstat(fd, &st_tgt) == 0 && S_ISBLK(st_tgt.st_mode)) {
		int ro = 0;
		ioctl(fd, BLKROSET, &ro);
	}

	if (lseek(fd, 0, SEEK_SET) < 0 || full_write(fd, hdr_buf, nr) != nr) {
		bb_perror_msg("failed to write updated header to %s", target);
		close(fd);
		return 1;
	}

	fsync(fd);
	if (fstat(fd, &st_tgt) == 0 && S_ISBLK(st_tgt.st_mode)) {
		ioctl(fd, BLKFLSBUF, 0);
	}
	close(fd);

	printf("  • Updated cmdline : %s\n", new_cmdline);
	printf("[✓] SUCCESS: Kernel command line updated in-place on %s\n", target);
	printf("======================================================================\n");
	return 0;
}

static int magiskboot_patch_fstab_op(int argc, char **argv) {
	bool live = false;
	const char *target = NULL;
	char discovered_boot[PATH_MAX];
	int arg_idx = 2;
	int tfd;
	char magic[8];
	bool is_boot = false;
	ssize_t mn;

	if (argc < 4 && (argc < 3 || strcmp(argv[2], "--live") != 0)) {
		bb_error_msg("usage: aimg --patch-fstab <boot.img|fstab|--live> <mount|pattern> <old_opt|replacement> [new_opt]");
		return 1;
	}

	if (strcmp(argv[2], "--live") == 0) {
		live = true;
		arg_idx = 3;
	} else if (argc >= 4 && strcmp(argv[3], "--live") == 0) {
		live = true;
		target = argv[2];
		arg_idx = 4;
	} else {
		target = argv[2];
		arg_idx = 3;
	}

	if (live || !target) {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		target = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", target);
	}

	memset(magic, 0, sizeof(magic));
	tfd = open(target, O_RDONLY | O_CLOEXEC);
	if (tfd >= 0) {
		mn = full_read(tfd, magic, sizeof(magic));
		close(tfd);
		if (mn == (ssize_t)sizeof(magic)) {
			if (memcmp(magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0 ||
			    memcmp(magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE) == 0) {
				is_boot = true;
			}
		}
	}

	/* Plain text fstab handling */
	if (!is_boot) {
		if (argc - arg_idx >= 3) {
			return fstab_patch(target, argv[arg_idx], argv[arg_idx + 1], argv[arg_idx + 2]);
		} else if (argc - arg_idx == 2) {
			return fstab_patch(target, "*", argv[arg_idx], argv[arg_idx + 1]);
		} else if (argc - arg_idx == 1) {
			return fstab_patch(target, "*", argv[arg_idx], "");
		}
		return 1;
	}

	/* Boot image / partition ramdisk fstab handling */
	{
		char tmp_dir[256];
		char old_cwd[512];
		char repacked_img[PATH_MAX];
		int ret = 0;
		int modified_count = 0;
		cpio_node_t *head;
		cpio_node_t *cur;

		if (!getcwd(old_cwd, sizeof(old_cwd))) {
			strcpy(old_cwd, ".");
		}

		safe_strncpy(tmp_dir, "/tmp/mb_pfst_XXXXXX", sizeof(tmp_dir));
		if (!mkdtemp(tmp_dir)) {
			bb_perror_msg("cannot create temporary directory '%s'", tmp_dir);
			return 1;
		}

		printf("[*] Unpacking boot image ramdisk to patch fstab: %s...\n", target);
		chdir(tmp_dir);
		if (magiskboot_unpack(target, true, false, false, false) != 0) {
			bb_error_msg("failed to unpack boot image '%s'", target);
			ret = 1;
			goto cleanup_pfst;
		}

		if (access(RAMDISK_FILE, R_OK) != 0) {
			bb_error_msg("no ramdisk found in boot image '%s'", target);
			ret = 1;
			goto cleanup_pfst;
		}

		head = cpio_read_all(RAMDISK_FILE);
		if (!head) {
			bb_error_msg("failed to parse ramdisk CPIO archive");
			ret = 1;
			goto cleanup_pfst;
		}

		for (cur = head; cur; cur = cur->next) {
			if (strstr(cur->name, "fstab") != NULL && cur->data && cur->filesize > 0) {
				int mods = 0;
				if (argc - arg_idx >= 3) {
					mods = fstab_buffer_patch(cur, argv[arg_idx], argv[arg_idx + 1], argv[arg_idx + 2]);
				} else if (argc - arg_idx == 2) {
					mods = fstab_buffer_patch(cur, "*", argv[arg_idx], argv[arg_idx + 1]);
				} else if (argc - arg_idx == 1) {
					mods = fstab_buffer_patch(cur, "*", argv[arg_idx], "");
				}
				if (mods > 0) {
					printf("  [+] Applied %d patch(es) to ramdisk fstab: %s\n", mods, cur->name);
					modified_count += mods;
				}
			}
		}

		if (modified_count == 0) {
			printf("[-] Notice: No matching fstab entries were found to modify in ramdisk\n");
			cpio_free_all(head);
			goto cleanup_pfst;
		}

		printf("[*] Repacking ramdisk CPIO archive with updated fstab entries...\n");
		if (cpio_write_all(RAMDISK_FILE, head) != 0) {
			bb_error_msg("failed to write patched ramdisk");
			cpio_free_all(head);
			ret = 1;
			goto cleanup_pfst;
		}
		cpio_free_all(head);

		unlink("ramdisk.cpio.gz");
		unlink("ramdisk.cpio.xz");
		unlink("ramdisk.cpio.lz4");
		unlink("ramdisk.cpio.bz2");
		unlink("ramdisk.cpio.zst");

		printf("[*] Repacking boot image...\n");
		snprintf(repacked_img, sizeof(repacked_img), "%s/new-boot.img", tmp_dir);
		if (magiskboot_repack(target, repacked_img, false) != 0) {
			bb_error_msg("failed to repack boot image");
			ret = 1;
			goto cleanup_pfst;
		}

		if (live || is_block_device_node(target)) {
			printf("[*] Flashing updated boot image directly to %s...\n", target);
			if (flash_partition_image(repacked_img, target, FLASH_OPT_VERIFY_READ) != 0) {
				bb_error_msg("failed to flash updated boot image to %s", target);
				ret = 1;
				goto cleanup_pfst;
			}
			printf("[✓] SUCCESS: Flashed patched fstab directly to %s\n", target);
		} else {
			chdir(old_cwd);
			if (copy_file(repacked_img, target, FILEUTILS_FORCE) != 0) {
				bb_perror_msg("failed to write output image '%s'", target);
				ret = 1;
				goto cleanup_pfst;
			}
			printf("[✓] SUCCESS: Updated fstab inside boot image '%s'\n", target);
		}

cleanup_pfst:
		chdir(old_cwd);
		remove_file(tmp_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
		return ret;
	}
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
 * Universal Image & Component Inspector
 * ========================================================================= */

static int magiskboot_info_image(const char *path) {
	boot_img_t boot;
	int fd;
	struct stat st;
	off_t sz;
	void *map;
	uint8_t fmt;

	if (!path) return 1;

	/* 1. Try parsing as an Android boot / vendor boot image */
	if (boot_img_parse_full(&boot, path, true)) {
		boot_img_print_info(&boot, path);
		boot_img_free(&boot);
		return 0;
	}

	/* 2. Standalone image/component analysis */
	fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return 1;
	}

	sz = get_file_or_bdev_size(fd, &st);
	if (sz < 4) {
		close(fd);
		bb_error_msg("file '%s' is too small (%lld bytes)", path, (long long)sz);
		return 1;
	}

	map = map_or_read_image(fd, (size_t)sz, false);
	close(fd);
	if (!map || map == MAP_FAILED) return 1;

	fmt = boot_check_fmt(map, (size_t)sz);

	printf("====================================================================\n");
	printf("Image File:           %s\n", path);
	printf("Total Size:           %lld bytes (%.2f MB)\n", (long long)sz, (double)sz / (1024 * 1024));
	printf("Detected Format:      %s\n", boot_fmt2name(fmt));
	printf("--------------------------------------------------------------------\n");

	switch (fmt) {
	case BOOT_FMT_ARM64_IMAGE: {
		char banner[256];
		printf("Type:                 ARM64 (AArch64) Linux Kernel Image\n");
		inspect_arm64_image(map, (size_t)sz, "");
		if (scan_linux_version_banner(map, (size_t)sz, banner, sizeof(banner))) {
			printf("Linux Banner:         %s\n", banner);
		}
		break;
	}

	case BOOT_FMT_ZIMAGE: {
		char banner[256];
		printf("Type:                 ARM 32-bit zImage Kernel\n");
		inspect_arm32_zimage(map, (size_t)sz, "");
		if (scan_linux_version_banner(map, (size_t)sz, banner, sizeof(banner))) {
			printf("Linux Banner:         %s\n", banner);
		}
		break;
	}

	case BOOT_FMT_DTB:
		printf("Type:                 Flattened Device Tree Blob (DTB)\n");
		inspect_fdt_details(map, (size_t)sz, "");
		break;

	case BOOT_FMT_DTBO:
		printf("Type:                 Device Tree Overlay Table (DTBO)\n");
		inspect_dtbo_details(map, (size_t)sz, "");
		break;

	case BOOT_FMT_CPIO:
		printf("Type:                 CPIO Archive (Ramdisk)\n");
		inspect_cpio_buffer(map, (size_t)sz, "");
		break;

	case BOOT_FMT_SPARSE:
		inspect_sparse_details(map, (size_t)sz, "");
		break;

	case BOOT_FMT_SUPER:
		inspect_super_details(map, (size_t)sz, "");
		break;

	case BOOT_FMT_EROFS:
	case BOOT_FMT_F2FS:
	case BOOT_FMT_EXT4:
		inspect_filesystem_details(map, (size_t)sz, fmt, "");
		break;

	case BOOT_FMT_SQUASHFS:
		printf("Type:                 SquashFS File System\n");
		break;

	case BOOT_FMT_VBMETA:
		inspect_avb_vbmeta_details(map, (size_t)sz, "");
		break;

	case BOOT_FMT_PAYLOAD:
		printf("Type:                 Android OTA Update Payload (payload.bin)\n");
		payload_info(path);
		break;

	case BOOT_FMT_GZIP:
	case BOOT_FMT_XZ:
	case BOOT_FMT_LZMA:
	case BOOT_FMT_BZIP2:
	case BOOT_FMT_LZ4:
	case BOOT_FMT_LZ4_LEGACY:
	case BOOT_FMT_LZ4_LG:
	case BOOT_FMT_LZOP:
	case BOOT_FMT_ZSTD: {
		char banner[256];
		printf("Type:                 Compressed Archive / Stream (%s)\n", boot_fmt2name(fmt));
		inspect_compression_details(map, (size_t)sz, fmt, "");
		inspect_ramdisk_details(map, (size_t)sz, fmt, "");
		if (extract_kernel_banner(map, (size_t)sz, fmt, banner, sizeof(banner))) {
			printf("Linux Kernel Banner:  %s\n", banner);
		}
		inspect_kernel_embedded_details(map, (size_t)sz, "");
		break;
	}

	default: {
		char banner[256];
		if ((size_t)sz >= 4096 + 4 && memcmp((const uint8_t *)map + 4096, "gDla", 4) == 0) {
			inspect_super_details(map, (size_t)sz, "");
		} else if ((size_t)sz >= 4 && memcmp(map, "gDla", 4) == 0) {
			inspect_super_details(map, (size_t)sz, "");
		} else {
			printf("Type:                 Raw / Unrecognized Binary Image\n");
			if (scan_linux_version_banner(map, (size_t)sz, banner, sizeof(banner))) {
				printf("Linux Kernel Banner:  %s\n", banner);
			}
			inspect_kernel_embedded_details(map, (size_t)sz, "");
		}
		break;
	}
	}

	printf("====================================================================\n");
	munmap(map, (size_t)sz);
	return 0;
}

/* =========================================================================
 * 13. Android Production & Debug Flags Engine (user, userdebug, eng)
 * ========================================================================= */

struct prop_grow_buf {
	char *data;
	size_t len;
	size_t cap;
};

static void prop_gb_append(struct prop_grow_buf *gb, const void *src, size_t n)
{
	if (!gb || !src || n == 0) return;
	if (gb->len + n + 1 > gb->cap) {
		gb->cap = (gb->cap == 0) ? (n + 512) : (gb->cap * 2 + n + 512);
		gb->data = xrealloc(gb->data, gb->cap);
	}
	memcpy(gb->data + gb->len, src, n);
	gb->len += n;
	gb->data[gb->len] = '\0';
}

static bool property_buffer_get(const char *buf, size_t sz, const char *key, char *out_val, size_t max_len)
{
	const char *cur = buf;
	const char *end = buf + sz;
	size_t klen;

	if (!buf || sz == 0 || !key || !out_val || max_len == 0) return false;
	klen = strlen(key);

	while (cur < end) {
		const char *line_start = cur;
		const char *line_end = memchr(cur, '\n', end - cur);
		const char *p;
		const char *eq;
		size_t vlen;

		if (!line_end) line_end = end;
		cur = (line_end < end) ? line_end + 1 : end;

		p = line_start;
		while (p < line_end && (*p == ' ' || *p == '\t')) p++;
		if (p >= line_end || *p == '#' || *p == '\0') continue;

		eq = memchr(p, '=', line_end - p);
		if (!eq) continue;

		if ((size_t)(eq - p) == klen && memcmp(p, key, klen) == 0) {
			const char *vstart = eq + 1;
			const char *vend = line_end;
			while (vend > vstart && (*(vend - 1) == '\r' || *(vend - 1) == ' ' || *(vend - 1) == '\t'))
				vend--;
			vlen = vend - vstart;
			if (vlen >= max_len) vlen = max_len - 1;
			memcpy(out_val, vstart, vlen);
			out_val[vlen] = '\0';
			return true;
		}
	}
	return false;
}

static char *property_buffer_set(const char *buf, size_t sz, const char *key, const char *val, size_t *out_sz)
{
	struct prop_grow_buf gb = { NULL, 0, 0 };
	const char *cur = buf;
	const char *end = buf + (buf ? sz : 0);
	size_t klen = strlen(key);
	bool found = false;

	while (cur && cur < end) {
		const char *line_start = cur;
		const char *line_end = memchr(cur, '\n', end - cur);
		const char *p;
		const char *eq;

		if (!line_end) line_end = end;
		cur = (line_end < end) ? line_end + 1 : end;

		p = line_start;
		while (p < line_end && (*p == ' ' || *p == '\t')) p++;

		if (p < line_end && *p != '#' && *p != '\0') {
			eq = memchr(p, '=', line_end - p);
			if (eq && (size_t)(eq - p) == klen && memcmp(p, key, klen) == 0) {
				found = true;
				if (val) {
					/* Replace with key=val\n */
					prop_gb_append(&gb, key, klen);
					prop_gb_append(&gb, "=", 1);
					prop_gb_append(&gb, val, strlen(val));
					prop_gb_append(&gb, "\n", 1);
				}
				/* If val == NULL, omit line entirely */
				continue;
			}
		}

		/* Preserve original line */
		prop_gb_append(&gb, line_start, cur - line_start);
	}

	if (!found && val) {
		if (gb.len > 0 && gb.data[gb.len - 1] != '\n') {
			prop_gb_append(&gb, "\n", 1);
		}
		prop_gb_append(&gb, key, klen);
		prop_gb_append(&gb, "=", 1);
		prop_gb_append(&gb, val, strlen(val));
		prop_gb_append(&gb, "\n", 1);
	}

	if (out_sz) *out_sz = gb.len;
	return gb.data ? gb.data : xstrdup("");
}

static char *bootconfig_buffer_set(const char *buf, size_t sz, const char *key, const char *val, size_t *out_sz)
{
	struct prop_grow_buf gb = { NULL, 0, 0 };
	const char *cur = buf;
	const char *end = buf + (buf ? sz : 0);
	size_t klen = strlen(key);
	bool found = false;

	while (cur && cur < end) {
		const char *line_start = cur;
		const char *line_end = memchr(cur, '\n', end - cur);
		const char *p;

		if (!line_end) line_end = end;
		cur = (line_end < end) ? line_end + 1 : end;

		p = line_start;
		while (p < line_end && (*p == ' ' || *p == '\t')) p++;

		if (p < line_end && *p != '#' && *p != '\0') {
			if ((size_t)(line_end - p) >= klen && memcmp(p, key, klen) == 0 &&
			    (p + klen == line_end || p[klen] == ' ' || p[klen] == '\t' || p[klen] == '=')) {
				found = true;
				if (val) {
					/* Replace with key = "val"\n */
					prop_gb_append(&gb, key, klen);
					prop_gb_append(&gb, " = \"", 4);
					prop_gb_append(&gb, val, strlen(val));
					prop_gb_append(&gb, "\"\n", 2);
				}
				continue;
			}
		}

		prop_gb_append(&gb, line_start, cur - line_start);
	}

	if (!found && val) {
		if (gb.len > 0 && gb.data[gb.len - 1] != '\n') {
			prop_gb_append(&gb, "\n", 1);
		}
		prop_gb_append(&gb, key, klen);
		prop_gb_append(&gb, " = \"", 4);
		prop_gb_append(&gb, val, strlen(val));
		prop_gb_append(&gb, "\"\n", 2);
	}

	if (out_sz) *out_sz = gb.len;
	return gb.data ? gb.data : xstrdup("");
}

static char *cmdline_buffer_set_param(const char *cmdline, const char *key, const char *val)
{
	char *dup = xstrdup(cmdline ? cmdline : "");
	char **tokens = NULL;
	size_t cap = 32, count = 0;
	char *tok, *saveptr;
	size_t klen = strlen(key);
	bool found = false;
	size_t i;
	struct prop_grow_buf gb = { NULL, 0, 0 };

	tokens = xmalloc(cap * sizeof(char *));
	tok = strtok_r(dup, " \t\r\n", &saveptr);
	while (tok) {
		if (count >= cap) {
			cap *= 2;
			tokens = xrealloc(tokens, cap * sizeof(char *));
		}
		tokens[count++] = xstrdup(tok);
		tok = strtok_r(NULL, " \t\r\n", &saveptr);
	}
	free(dup);

	for (i = 0; i < count; i++) {
		if (!tokens[i]) continue;
		if (strcmp(tokens[i], key) == 0 ||
		    (strncmp(tokens[i], key, klen) == 0 && tokens[i][klen] == '=')) {
			free(tokens[i]);
			tokens[i] = NULL;
			if (val) {
				char tmp[512];
				snprintf(tmp, sizeof(tmp), "%s=%s", key, val);
				tokens[i] = xstrdup(tmp);
				found = true;
			}
		}
	}

	if (!found && val) {
		char tmp[512];
		if (count >= cap) {
			cap += 16;
			tokens = xrealloc(tokens, cap * sizeof(char *));
		}
		snprintf(tmp, sizeof(tmp), "%s=%s", key, val);
		tokens[count++] = xstrdup(tmp);
	}

	for (i = 0; i < count; i++) {
		if (tokens[i]) {
			if (gb.len > 0) prop_gb_append(&gb, " ", 1);
			prop_gb_append(&gb, tokens[i], strlen(tokens[i]));
			free(tokens[i]);
		}
	}
	free(tokens);

	return gb.data ? gb.data : xstrdup("");
}

struct build_flag_changes {
	const char *build_type;      /* e.g. "user", "userdebug", "eng", or NULL if unchanged */
	const char *debuggable;      /* e.g. "1", "0", or NULL if unchanged */
	const char *secure;          /* e.g. "1", "0", or NULL if unchanged */
	const char *adb_secure;      /* e.g. "1", "0", or NULL if unchanged */
	const char *perf_harden;     /* e.g. "1", "0", or NULL if unchanged */
	const char *cmd_debuggable;  /* e.g. "1", "0", or NULL if unchanged */
	const char *cmd_devkmsg;     /* e.g. "on", or NULL if unchanged */
};

static int magiskboot_modify_flags_core(const char *target, bool live,
                                        const struct build_flag_changes *changes,
                                        const char *out_file)
{
	char discovered_boot[PATH_MAX];
	char abs_target[PATH_MAX];
	char abs_final_dest[PATH_MAX];
	char old_cwd[512];
	char tmp_dir[256];
	char repacked_img[PATH_MAX];
	int ret = 0;
	bool is_bdev = false;
	const char *final_dest = NULL;

	if (!target || live) {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		target = discovered_boot;
		live = true;
		printf("[+] Target Live Boot Partition: %s\n", target);
	} else {
		printf("[+] Target Boot Image: %s\n", target);
	}

	if (realpath(target, abs_target)) {
		target = abs_target;
	}

	is_bdev = is_block_device_node(target);
	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}

	if (live || is_bdev) {
		final_dest = target;
	} else if (out_file) {
		if (out_file[0] != '/') {
			snprintf(abs_final_dest, sizeof(abs_final_dest), "%s/%s", old_cwd, out_file);
			final_dest = abs_final_dest;
		} else {
			final_dest = out_file;
		}
	} else {
		final_dest = target;
	}

	safe_strncpy(tmp_dir, "/tmp/mb_bflags_XXXXXX", sizeof(tmp_dir));
	if (!mkdtemp(tmp_dir)) {
		bb_perror_msg("failed to create temporary directory '%s'", tmp_dir);
		return 1;
	}

	printf("[*] Unpacking boot image to patch build flags: %s...\n", target);
	chdir(tmp_dir);
	if (magiskboot_unpack(target, true, false, false, false) != 0) {
		bb_error_msg("failed to unpack boot image '%s'", target);
		ret = 1;
		goto cleanup;
	}

	/* 1. Modify HEADER_FILE (cmdline) */
	if (access(HEADER_FILE, R_OK) == 0) {
		FILE *hfp = fopen(HEADER_FILE, "r");
		struct prop_grow_buf hbuf = { NULL, 0, 0 };
		char *hline;

		if (hfp) {
			while ((hline = xmalloc_fgetline(hfp)) != NULL) {
				if (strncmp(hline, "cmdline=", 8) == 0) {
					char *cmdline = hline + 8;
					char *new_cmd = NULL;

					if (changes->cmd_debuggable) {
						new_cmd = cmdline_buffer_set_param(cmdline, "androidboot.debuggable", changes->cmd_debuggable);
					} else {
						new_cmd = xstrdup(cmdline);
					}

					if (changes->cmd_devkmsg) {
						char *tmp_cmd = cmdline_buffer_set_param(new_cmd, "printk.devkmsg", changes->cmd_devkmsg);
						free(new_cmd);
						new_cmd = tmp_cmd;
					} else if (changes->build_type && strcmp(changes->build_type, "user") == 0) {
						char *tmp_cmd = cmdline_buffer_set_param(new_cmd, "printk.devkmsg", NULL);
						free(new_cmd);
						new_cmd = tmp_cmd;
					}

					prop_gb_append(&hbuf, "cmdline=", 8);
					prop_gb_append(&hbuf, new_cmd, strlen(new_cmd));
					prop_gb_append(&hbuf, "\n", 1);
					printf("  [+] Patched boot header cmdline: %s\n", new_cmd);
					free(new_cmd);
				} else {
					prop_gb_append(&hbuf, hline, strlen(hline));
					prop_gb_append(&hbuf, "\n", 1);
				}
				free(hline);
			}
			fclose(hfp);

			if (hbuf.data) {
				FILE *wfp = fopen(HEADER_FILE, "w");
				if (wfp) {
					fwrite(hbuf.data, 1, hbuf.len, wfp);
					fclose(wfp);
				}
				free(hbuf.data);
			}
		}
	}

	/* 2. Modify BOOTCONFIG_FILE if present */
	if (access(BOOTCONFIG_FILE, R_OK) == 0 && changes->cmd_debuggable) {
		int bcfd = open(BOOTCONFIG_FILE, O_RDONLY);
		if (bcfd >= 0) {
			struct stat st;
			if (fstat(bcfd, &st) == 0 && st.st_size > 0) {
				char *bc_buf = xmalloc(st.st_size + 1);
				if (full_read(bcfd, bc_buf, st.st_size) == st.st_size) {
					size_t new_sz = 0;
					char *new_bc = bootconfig_buffer_set(bc_buf, st.st_size,
					                                     "androidboot.debuggable",
					                                     changes->cmd_debuggable,
					                                     &new_sz);
					close(bcfd);
					bcfd = -1;
					if (new_bc) {
						FILE *bcfp = fopen(BOOTCONFIG_FILE, "w");
						if (bcfp) {
							fwrite(new_bc, 1, new_sz, bcfp);
							fclose(bcfp);
							printf("  [+] Patched bootconfig: androidboot.debuggable = \"%s\"\n", changes->cmd_debuggable);
						}
						free(new_bc);
					}
				}
				free(bc_buf);
			}
			if (bcfd >= 0) close(bcfd);
		}
	}

	/* 3. Modify Ramdisk Properties */
	if (access(RAMDISK_FILE, R_OK) == 0) {
		cpio_node_t *head = cpio_read_all(RAMDISK_FILE);
		if (head) {
			cpio_node_t *cur;
			bool prop_found = false;

			for (cur = head; cur; cur = cur->next) {
				if (!cur->data || cur->filesize == 0) continue;
				if (strcmp(cur->name, "default.prop") == 0 ||
				    strcmp(cur->name, "prop.default") == 0 ||
				    strcmp(cur->name, "system/etc/prop.default") == 0 ||
				    strcmp(cur->name, "vendor/default.prop") == 0 ||
				    strcmp(cur->name, "vendor/etc/prop.default") == 0) {
					char *data_str = (char *)cur->data;
					size_t dsz = cur->filesize;
					char *new_data = NULL;
					size_t nsz = 0;
					prop_found = true;

					if (changes->build_type) {
						new_data = property_buffer_set(data_str, dsz, "ro.build.type", changes->build_type, &nsz);
						if (data_str != cur->data) free(data_str);
						data_str = new_data; dsz = nsz;
					}
					if (changes->debuggable) {
						new_data = property_buffer_set(data_str, dsz, "ro.debuggable", changes->debuggable, &nsz);
						if (data_str != cur->data) free(data_str);
						data_str = new_data; dsz = nsz;
					}
					if (changes->secure) {
						new_data = property_buffer_set(data_str, dsz, "ro.secure", changes->secure, &nsz);
						if (data_str != cur->data) free(data_str);
						data_str = new_data; dsz = nsz;
					}
					if (changes->adb_secure) {
						new_data = property_buffer_set(data_str, dsz, "ro.adb.secure", changes->adb_secure, &nsz);
						if (data_str != cur->data) free(data_str);
						data_str = new_data; dsz = nsz;
					}
					if (changes->perf_harden) {
						new_data = property_buffer_set(data_str, dsz, "security.perf_harden", changes->perf_harden, &nsz);
						if (data_str != cur->data) free(data_str);
						data_str = new_data; dsz = nsz;
					}

					if (data_str != cur->data) {
						free(cur->data);
						cur->data = data_str;
						cur->filesize = dsz;
						printf("  [+] Patched ramdisk property file: %s\n", cur->name);
					}
				}
			}

			if (!prop_found) {
				/* Create prop.default in ramdisk root */
				struct prop_grow_buf pgb = { NULL, 0, 0 };
				if (changes->build_type) {
					prop_gb_append(&pgb, "ro.build.type=", 14);
					prop_gb_append(&pgb, changes->build_type, strlen(changes->build_type));
					prop_gb_append(&pgb, "\n", 1);
				}
				if (changes->debuggable) {
					prop_gb_append(&pgb, "ro.debuggable=", 14);
					prop_gb_append(&pgb, changes->debuggable, strlen(changes->debuggable));
					prop_gb_append(&pgb, "\n", 1);
				}
				if (changes->secure) {
					prop_gb_append(&pgb, "ro.secure=", 10);
					prop_gb_append(&pgb, changes->secure, strlen(changes->secure));
					prop_gb_append(&pgb, "\n", 1);
				}
				if (changes->adb_secure) {
					prop_gb_append(&pgb, "ro.adb.secure=", 14);
					prop_gb_append(&pgb, changes->adb_secure, strlen(changes->adb_secure));
					prop_gb_append(&pgb, "\n", 1);
				}
				if (changes->perf_harden) {
					prop_gb_append(&pgb, "security.perf_harden=", 21);
					prop_gb_append(&pgb, changes->perf_harden, strlen(changes->perf_harden));
					prop_gb_append(&pgb, "\n", 1);
				}
				if (pgb.data) {
					cpio_set_file(&head, "prop.default", 0100644, pgb.data, pgb.len);
					printf("  [+] Injected new ramdisk property file: prop.default\n");
				}
			}

			printf("[*] Repacking ramdisk CPIO archive...\n");
			if (cpio_write_all(RAMDISK_FILE, head) != 0) {
				bb_error_msg("failed to write patched ramdisk CPIO archive");
				cpio_free_all(head);
				ret = 1;
				goto cleanup;
			}
			cpio_free_all(head);

			unlink("ramdisk.cpio.gz");
			unlink("ramdisk.cpio.xz");
			unlink("ramdisk.cpio.lz4");
			unlink("ramdisk.cpio.bz2");
			unlink("ramdisk.cpio.zst");
		}
	} else {
		printf("[-] Notice: No ramdisk present in boot image (system-as-root mode)\n");
	}

	/* 4. Repack Boot Image */
	printf("[*] Repacking boot image...\n");
	snprintf(repacked_img, sizeof(repacked_img), "%s/new-boot.img", tmp_dir);
	if (magiskboot_repack(target, repacked_img, false) != 0) {
		bb_error_msg("failed to repack boot image");
		ret = 1;
		goto cleanup;
	}

	/* 5. Flash or Save */
	if (live || is_bdev) {
		printf("[*] Flashing patched boot image to %s...\n", target);
		if (flash_partition_image(repacked_img, target, FLASH_OPT_VERIFY_READ) != 0) {
			bb_error_msg("failed to flash updated boot image to %s", target);
			ret = 1;
			goto cleanup;
		}
		printf("[✓] SUCCESS: Flashed patched build configuration directly to %s\n", target);
	} else {
		chdir(old_cwd);
		if (copy_file(repacked_img, final_dest, FILEUTILS_FORCE) != 0) {
			bb_perror_msg("failed to write output image '%s'", final_dest);
			ret = 1;
			goto cleanup;
		}
		printf("[✓] SUCCESS: Updated build configuration inside boot image '%s'\n", final_dest);
	}

cleanup:
	chdir(old_cwd);
	remove_file(tmp_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}

static int magiskboot_build_status_op(int argc, char **argv)
{
	const char *target = NULL;
	char discovered_boot[PATH_MAX];
	boot_img_t boot;
	char cmdline_buf[4096];
	char prop_type[64] = "unknown";
	char prop_debuggable[32] = "unknown";
	char prop_secure[32] = "unknown";
	char prop_adb_secure[32] = "unknown";
	char prop_perf_harden[32] = "unknown";
	char cmd_debuggable[32] = "not set";
	char cmd_selinux[32] = "not set";
	char cmd_force_normal[32] = "not set";
	char cmd_devkmsg[32] = "not set";
	char bcfg_debuggable[32] = "not set";
	bool has_bootconfig = false;
	bool has_ramdisk = false;
	int prop_files_found = 0;
	cpio_node_t *head = NULL;
	cpio_node_t *cur;
	char tmp_cpio[PATH_MAX];
	int c_fd;

	if (argc >= 3 && strcmp(argv[2], "--live") != 0 && argv[2][0] != '-') {
		target = argv[2];
	}

	if (!target || (argc >= 3 && strcmp(argv[2], "--live") == 0)) {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		target = discovered_boot;
		printf("[+] Inspecting Live Target Boot: %s\n", target);
	} else {
		printf("[+] Inspecting Target Boot Image: %s\n", target);
	}

	if (!boot_img_parse_full(&boot, target, true)) {
		bb_error_msg("failed to parse boot image header from '%s'", target);
		return 1;
	}

	/* 1. Extract and parse kernel cmdline */
	memset(cmdline_buf, 0, sizeof(cmdline_buf));
	switch (boot.hdr.type) {
	case BOOT_HDR_V0:
	case BOOT_HDR_V1:
	case BOOT_HDR_V2: {
		struct boot_img_hdr_v0 *h0 = (struct boot_img_hdr_v0 *)boot.hdr.raw;
		snprintf(cmdline_buf, sizeof(cmdline_buf), "%.*s %.*s",
		         BOOT_ARGS_SIZE, h0->cmdline,
		         BOOT_EXTRA_ARGS_SIZE, h0->extra_cmdline);
		break;
	}
	case BOOT_HDR_V3:
	case BOOT_HDR_V4: {
		struct boot_img_hdr_v3 *h3 = (struct boot_img_hdr_v3 *)boot.hdr.raw;
		snprintf(cmdline_buf, sizeof(cmdline_buf), "%.*s",
		         (int)sizeof(h3->cmdline), h3->cmdline);
		break;
	}
	case BOOT_HDR_VND_V3:
	case BOOT_HDR_VND_V4: {
		struct boot_img_hdr_vnd_v3 *hv = (struct boot_img_hdr_vnd_v3 *)boot.hdr.raw;
		snprintf(cmdline_buf, sizeof(cmdline_buf), "%.*s",
		         (int)sizeof(hv->cmdline), hv->cmdline);
		break;
	}
	default:
		break;
	}
	trim(cmdline_buf);

	{
		char *tok, *saveptr;
		char *dup = xstrdup(cmdline_buf);
		tok = strtok_r(dup, " \t\r\n", &saveptr);
		while (tok) {
			if (strncmp(tok, "androidboot.debuggable=", 23) == 0) {
				safe_strncpy(cmd_debuggable, tok + 23, sizeof(cmd_debuggable));
			} else if (strncmp(tok, "androidboot.selinux=", 20) == 0) {
				safe_strncpy(cmd_selinux, tok + 20, sizeof(cmd_selinux));
			} else if (strncmp(tok, "androidboot.force_normal_boot=", 30) == 0) {
				safe_strncpy(cmd_force_normal, tok + 30, sizeof(cmd_force_normal));
			} else if (strncmp(tok, "printk.devkmsg=", 15) == 0) {
				safe_strncpy(cmd_devkmsg, tok + 15, sizeof(cmd_devkmsg));
			}
			tok = strtok_r(NULL, " \t\r\n", &saveptr);
		}
		free(dup);
	}

	/* 2. Bootconfig inspection (Header v4) */
	if (boot.bootconfig && boot.bootconfig_size > 0) {
		has_bootconfig = true;
		{
			const char *bc = (const char *)boot.bootconfig;
			const char *bc_end = bc + boot.bootconfig_size;
			while (bc < bc_end) {
				const char *le = memchr(bc, '\n', bc_end - bc);
				if (!le) le = bc_end;
				while (bc < le && (*bc == ' ' || *bc == '\t')) bc++;
				if (bc < le && strncmp(bc, "androidboot.debuggable", 22) == 0) {
					const char *eq = memchr(bc, '=', le - bc);
					if (eq) {
						const char *vs = eq + 1;
						const char *ve;
						while (vs < le && (*vs == ' ' || *vs == '\t' || *vs == '"')) vs++;
						ve = le;
						while (ve > vs && (*(ve - 1) == '\r' || *(ve - 1) == ' ' || *(ve - 1) == '\t' || *(ve - 1) == '"')) ve--;
						if (ve > vs) {
							size_t l = ve - vs;
							if (l >= sizeof(bcfg_debuggable)) l = sizeof(bcfg_debuggable) - 1;
							memcpy(bcfg_debuggable, vs, l);
							bcfg_debuggable[l] = '\0';
						}
					}
				}
				bc = (le < bc_end) ? le + 1 : bc_end;
			}
		}
	}

	/* 3. Ramdisk properties inspection */
	if (boot.ramdisk && boot.ramdisk_size > 0) {
		has_ramdisk = true;
		safe_strncpy(tmp_cpio, "/tmp/mb_bstat_XXXXXX", sizeof(tmp_cpio));
		c_fd = xmkstemp(tmp_cpio);
		if (boot_fmt_compressed(boot.r_fmt)) {
			bb_decompress_data(boot.r_fmt, boot.ramdisk, boot.ramdisk_size, c_fd);
		} else {
			full_write(c_fd, boot.ramdisk, boot.ramdisk_size);
		}
		close(c_fd);

		head = cpio_read_all(tmp_cpio);
		unlink(tmp_cpio);

		if (head) {
			for (cur = head; cur; cur = cur->next) {
				if (!cur->data || cur->filesize == 0) continue;
				if (strcmp(cur->name, "default.prop") == 0 ||
				    strcmp(cur->name, "prop.default") == 0 ||
				    strcmp(cur->name, "system/etc/prop.default") == 0 ||
				    strcmp(cur->name, "vendor/default.prop") == 0 ||
				    strcmp(cur->name, "vendor/etc/prop.default") == 0) {
					char val[64];
					prop_files_found++;
					if (property_buffer_get((const char *)cur->data, cur->filesize, "ro.build.type", val, sizeof(val)))
						safe_strncpy(prop_type, val, sizeof(prop_type));
					if (property_buffer_get((const char *)cur->data, cur->filesize, "ro.debuggable", val, sizeof(val)))
						safe_strncpy(prop_debuggable, val, sizeof(prop_debuggable));
					if (property_buffer_get((const char *)cur->data, cur->filesize, "ro.secure", val, sizeof(val)))
						safe_strncpy(prop_secure, val, sizeof(prop_secure));
					if (property_buffer_get((const char *)cur->data, cur->filesize, "ro.adb.secure", val, sizeof(val)))
						safe_strncpy(prop_adb_secure, val, sizeof(prop_adb_secure));
					if (property_buffer_get((const char *)cur->data, cur->filesize, "security.perf_harden", val, sizeof(val)))
						safe_strncpy(prop_perf_harden, val, sizeof(prop_perf_harden));
				}
			}
			cpio_free_all(head);
		}
	}

	boot_img_free(&boot);

	/* 4. Display Report */
	printf("======================================================================\n");
	printf("  Android Production & Debug Configuration Report\n");
	printf("======================================================================\n");
	printf("  • Target Path         : %s\n", target);
	printf("  • Ramdisk Status      : %s (found %d prop file%s)\n",
	       has_ramdisk ? "Present" : "None (System-as-root / DLKM-only)",
	       prop_files_found, (prop_files_found == 1) ? "" : "s");
	if (has_bootconfig) {
		printf("  • Bootconfig Status   : Present (%s)\n", bcfg_debuggable);
	}
	printf("----------------------------------------------------------------------\n");
	printf("  Kernel Command Line & Bootconfig Parameters:\n");
	printf("    - androidboot.debuggable   : %s\n", cmd_debuggable);
	printf("    - androidboot.selinux      : %s\n", cmd_selinux);
	printf("    - androidboot.force_normal : %s\n", cmd_force_normal);
	printf("    - printk.devkmsg           : %s\n", cmd_devkmsg);
	if (has_bootconfig) {
		printf("    - bootconfig debuggable    : %s\n", bcfg_debuggable);
	}
	printf("----------------------------------------------------------------------\n");
	printf("  Ramdisk Build Properties (%s):\n", prop_files_found ? "Resolved" : "Default / Absent");
	printf("    - ro.build.type            : %s\n", prop_type);
	printf("    - ro.debuggable            : %s\n", prop_debuggable);
	printf("    - ro.secure                : %s\n", prop_secure);
	printf("    - ro.adb.secure            : %s\n", prop_adb_secure);
	printf("    - security.perf_harden     : %s\n", prop_perf_harden);
	printf("======================================================================\n");

	/* 5. Classification Assessment */
	{
		bool is_userdebug = false;
		bool is_eng = false;

		if (strcmp(prop_type, "eng") == 0 || (strcmp(prop_debuggable, "1") == 0 && strcmp(prop_secure, "0") == 0)) {
			is_eng = true;
		} else if (strcmp(prop_type, "userdebug") == 0 || strcmp(prop_debuggable, "1") == 0 || strcmp(cmd_debuggable, "1") == 0) {
			is_userdebug = true;
		}

		printf("  [★] ACTIVE BUILD PERSONALITY: ");
		if (is_eng) {
			printf("ENG (Engineering / Insecure Development)\n");
			printf("      - ADB Root           : Elevated by default (UID 0 / GID 0)\n");
			printf("      - ADB Authentication : INSECURE (No RSA device confirmation dialog)\n");
			printf("      - App Debugging      : Unrestricted JDWP debugging enabled\n");
			printf("      - SELinux Permissive : Permitted at boot\n");
		} else if (is_userdebug) {
			printf("USERDEBUG (User Debug / Root Available)\n");
			printf("      - ADB Root           : Available on demand via 'adb root'\n");
			printf("      - ADB Authentication : SECURE (Requires RSA device confirmation)\n");
			printf("      - App Debugging      : JDWP debugging enabled\n");
			printf("      - SELinux Permissive : Permitted via kernel cmdline\n");
		} else {
			printf("USER (Strict Production)\n");
			printf("      - ADB Root           : FORBIDDEN ('adbd cannot run as root in production builds')\n");
			printf("      - ADB Authentication : SECURE (Enforced RSA dialog)\n");
			printf("      - App Debugging      : Restricted to android:debuggable=true apps\n");
			printf("      - SELinux Permissive : LOCKED (Enforcing mandatory by /init)\n");
		}
	}
	printf("======================================================================\n");

	return 0;
}

static int magiskboot_set_build_type_op(int argc, char **argv)
{
	const char *target = NULL;
	const char *profile = NULL;
	const char *out_file = NULL;
	bool live = false;
	struct build_flag_changes changes;
	int i;

	memset(&changes, 0, sizeof(changes));

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "user") == 0 ||
		           strcmp(argv[i], "userdebug") == 0 ||
		           strcmp(argv[i], "eng") == 0) {
			profile = argv[i];
		} else if (!target) {
			target = argv[i];
		} else if (!out_file) {
			out_file = argv[i];
		}
	}

	if (!profile) {
		bb_error_msg("missing build profile (must be 'user', 'userdebug', or 'eng')");
		bb_error_msg("usage: aimg --set-build-type <boot.img|--live> <user|userdebug|eng> [out.img]");
		return 1;
	}

	if (strcmp(profile, "user") == 0) {
		changes.build_type = "user";
		changes.debuggable = "0";
		changes.secure = "1";
		changes.adb_secure = "1";
		changes.perf_harden = "1";
		changes.cmd_debuggable = "0";
		changes.cmd_devkmsg = NULL;
	} else if (strcmp(profile, "userdebug") == 0) {
		changes.build_type = "userdebug";
		changes.debuggable = "1";
		changes.secure = "1";
		changes.adb_secure = "1";
		changes.perf_harden = "0";
		changes.cmd_debuggable = "1";
		changes.cmd_devkmsg = "on";
	} else if (strcmp(profile, "eng") == 0) {
		changes.build_type = "eng";
		changes.debuggable = "1";
		changes.secure = "0";
		changes.adb_secure = "0";
		changes.perf_harden = "0";
		changes.cmd_debuggable = "1";
		changes.cmd_devkmsg = "on";
	}

	return magiskboot_modify_flags_core(target, live, &changes, out_file);
}

static int magiskboot_set_flag_op(int argc, char **argv, const char *flag_name)
{
	const char *target = NULL;
	const char *val_str = NULL;
	const char *out_file = NULL;
	bool live = false;
	bool enable;
	struct build_flag_changes changes;
	int i;

	memset(&changes, 0, sizeof(changes));

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "1") == 0 || strcmp(argv[i], "0") == 0 ||
		           strcmp(argv[i], "true") == 0 || strcmp(argv[i], "false") == 0 ||
		           strcmp(argv[i], "on") == 0 || strcmp(argv[i], "off") == 0 ||
		           strcmp(argv[i], "enable") == 0 || strcmp(argv[i], "disable") == 0) {
			val_str = argv[i];
		} else if (!target) {
			target = argv[i];
		} else if (!out_file) {
			out_file = argv[i];
		}
	}

	if (!val_str) {
		bb_error_msg("missing flag value (1/0, on/off, true/false)");
		bb_error_msg("usage: aimg --set-%s <boot.img|--live> <1|0> [out.img]", flag_name);
		return 1;
	}

	enable = (strcmp(val_str, "1") == 0 || strcmp(val_str, "true") == 0 ||
	          strcmp(val_str, "on") == 0 || strcmp(val_str, "enable") == 0);

	if (strcmp(flag_name, "debuggable") == 0) {
		changes.debuggable = enable ? "1" : "0";
		changes.cmd_debuggable = enable ? "1" : "0";
		if (enable) {
			changes.build_type = "userdebug";
			changes.perf_harden = "0";
			changes.cmd_devkmsg = "on";
		} else {
			changes.build_type = "user";
			changes.perf_harden = "1";
		}
	} else if (strcmp(flag_name, "insecure-adb") == 0) {
		if (enable) {
			changes.secure = "0";
			changes.adb_secure = "0";
		} else {
			changes.secure = "1";
			changes.adb_secure = "1";
		}
	}

	return magiskboot_modify_flags_core(target, live, &changes, out_file);
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
		"-i\0"
		"--info\0"
		"info\0"

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
		"--set-ramdisk\0"
		"set-ramdisk\0"
		"--replace-ramdisk\0"
		"replace-ramdisk\0"
		"--extract-ramdisk\0"
		"extract-ramdisk\0"
		"--get-ramdisk\0"
		"get-ramdisk\0"
		"--ramdisk\0"
		"ramdisk\0"
		"--ramdisk-ls\0"
		"ramdisk-ls\0"
		"--ramdisk-cat\0"
		"ramdisk-cat\0"
		"--ramdisk-stat\0"
		"ramdisk-stat\0"
		"--ramdisk-test\0"
		"ramdisk-test\0"

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

		/* AnyKernel Engine */
		"--flash-kernel\0"
		"flash-kernel\0"
		"--set-kernel\0"
		"set-kernel\0"
		"--patch-cmdline\0"
		"patch-cmdline\0"
		"--patch-fstab\0"
		"patch-fstab\0"

		/* Android Build Flags & Production Personality Engine */
		"--build-status\0"
		"build-status\0"
		"--set-build-type\0"
		"set-build-type\0"
		"--build-type\0"
		"build-type\0"
		"--set-debuggable\0"
		"set-debuggable\0"
		"--set-insecure-adb\0"
		"set-insecure-adb\0"

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
		CMD_i,
		CMD_info,
		CMD_info_no_dash,

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
		CMD_set_ramdisk,
		CMD_set_ramdisk_no_dash,
		CMD_replace_ramdisk,
		CMD_replace_ramdisk_no_dash,
		CMD_extract_ramdisk,
		CMD_extract_ramdisk_no_dash,
		CMD_get_ramdisk,
		CMD_get_ramdisk_no_dash,
		CMD_ramdisk,
		CMD_ramdisk_no_dash,
		CMD_ramdisk_ls,
		CMD_ramdisk_ls_no_dash,
		CMD_ramdisk_cat,
		CMD_ramdisk_cat_no_dash,
		CMD_ramdisk_stat,
		CMD_ramdisk_stat_no_dash,
		CMD_ramdisk_test,
		CMD_ramdisk_test_no_dash,

		CMD_dist,
		CMD_dist_no_dash,
		CMD_zip,
		CMD_zip_no_dash,

		CMD_kernel,
		CMD_kernel_no_dash,
		CMD_module,
		CMD_module_no_dash,

		CMD_flash_kernel,
		CMD_flash_kernel_no_dash,
		CMD_set_kernel,
		CMD_set_kernel_no_dash,
		CMD_patch_cmdline,
		CMD_patch_cmdline_no_dash,
		CMD_patch_fstab,
		CMD_patch_fstab_no_dash,

		CMD_build_status,
		CMD_build_status_no_dash,
		CMD_set_build_type,
		CMD_set_build_type_no_dash,
		CMD_build_type,
		CMD_build_type_no_dash,
		CMD_set_debuggable,
		CMD_set_debuggable_no_dash,
		CMD_set_insecure_adb,
		CMD_set_insecure_adb_no_dash,

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

	case CMD_i:
	case CMD_info:
	case CMD_info_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_info_image(argv[2]);

	case CMD_mod_info:
	case CMD_mod_info_no_dash:
		return module_info_file((argc >= 3) ? argv[2] : resolve_default_module_path(argc, argv, 2),
		                        (argc >= 4) ? argv[3] : NULL);

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

	case CMD_set_ramdisk:
	case CMD_set_ramdisk_no_dash:
	case CMD_replace_ramdisk:
	case CMD_replace_ramdisk_no_dash:
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_set_ramdisk_op(argc, argv);

	case CMD_extract_ramdisk:
	case CMD_extract_ramdisk_no_dash:
	case CMD_get_ramdisk:
	case CMD_get_ramdisk_no_dash:
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_extract_ramdisk_op(argc, argv);

	case CMD_ramdisk:
	case CMD_ramdisk_no_dash:
		if (argc >= 3 && (strcmp(argv[2], "extract") == 0 || strcmp(argv[2], "dump") == 0 || strcmp(argv[2], "get") == 0)) {
			return magiskboot_extract_ramdisk_op(argc - 1, argv + 1);
		}
		if (argc >= 3 && (strcmp(argv[2], "set") == 0 || strcmp(argv[2], "replace") == 0 || strcmp(argv[2], "inject") == 0)) {
			return magiskboot_set_ramdisk_op(argc - 1, argv + 1);
		}
		if (argc >= 4 && (strcmp(argv[3], "ls") == 0 || strcmp(argv[3], "cat") == 0 || strcmp(argv[3], "chmod") == 0 ||
		                  strcmp(argv[3], "add") == 0 || strcmp(argv[3], "rm") == 0 || strcmp(argv[3], "mkdir") == 0 ||
		                  strcmp(argv[3], "stat") == 0 || strcmp(argv[3], "test") == 0)) {
			char *cpio_argv[32];
			int cpio_argc = 0;
			int k;
			cpio_argv[cpio_argc++] = argv[0];
			cpio_argv[cpio_argc++] = (char *)"--cpio";
			for (k = 2; k < argc && cpio_argc < 31; k++) {
				cpio_argv[cpio_argc++] = argv[k];
			}
			cpio_argv[cpio_argc] = NULL;
			return magiskboot_cpio(cpio_argc, cpio_argv);
		}
		if (argc < 3 && !strstr(cmd, "live")) bb_show_usage();
		return magiskboot_set_ramdisk_op(argc, argv);

	case CMD_ramdisk_ls:
	case CMD_ramdisk_ls_no_dash: {
		char *cpio_argv[5];
		if (argc < 3) bb_show_usage();
		cpio_argv[0] = argv[0];
		cpio_argv[1] = (char *)"--cpio";
		cpio_argv[2] = argv[2];
		cpio_argv[3] = (char *)"ls";
		cpio_argv[4] = NULL;
		return magiskboot_cpio(4, cpio_argv);
	}

	case CMD_ramdisk_cat:
	case CMD_ramdisk_cat_no_dash: {
		char *cpio_argv[6];
		if (argc < 4) bb_show_usage();
		cpio_argv[0] = argv[0];
		cpio_argv[1] = (char *)"--cpio";
		cpio_argv[2] = argv[2];
		cpio_argv[3] = (char *)"cat";
		cpio_argv[4] = argv[3];
		cpio_argv[5] = NULL;
		return magiskboot_cpio(5, cpio_argv);
	}

	case CMD_ramdisk_stat:
	case CMD_ramdisk_stat_no_dash: {
		char *cpio_argv[6];
		if (argc < 4) bb_show_usage();
		cpio_argv[0] = argv[0];
		cpio_argv[1] = (char *)"--cpio";
		cpio_argv[2] = argv[2];
		cpio_argv[3] = (char *)"stat";
		cpio_argv[4] = argv[3];
		cpio_argv[5] = NULL;
		return magiskboot_cpio(5, cpio_argv);
	}

	case CMD_ramdisk_test:
	case CMD_ramdisk_test_no_dash: {
		char *cpio_argv[5];
		if (argc < 3) bb_show_usage();
		cpio_argv[0] = argv[0];
		cpio_argv[1] = (char *)"--cpio";
		cpio_argv[2] = argv[2];
		cpio_argv[3] = (char *)"test";
		cpio_argv[4] = NULL;
		return magiskboot_cpio(4, cpio_argv);
	}

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

	case CMD_flash_kernel:
	case CMD_flash_kernel_no_dash:
	case CMD_set_kernel:
	case CMD_set_kernel_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_flash_kernel_op(argc, argv);

	case CMD_patch_cmdline:
	case CMD_patch_cmdline_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_patch_cmdline_op(argc, argv);

	case CMD_patch_fstab:
	case CMD_patch_fstab_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_patch_fstab_op(argc, argv);

	case CMD_build_status:
	case CMD_build_status_no_dash:
		return magiskboot_build_status_op(argc, argv);

	case CMD_set_build_type:
	case CMD_set_build_type_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_set_build_type_op(argc, argv);

	case CMD_build_type:
	case CMD_build_type_no_dash:
		if (argc <= 3) {
			return magiskboot_build_status_op(argc, argv);
		}
		return magiskboot_set_build_type_op(argc, argv);

	case CMD_set_debuggable:
	case CMD_set_debuggable_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_set_flag_op(argc, argv, "debuggable");

	case CMD_set_insecure_adb:
	case CMD_set_insecure_adb_no_dash:
		if (argc < 3) bb_show_usage();
		return magiskboot_set_flag_op(argc, argv, "insecure-adb");

	case CMD_h:
	case CMD_help:
	case CMD_help_no_dash:
		if (subcmd == CMD_h && argc >= 3 && argv[2][0] != '-') {
			return magiskboot_info_image(argv[2]);
		}
		bb_show_usage();
		return 1;
	default:
		bb_show_usage();
		return 1;
	}
	return 1;
}
