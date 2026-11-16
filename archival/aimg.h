/* vi: set sw=4 ts=4: */
/*
 * aimg.h — Android Image Tool Architecture & Constants for BusyBox
 *
 * Implements standard AOSP boot headers (v0, v1, v2, v3, v4), Vendor Boot headers
 * (v3, v4), Samsung PXA headers, OEM loader extensions, and AVB 2.0 structures.
 * Conforms to Linux Kernel Coding Style & ISO C99/C11 standards.
 */

#ifndef AIMG_H
#define AIMG_H 1

#include "libbb.h"

#define HEADER_FILE         "header"
#define KERNEL_FILE         "kernel"
#define RAMDISK_FILE        "ramdisk.cpio"
#define VND_RAMDISK_DIR     "vendor_ramdisk"
#define SECOND_FILE         "second"
#define EXTRA_FILE          "extra"
#define KER_DTB_FILE        "kernel_dtb"
#define RECV_DTBO_FILE      "recovery_dtbo"
#define DTB_FILE            "dtb"
#define BOOTCONFIG_FILE     "bootconfig"

#define PADDING             15
#define SHA256_DIGEST_SIZE  32
#define SHA_DIGEST_SIZE     20

#define BOOT_MAGIC_SIZE                             8
#define VENDOR_BOOT_MAGIC_SIZE                      8
#define BOOT_MAGIC                                  "ANDROID!"
#define VENDOR_BOOT_MAGIC                           "VNDRBOOT"
#define BOOT_NAME_SIZE                              16
#define BOOT_ID_SIZE                                32
#define BOOT_ARGS_SIZE                              512
#define BOOT_EXTRA_ARGS_SIZE                        1024
#define VENDOR_BOOT_ARGS_SIZE                       2048
#define VENDOR_RAMDISK_NAME_SIZE                    32
#define VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE    16

#define VENDOR_RAMDISK_TYPE_NONE        0
#define VENDOR_RAMDISK_TYPE_PLATFORM    1
#define VENDOR_RAMDISK_TYPE_RECOVERY    2
#define VENDOR_RAMDISK_TYPE_DLKM        3

#define DTB_MAGIC               "\xd0\x0d\xfe\xed"
#define LG_BUMP_MAGIC           "\x41\xa9\xe4\x67\x74\x4d\x1d\x1b\xa4\x29\xf2\xec\xea\x65\x52\x79"
#define SEANDROID_MAGIC         "SEANDROIDENFORCE"
#define NOOKHD_RL_MAGIC         "Red Loader"
#define NOOKHD_GL_MAGIC         "Green Loader"
#define NOOKHD_GR_MAGIC         "Green Recovery"
#define NOOKHD_EB_MAGIC         "eMMC boot.img+secondloader"
#define NOOKHD_ER_MAGIC         "eMMC recovery.img+secondloader"
#define NOOKHD_PRE_HEADER_SZ    1048576
#define ACCLAIM_MAGIC           "BauwksBoot"
#define ACCLAIM_PRE_HEADER_SZ   262144
#define AMONET_MICROLOADER_MAGIC "microloader"
#define AMONET_MICROLOADER_SZ   1024
#define AVB_FOOTER_MAGIC        "AVBf"
#define AVB_MAGIC               "AVB0"

#define MTK_HEADER_SIZE         512
#define DHTB_HEADER_SIZE        512
#define BLOB_HEADER_SIZE        512

/*
 * File Format Enumeration
 */
typedef enum {
    BOOT_FMT_UNKNOWN = 0,
    BOOT_FMT_CHROMEOS,
    BOOT_FMT_AOSP,
    BOOT_FMT_AOSP_VENDOR,
    BOOT_FMT_DHTB,
    BOOT_FMT_BLOB,
    BOOT_FMT_GZIP,
    BOOT_FMT_ZOPFLI,
    BOOT_FMT_XZ,
    BOOT_FMT_LZMA,
    BOOT_FMT_BZIP2,
    BOOT_FMT_LZ4,
    BOOT_FMT_LZ4_LEGACY,
    BOOT_FMT_LZ4_LG,
    BOOT_FMT_LZOP,
    BOOT_FMT_DTB,
    BOOT_FMT_ZIMAGE,
    BOOT_FMT_MTK,
} boot_format_t;

/*
 * Bitflags representing OEM loaders and boot image payload characteristics
 */
enum {
    BOOT_FLAG_MTK_KERNEL     = (1u << 0),
    BOOT_FLAG_MTK_RAMDISK    = (1u << 1),
    BOOT_FLAG_CHROMEOS       = (1u << 2),
    BOOT_FLAG_DHTB           = (1u << 3),
    BOOT_FLAG_SEANDROID      = (1u << 4),
    BOOT_FLAG_LG_BUMP        = (1u << 5),
    BOOT_FLAG_SHA256         = (1u << 6),
    BOOT_FLAG_BLOB           = (1u << 7),
    BOOT_FLAG_NOOKHD         = (1u << 8),
    BOOT_FLAG_ACCLAIM        = (1u << 9),
    BOOT_FLAG_AMONET         = (1u << 10),
    BOOT_FLAG_AVB1_SIGNED    = (1u << 11),
    BOOT_FLAG_AVB            = (1u << 12),
    BOOT_FLAG_ZIMAGE_KERNEL  = (1u << 13),
};

/*
 * AOSP Boot Image Header v0 (1632 bytes).
 */
struct boot_img_hdr_v0 {
    char magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t header_version;
    uint32_t os_version;
    char name[BOOT_NAME_SIZE];
    char cmdline[BOOT_ARGS_SIZE];
    char id[BOOT_ID_SIZE];
    char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

/*
 * AOSP Boot Image Header v1 (1648 bytes).
 */
struct boot_img_hdr_v1 {
    struct boot_img_hdr_v0 base;
    uint32_t recovery_dtbo_size;
    uint64_t recovery_dtbo_offset;
    uint32_t header_size;
} __attribute__((packed));

/*
 * AOSP Boot Image Header v2 (1660 bytes).
 */
struct boot_img_hdr_v2 {
    struct boot_img_hdr_v1 v1;
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed));

/*
 * AOSP Boot Image Header v3 (4096 bytes).
 */
struct boot_img_hdr_v3 {
    uint8_t magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;
    uint32_t ramdisk_size;
    uint32_t os_version;
    uint32_t header_size;
    uint32_t reserved[4];
    uint32_t header_version;
    char cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

/*
 * AOSP Boot Image Header v4 (4096 bytes).
 */
struct boot_img_hdr_v4 {
    struct boot_img_hdr_v3 v3;
    uint32_t signature_size;
} __attribute__((packed));

/*
 * Samsung PXA Header.
 */
struct boot_img_hdr_pxa {
    char magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t extra_size;
    uint32_t unknown;
    uint32_t tags_addr;
    uint32_t page_size;
    char name[24];
    char cmdline[BOOT_ARGS_SIZE];
    char id[BOOT_ID_SIZE];
    char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

/*
 * AOSP Vendor Boot Header v3 (2112 bytes).
 */
struct boot_img_hdr_vnd_v3 {
    uint8_t magic[BOOT_MAGIC_SIZE];
    uint32_t header_version;
    uint32_t page_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_addr;
    uint32_t ramdisk_size;
    char cmdline[VENDOR_BOOT_ARGS_SIZE];
    uint32_t tags_addr;
    char name[BOOT_NAME_SIZE];
    uint32_t header_size;
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed));

/*
 * AOSP Vendor Boot Header v4.
 */
struct boot_img_hdr_vnd_v4 {
    struct boot_img_hdr_vnd_v3 vnd_v3;
    uint32_t vendor_ramdisk_table_size;
    uint32_t vendor_ramdisk_table_entry_num;
    uint32_t vendor_ramdisk_table_entry_size;
    uint32_t bootconfig_size;
} __attribute__((packed));

/*
 * Vendor Ramdisk Table Entry (v4).
 */
struct vendor_ramdisk_table_entry_v4 {
    uint32_t ramdisk_size;
    uint32_t ramdisk_offset;
    uint32_t ramdisk_type;
    char ramdisk_name[VENDOR_RAMDISK_NAME_SIZE];
    uint32_t board_id[VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];
} __attribute__((packed));

/*
 * OEM Pre-headers: MediaTek, DHTB, Tegra BLOB
 */
struct mtk_hdr {
    uint32_t magic;         /* MTK magic (0x58881688) */
    uint32_t size;          /* Size of payload content */
    char name[32];          /* Kernel/RootFS identifier */
    uint8_t padding[472];   /* Pad out to exactly 512 bytes */
} __attribute__((packed));

struct dhtb_hdr {
    char magic[8];          /* "DHTB\x01\x00\x00\x00" */
    uint8_t checksum[40];   /* SHA256 / SHA1 */
    uint32_t size;          /* Length of payload following */
    uint8_t padding[460];   /* 512-byte header */
} __attribute__((packed));

struct blob_hdr {
    char magic[20];         /* "-SIGNED-BY-SIGNBLOB-" */
    uint8_t padding[492];   /* 512-byte alignment */
} __attribute__((packed));

/*
 * AVB 2.0 Structures
 */
#define AVB_FOOTER_MAGIC_LEN        4
#define AVB_MAGIC_LEN               4
#define AVB_RELEASE_STRING_SIZE     64
#define AVB_SHA256_DIGEST_SIZE      32
#define AVB_DESCRIPTOR_TAG_HASH     2

#define AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED       (1U << 0)
#define AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED   (1U << 1)

struct avb_footer {
    uint8_t magic[AVB_FOOTER_MAGIC_LEN];
    uint32_t version_major;
    uint32_t version_minor;
    uint64_t original_image_size;
    uint64_t vbmeta_offset;
    uint64_t vbmeta_size;
    uint8_t reserved[160];
} __attribute__((packed));

struct avb_vbmeta_image_header {
    uint8_t magic[AVB_MAGIC_LEN];
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptors_offset;
    uint64_t descriptors_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    uint8_t release_string[AVB_RELEASE_STRING_SIZE];
    uint8_t reserved[80];
} __attribute__((packed));

struct avb_descriptor {
    uint64_t tag;
    uint64_t num_bytes_following;
} __attribute__((packed));

struct avb_hash_descriptor {
    struct avb_descriptor parent;
    uint64_t image_size;
    uint8_t hash_algorithm[32];
    uint32_t partition_name_len;
    uint32_t salt_len;
    uint32_t digest_len;
    uint32_t flags;
    uint8_t reserved[60];
} __attribute__((packed));

/*
 * Dynamic Boot Header Type Enumeration
 */
typedef enum {
    BOOT_HDR_NONE = 0,
    BOOT_HDR_V0,
    BOOT_HDR_V1,
    BOOT_HDR_V2,
    BOOT_HDR_V3,
    BOOT_HDR_V4,
    BOOT_HDR_VND_V3,
    BOOT_HDR_VND_V4,
    BOOT_HDR_PXA
} boot_hdr_type_t;

typedef struct boot_dyn_hdr {
    boot_hdr_type_t type;
    void *raw;
    size_t raw_sz;
    uint32_t dummy32;
    uint64_t dummy64;
} boot_dyn_hdr_t;

/*
 * Parsed Boot Image Context
 */
typedef struct {
    uint32_t flags;
    boot_dyn_hdr_t hdr;

    const uint8_t *payload;
    size_t payload_size;
    const uint8_t *tail;
    size_t tail_size;

    const uint8_t *kernel;
    uint32_t kernel_size;
    uint8_t k_fmt;

    const uint8_t *kernel_dtb;
    size_t kernel_dtb_size;

    const uint8_t *ramdisk;
    uint32_t ramdisk_size;
    uint8_t r_fmt;

    const uint8_t *second;
    uint32_t second_size;

    const uint8_t *extra;
    uint32_t extra_size;
    uint8_t e_fmt;

    const uint8_t *recovery_dtbo;
    uint32_t recovery_dtbo_size;

    const uint8_t *dtb;
    uint32_t dtb_size;

    const uint8_t *signature;
    uint32_t signature_size;

    const uint8_t *vendor_ramdisk_table;
    uint32_t vendor_ramdisk_table_size;

    const uint8_t *bootconfig;
    uint32_t bootconfig_size;

    const struct mtk_hdr *k_hdr;
    const struct mtk_hdr *r_hdr;
    const struct avb_footer *avb_footer;
    const struct avb_vbmeta_image_header *vbmeta;
    uint64_t vbmeta_offset;

    /* Memory map */
    void *map_ptr;
    size_t map_sz;
    bool valid;
} boot_img_t;

/*
 * ARM64 Linux Kernel Image Header and Opcode Constants
 */
#define ARM64_IMAGE_MAGIC        0x644d5241U /* "ARM\x64" */
#define ARM64_NOP_OPCODE         0xd503201fU
#define ARM64_MOV_W0_WZR_OPCODE  0x2a1f03e0U
#define ARM64_B_TO_SKIP          0x14000008U
#define ARM64_CMP_W0_1           0x7100041fU
#define ARM64_B_EQ_40            0x54000140U
#define ARM64_CMP_W0_2           0x7100081fU
#define ARM64_B_EQ_12            0x54000060U
#define ARM64_BRK_800            0xd4210000U
#define ARM64_MOV_X1_X19         0xaa1303e1U
#define ARM64_BL_MASK            0xfc000000U
#define ARM64_BL_VAL             0x94000000U
#define ARM64_ADRP_MASK          0x9f000000U
#define ARM64_ADRP_VAL           0x90000000U
#define ARM64_LDRB_IMM_MASK      0xffc00000U
#define ARM64_LDRB_IMM_VAL       0x39400000U
#define ARM64_CBZ_MASK           0x7f000000U
#define ARM64_CBZ_VAL            0x34000000U
#define ARM64_STRB_IMM_MASK      0xffc00000U
#define ARM64_STRB_IMM_VAL       0x39000000U

struct arm64_image_header {
	uint32_t code0;
	uint32_t code1;
	uint64_t text_offset;
	uint64_t image_size;
	uint64_t flags;
	uint64_t res2;
	uint64_t res3;
	uint64_t res4;
	uint32_t magic;
	uint32_t res5;
};
typedef struct arm64_image_header arm64_image_header_t;

/*
 * Kernel Module & ELF Structure Manipulation (BTF, Relocation, Vermagic, CFI)
 */
#include <elf.h>

#define ARM64_RET_OPCODE         0xd65f03c0U
#define ARM64_NOP_OPCODE         0xd503201fU

#define DEFAULT_MODULE_PATH      "/lib/modules/kroot.ko"
#define FALLBACK_MODULE_PATH     "/data/adb/modules/kroot/kroot.ko"
#define LEGACY_FALLBACK_PATH     "/data/adb/modules/kcompat/compat_modern_kernel.ko"

#define KROOT_BTF_MAGIC          0xeb9f
#define KROOT_BTF_VERSION        1

#define KROOT_BTF_KIND_UNKN      0
#define KROOT_BTF_KIND_INT       1
#define KROOT_BTF_KIND_PTR       2
#define KROOT_BTF_KIND_ARRAY     3
#define KROOT_BTF_KIND_STRUCT    4
#define KROOT_BTF_KIND_UNION     5
#define KROOT_BTF_KIND_ENUM      6
#define KROOT_BTF_KIND_FWD       7
#define KROOT_BTF_KIND_TYPEDEF   8
#define KROOT_BTF_KIND_VOLATILE  9
#define KROOT_BTF_KIND_CONST     10
#define KROOT_BTF_KIND_RESTRICT  11
#define KROOT_BTF_KIND_FUNC      12
#define KROOT_BTF_KIND_FUNC_PROTO 13
#define KROOT_BTF_KIND_VAR       14
#define KROOT_BTF_KIND_DATASEC   15
#define KROOT_BTF_KIND_FLOAT     16
#define KROOT_BTF_KIND_DECL_TAG  17
#define KROOT_BTF_KIND_TYPE_TAG  18
#define KROOT_BTF_KIND_ENUM64    19

struct kroot_btf_header {
	uint16_t magic;
	uint8_t  version;
	uint8_t  flags;
	uint32_t hdr_len;
	uint32_t type_off;
	uint32_t type_len;
	uint32_t str_off;
	uint32_t str_len;
};

struct kroot_btf_type {
	uint32_t name_off;
	uint32_t info;
	union {
		uint32_t size;
		uint32_t type;
	};
};

struct kroot_btf_member {
	uint32_t name_off;
	uint32_t type;
	uint32_t offset;
};

struct kroot_btf_enum {
	uint32_t name_off;
	int32_t  val;
};

struct kroot_btf_enum64 {
	uint32_t name_off;
	uint32_t val_lo32;
	uint32_t val_hi32;
};

struct kroot_btf_array {
	uint32_t type;
	uint32_t index_type;
	uint32_t nelems;
};

struct kroot_btf_param {
	uint32_t name_off;
	uint32_t type;
};

struct kroot_btf_var {
	uint32_t linkage;
};

struct kroot_btf_var_secinfo {
	uint32_t type;
	uint32_t offset;
	uint32_t size;
};

struct module_layout_probe {
	size_t mod_size;
	size_t init_off;
	size_t exit_off;
	size_t core_layout_off;
	size_t header_len;
	bool   found;
};

#ifndef SYS_init_module
# if defined(__aarch64__)
#  define SYS_init_module 105
# elif defined(__x86_64__)
#  define SYS_init_module 175
# else
#  define SYS_init_module 105
# endif
#endif

#ifndef SYS_delete_module
# if defined(__aarch64__)
#  define SYS_delete_module 106
# elif defined(__x86_64__)
#  define SYS_delete_module 176
# else
#  define SYS_delete_module 106
# endif
#endif

#ifndef SYS_finit_module
# if defined(__aarch64__)
#  define SYS_finit_module 273
# elif defined(__x86_64__)
#  define SYS_finit_module 313
# else
#  define SYS_finit_module 273
# endif
#endif

struct elf64_ctx {
	uint8_t *buf;
	size_t size;
	size_t capacity;
	bool is_allocated;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdrs;
	size_t shnum;
	const char *shstrtab;
};


/*
 * ZIP Archive & Flashable Package Generator
 */
#define ZIP_LOCAL_HDR_MAGIC    0x04034b50U /* "PK\x03\x04" */
#define ZIP_CENTRAL_DIR_MAGIC  0x02014b50U /* "PK\x01\x02" */
#define ZIP_EOCD_MAGIC         0x06054b50U /* "PK\x05\x06" */

struct zip_local_hdr {
	uint32_t signature;
	uint16_t version_needed;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint16_t filename_len;
	uint16_t extra_len;
} __attribute__((packed));

struct zip_central_dir_hdr {
	uint32_t signature;
	uint16_t version_made_by;
	uint16_t version_needed;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint16_t filename_len;
	uint16_t extra_len;
	uint16_t comment_len;
	uint16_t disk_num_start;
	uint16_t internal_attr;
	uint32_t external_attr;
	uint32_t local_hdr_offset;
} __attribute__((packed));

struct zip_eocd_record {
	uint32_t signature;
	uint16_t disk_num;
	uint16_t cd_disk_num;
	uint16_t total_entries_disk;
	uint16_t total_entries;
	uint32_t cd_size;
	uint32_t cd_offset;
	uint16_t comment_len;
} __attribute__((packed));

struct zip_entry_info {
	char *name;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint32_t local_hdr_offset;
	uint16_t comp_method;
	uint32_t external_attr;
};

struct zip_writer {
	FILE *fp;
	size_t num_entries;
	size_t capacity;
	struct zip_entry_info *entries;
	uint32_t current_offset;
};

struct dist_package_options {
	const char *out_zip;
	const char *kernel_path;
	const char *dtb_path;
	const char *dtbo_path;
	const char *app_path;
	const char *overlay_dir;
	const char *magiskboot_bin;
	const char *banner;
	const char *device_check;
	const char *supported_versions;
	const char *supported_patchlevels;
	const char *vendor_boot_path;
	const char *vendor_dlkm_path;
	const char *system_dlkm_path;
	const char *update_binary_script;
	bool target_init_boot;
	bool target_vendor_boot;
	bool patch_vbmeta;
	size_t num_modules;
	char **modules;

	/* Magisk / KernelSU / APatch Module Options */
	bool is_magisk;
	const char *mod_id;
	const char *mod_name;
	const char *mod_version;
	int mod_version_code;
	const char *mod_author;
	const char *mod_description;
	const char *mod_prop_file;
	const char *service_script;
	const char *post_fs_data_script;
	const char *customize_script;
	const char *sepolicy_rule_file;
	const char *action_script;
	const char *system_dir;
};

#endif /* AIMG_H */
