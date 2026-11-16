/* vi: set sw=4 ts=4: */
/*
 * Android Runtime System Properties, Block Device & Storage Constants
 *
 * Provides canonical protocol definitions, shared memory layouts,
 * property service wire format, error codes, and storage geometry definitions
 * for Android subsystems in BusyBox.
 *
 * Licensed under GPLv2 or later.
 */

#ifndef BB_ANDROID_H
#define BB_ANDROID_H 1

#include "libbb.h"

#ifdef __linux__
# include <linux/fs.h>
#endif

/*
 * =========================================================================
 * 1. Linux Block Device Fallback Ioctls
 * =========================================================================
 */
#ifndef BLKROSET
# define BLKROSET    _IO(0x12, 93)
#endif
#ifndef BLKROGET
# define BLKROGET    _IO(0x12, 94)
#endif
#ifndef BLKGETSIZE
# define BLKGETSIZE   _IO(0x12, 96)
#endif
#ifndef BLKFLSBUF
# define BLKFLSBUF   _IO(0x12, 97)
#endif
#ifndef BLKSSZGET
# define BLKSSZGET   _IO(0x12, 104)
#endif
#ifndef BLKGETSIZE64
# define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif
#ifndef BLKPBSZGET
# define BLKPBSZGET  _IO(0x12, 123)
#endif

/*
 * =========================================================================
 * 2. Android Verified Boot (AVB 2.0) Definitions
 * =========================================================================
 */
#ifndef AVB_FOOTER_MAGIC
# define AVB_FOOTER_MAGIC        "AVBf"
#endif
#ifndef AVB_FOOTER_MAGIC_LEN
# define AVB_FOOTER_MAGIC_LEN    4
#endif
#ifndef AVB_FOOTER_SIZE
# define AVB_FOOTER_SIZE         64
#endif
#ifndef AVB_FOOTER_RESERVED_OFFSET
# define AVB_FOOTER_RESERVED_OFFSET 4096
#endif

struct avb_raw_footer {
	uint8_t magic[AVB_FOOTER_MAGIC_LEN];
	uint32_t version_major;
	uint32_t version_minor;
	uint64_t original_image_size;
	uint64_t vbmeta_offset;
	uint64_t vbmeta_size;
	uint8_t reserved[28];
} __attribute__((packed));

/*
 * =========================================================================
 * 3. Android System Properties Architecture (/dev/__properties__/)
 * =========================================================================
 */
#define ANDROID_PROP_DIR               "/dev/__properties__"
#define ANDROID_PROP_INFO_FILE         "/dev/__properties__/property_info"
#define ANDROID_PROP_SERIAL_FILE       "/dev/__properties__/properties_serial"
#define ANDROID_PROP_SERVICE_SOCKET    "/dev/socket/property_service"

#define PROP_AREA_MAGIC                0x50524f50 /* "PROP" */
#define PROP_AREA_VERSION              0xfc6ea652
#define PROP_AREA_HEADER_SIZE          128

#define PROP_NAME_MAX                  32
#define PROP_VALUE_MAX                 92
#define PROP_FLAG_LONG                 (1U << 16)
#define PROP_LONG_LEGACY_ERR_SZ        56

/*
 * Shared memory property area header: 128 bytes total
 * Followed immediately by data_ payload area at offset 128.
 */
struct prop_area_header {
	uint32_t bytes_used;
	uint32_t serial;
	uint32_t magic;
	uint32_t version;
	uint32_t reserved[28];
};

/*
 * Hybrid trie / binary search tree node (prop_bt in AOSP Bionic)
 * All offsets are relative to data_ payload area (file offset 128)
 */
struct prop_trie_node {
	uint32_t namelen;
	uint32_t prop;     /* offset relative to data_ to prop_info, or 0 */
	uint32_t left;     /* offset relative to data_ to left sibling BST, or 0 */
	uint32_t right;    /* offset relative to data_ to right sibling BST, or 0 */
	uint32_t children; /* offset relative to data_ to children sub-trie, or 0 */
	char name[0];      /* flexible array member */
};

/*
 * System property entry in shared memory (prop_info in AOSP Bionic)
 */
struct prop_info {
	uint32_t serial;
	union {
		char value[PROP_VALUE_MAX];
		struct {
			char error_message[PROP_LONG_LEGACY_ERR_SZ];
			uint32_t offset; /* relative to start of this prop_info struct */
		} long_property;
	};
	char name[0];      /* full null-terminated property name */
};

/*
 * Binary property_info serialization header (/dev/__properties__/property_info)
 */
struct property_info_area_header {
	uint32_t current_version;
	uint32_t minimum_supported_version;
	uint32_t size;
	uint32_t contexts_offset;
	uint32_t types_offset;
	uint32_t root_offset;
};

/*
 * =========================================================================
 * 4. Android Property Service Wire Protocol (/dev/socket/property_service)
 * =========================================================================
 */
#define PROP_MSG_SETPROP               1
#define PROP_MSG_SETPROP2              0x00020001

/* Property Service Response / Status Codes */
#define PROP_SUCCESS                   0
#define PROP_ERROR_READ_CMD            4
#define PROP_ERROR_READ_DATA           8
#define PROP_ERROR_READ_ONLY_PROPERTY  11
#define PROP_ERROR_INVALID_NAME        16
#define PROP_ERROR_INVALID_VALUE       20
#define PROP_ERROR_PERMISSION_DENIED   24
#define PROP_ERROR_INVALID_CMD         27
#define PROP_ERROR_HANDLE_CONTROL_MESSAGE 32
#define PROP_ERROR_SET_FAILED          36

/* Return human-readable string for property service error code */
static ALWAYS_INLINE const char *android_prop_strerror(uint32_t status)
{
	switch (status) {
	case PROP_SUCCESS:
		return "success";
	case PROP_ERROR_READ_CMD:
		return "failed to read command";
	case PROP_ERROR_READ_DATA:
		return "failed to read payload";
	case PROP_ERROR_READ_ONLY_PROPERTY:
		return "read-only property";
	case PROP_ERROR_INVALID_NAME:
		return "invalid property name";
	case PROP_ERROR_INVALID_VALUE:
		return "invalid property value";
	case PROP_ERROR_PERMISSION_DENIED:
		return "permission denied (requires root/privilege)";
	case PROP_ERROR_INVALID_CMD:
		return "invalid command";
	case PROP_ERROR_HANDLE_CONTROL_MESSAGE:
		return "control message failed";
	case PROP_ERROR_SET_FAILED:
		return "internal set failure";
	default:
		return "unknown error";
	}
}

#endif /* BB_ANDROID_H */
