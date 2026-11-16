/* vi: set sw=4 ts=4: */
/*
 * Mission-Critical Android Partition Flash Engine & Storage Diagnostics
 *
 * Provides safe, non-destructive, verified streaming writes to physical
 * block devices and flash partitions (e.g. boot, recovery, vendor_boot, init_boot).
 *
 * Safety Invariants:
 * 1. Strict geometry & boundary audit: Ensures image fits within partition capacity.
 * 2. AVB 2.0 footer preservation: Never truncates or overwrites unallocated slack.
 * 3. Atomic write-unprotect: Clears BLKROSET on read-only block devices.
 * 4. Deterministic hardware cache synchronization: Guarantees fsync() persistence.
 * 5. High-precision throughput telemetry and progress reporting.
 * 6. Bit-for-bit physical readback verification: Validates flash writes against source.
 *
 * Licensed under GPLv2 or later.
 */

#ifndef AIMG_FLASH_ENGINE_H
#define AIMG_FLASH_ENGINE_H 1

#include "libbb.h"
#include "bb_android.h"
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

#ifdef __linux__
# include <linux/fs.h>
#endif

/* Flash Engine Configuration Flags */
#define FLASH_OPT_SILENT         (1 << 0) /* Suppress verbose telemetry output */
#define FLASH_OPT_SYNC_EACH      (1 << 1) /* Sync after every block write */
#define FLASH_OPT_VERIFY_READ    (1 << 2) /* Perform post-write physical readback verification */
#define FLASH_OPT_BACKUP         (1 << 3) /* Backup existing partition before overwriting */
#define FLASH_OPT_FORCE          (1 << 4) /* Bypass safety boundary warnings */

/* Partition Geometry Diagnostics */
struct flash_target_geometry {
	char path[PATH_MAX];
	uint64_t capacity_bytes;
	uint32_t logical_sector_size;
	uint32_t physical_sector_size;
	unsigned int dev_major;
	unsigned int dev_minor;
	bool is_block_device;
	bool is_read_only;

	/* AVB 2.0 footer inspection */
	bool has_avb_footer;
	uint64_t avb_original_image_size;
	uint64_t avb_vbmeta_offset;
	uint64_t avb_vbmeta_size;
};

/*
 * Probe storage node geometry and inspect partition capacity.
 * Returns 0 on success, negative error code on failure.
 */
int flash_probe_geometry(const char *target_node, struct flash_target_geometry *geom);

/*
 * Flash an image directly to a block device or target node.
 * Performs complete safety checks, write-unprotect, block streaming,
 * hardware cache flush (fsync), and physical readback verification.
 *
 * Returns 0 on success, negative error code on failure.
 */
int flash_partition_image(const char *src_image_path, const char *target_node, unsigned int flags);

/*
 * Android Partition & Storage Node Discovery
 */

/*
 * Discover the platform's 'by-name' directory under a base path (default: "/dev/block").
 * Resolves directory trees and verifies presence of partition nodes.
 * Returns 0 on success, negative error code on failure.
 */
int flash_find_by_name_dir(const char *root, int max_depth, char *out_dir, size_t max_len);

/*
 * Discover the active A/B slot suffix ("_a", "_b", or "" for A-only).
 * Inspects /proc/cmdline, /proc/bootconfig, recovery env (SLOT/BOOT_SLOT), and active mounts.
 * Returns 0 on success, negative error code on failure.
 */
int flash_get_active_slot_suffix(char *slot_suffix, size_t max_len);

/*
 * Resolve a named partition (e.g. "boot", "recovery", "init_boot", "vendor_boot")
 * to its physical block device path under /dev/block/by-name/ taking A/B slot suffix
 * and platform topology into account.
 *
 * If part_name is an absolute path (starts with '/'), verifies its presence.
 * Returns 0 on success, negative error code on failure.
 */
int flash_find_partition(const char *part_name, char *out_path, size_t max_len);

/*
 * Backward-compatible helper for boot partition discovery.
 */
static inline int find_target_boot_image(char *out_path, size_t max_len)
{
	return flash_find_partition("boot", out_path, max_len);
}

#endif /* AIMG_FLASH_ENGINE_H */
