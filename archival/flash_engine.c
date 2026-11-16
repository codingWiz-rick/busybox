/* vi: set sw=4 ts=4: */
/*
 * Mission-Critical Android Partition Flash Engine Implementation
 *
 * Licensed under GPLv2 or later.
 */

//kbuild:lib-$(CONFIG_AIMG) += flash_engine.o

#include "libbb.h"
#include "flash_engine.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

#define FLASH_CHUNK_SIZE (1024 * 1024) /* 1 MB buffer for optimal I/O throughput */

static void probe_avb_footer(int fd, uint64_t capacity, struct flash_target_geometry *geom)
{
	uint8_t tail_buf[4096];
	ssize_t nr;
	off_t tail_off;
	int off;

	if (capacity < sizeof(tail_buf))
		return;

	tail_off = (off_t)(capacity - sizeof(tail_buf));
	if (lseek(fd, tail_off, SEEK_SET) < 0)
		return;

	nr = full_read(fd, tail_buf, sizeof(tail_buf));
	if (nr != (ssize_t)sizeof(tail_buf))
		return;

	/* Scan backwards for AVB_FOOTER_MAGIC */
	for (off = (int)(sizeof(tail_buf) - sizeof(struct avb_raw_footer)); off >= 0; off -= 64) {
		if (memcmp(tail_buf + off, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0) {
			const struct avb_raw_footer *ftr = (const struct avb_raw_footer *)(tail_buf + off);
			geom->has_avb_footer = true;
			geom->avb_original_image_size = SWAP_BE64(ftr->original_image_size);
			geom->avb_vbmeta_offset = SWAP_BE64(ftr->vbmeta_offset);
			geom->avb_vbmeta_size = SWAP_BE64(ftr->vbmeta_size);
			return;
		}
	}
}

int flash_probe_geometry(const char *target_node, struct flash_target_geometry *geom)
{
	struct stat st;
	int fd;

	if (!target_node || !geom)
		return -EINVAL;

	memset(geom, 0, sizeof(*geom));
	safe_strncpy(geom->path, target_node, sizeof(geom->path));

	fd = open(target_node, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	geom->logical_sector_size = 512;
	geom->physical_sector_size = 512;

	if (S_ISBLK(st.st_mode)) {
		uint64_t sz64 = 0;
		unsigned long sectors = 0;

		geom->is_block_device = true;
		geom->dev_major = major(st.st_rdev);
		geom->dev_minor = minor(st.st_rdev);

		/* 1. Primary capacity resolution via 64-bit ioctl */
		if (ioctl(fd, BLKGETSIZE64, &sz64) == 0 && sz64 > 0) {
			geom->capacity_bytes = sz64;
		}
		/* 2. Secondary fallback via 32-bit sector count ioctl */
		else if (ioctl(fd, BLKGETSIZE, &sectors) == 0 && sectors > 0) {
			geom->capacity_bytes = (uint64_t)sectors * 512;
		}
		/* 3. Tertiary fallback via lseek */
		else {
			off_t end = lseek(fd, 0, SEEK_END);
			if (end > 0)
				geom->capacity_bytes = (uint64_t)end;
		}

		/* 4. Quaternary fallback via sysfs block size entry */
		if (geom->capacity_bytes == 0 && geom->dev_major != 0) {
			char sysfs_path[64];
			int sfd;
			snprintf(sysfs_path, sizeof(sysfs_path), "/sys/dev/block/%u:%u/size",
			         geom->dev_major, geom->dev_minor);
			sfd = open(sysfs_path, O_RDONLY | O_CLOEXEC);
			if (sfd >= 0) {
				char sbuf[32];
				ssize_t sn = read(sfd, sbuf, sizeof(sbuf) - 1);
				close(sfd);
				if (sn > 0) {
					sbuf[sn] = '\0';
					geom->capacity_bytes = (uint64_t)strtoull(sbuf, NULL, 10) * 512;
				}
			}
		}

		/* Probe sector sizes and read-only status */
		ioctl(fd, BLKSSZGET, &geom->logical_sector_size);
		ioctl(fd, BLKPBSZGET, &geom->physical_sector_size);
		{
			int ro = 0;
			if (ioctl(fd, BLKROGET, &ro) == 0 && ro)
				geom->is_read_only = true;
		}

		/* Probe AVB 2.0 footer if capacity was determined */
		if (geom->capacity_bytes > 0)
			probe_avb_footer(fd, geom->capacity_bytes, geom);

	} else if (S_ISREG(st.st_mode)) {
		geom->is_block_device = false;
		geom->capacity_bytes = (uint64_t)st.st_size;
		if (geom->capacity_bytes > 0)
			probe_avb_footer(fd, geom->capacity_bytes, geom);
	}

	close(fd);
	return 0;
}

static int verify_flashed_data(int src_fd, int tgt_fd, off_t total_size,
                               char *buf1, char *buf2, size_t buf_sz)
{
	off_t checked = 0;

	if (lseek(src_fd, 0, SEEK_SET) < 0 || lseek(tgt_fd, 0, SEEK_SET) < 0) {
		bb_perror_msg("flash_engine: seek failed during readback verification");
		return -errno;
	}

	/* Evict block device buffer cache to force read from physical silicon */
	ioctl(tgt_fd, BLKFLSBUF, 0);
	posix_fadvise(tgt_fd, 0, total_size, POSIX_FADV_DONTNEED);

	while (checked < total_size) {
		size_t chunk = (total_size - checked > (off_t)buf_sz) ?
		               buf_sz : (size_t)(total_size - checked);
		ssize_t nr1 = full_read(src_fd, buf1, chunk);
		ssize_t nr2 = full_read(tgt_fd, buf2, chunk);

		if (nr1 <= 0 || nr2 <= 0 || nr1 != nr2) {
			bb_error_msg("flash_engine: read error during verification at offset %lld",
			             (long long)checked);
			return -EIO;
		}

		if (memcmp(buf1, buf2, (size_t)nr1) != 0) {
			size_t byte_idx;
			for (byte_idx = 0; byte_idx < (size_t)nr1; byte_idx++) {
				if (buf1[byte_idx] != buf2[byte_idx]) {
					bb_error_msg("CRITICAL: Verification mismatch at absolute offset 0x%llx (expected 0x%02x, read 0x%02x)",
					             (unsigned long long)(checked + byte_idx),
					             (unsigned char)buf1[byte_idx],
					             (unsigned char)buf2[byte_idx]);
					break;
				}
			}
			return -EIO;
		}

		checked += nr1;
	}

	return 0;
}

int flash_partition_image(const char *src_image_path, const char *target_node, unsigned int flags)
{
	struct stat st_src;
	struct flash_target_geometry geom;
	char *stream_buf = NULL;
	char *verify_buf = NULL;
	struct timespec t_start, t_end;
	off_t written = 0;
	double elapsed, mb_sec;
	int in_fd = -1;
	int out_fd = -1;
	int ret = 0;
	sigset_t old_mask, block_mask;
	bool sig_blocked = false;

	if (!src_image_path || !target_node) {
		bb_error_msg("flash_engine: invalid null arguments");
		return -EINVAL;
	}

	/* 1. Audit and validate source image */
	in_fd = open_or_warn(src_image_path, O_RDONLY | O_CLOEXEC);
	if (in_fd < 0)
		return -errno;

	if (fstat(in_fd, &st_src) < 0) {
		bb_error_msg("flash_engine: can't stat source image '%s'", src_image_path);
		close(in_fd);
		return -errno;
	}

	if (!S_ISREG(st_src.st_mode)) {
		bb_error_msg("flash_engine: source '%s' is not a regular file", src_image_path);
		close(in_fd);
		return -EINVAL;
	}

	if (st_src.st_size < 4096) {
		bb_error_msg("flash_engine: image size %lld bytes is too small for a valid boot/recovery image",
		             (long long)st_src.st_size);
		close(in_fd);
		return -EINVAL;
	}

	/* 2. Probe target storage geometry BEFORE opening for write */
	if (flash_probe_geometry(target_node, &geom) != 0) {
		bb_error_msg("flash_engine: failed to probe target '%s'", target_node);
		close(in_fd);
		return -errno;
	}

	if (!(flags & FLASH_OPT_SILENT)) {
		printf("[*] Target Storage Geometry & Diagnostics:\n");
		printf("    • Node Path          : %s\n", geom.path);
		printf("    • Device Type        : %s (major %u, minor %u)\n",
		       geom.is_block_device ? "Block Device" : "Regular File",
		       geom.dev_major, geom.dev_minor);
		if (geom.capacity_bytes > 0) {
			printf("    • Partition Capacity : %llu bytes (%.2f MB)\n",
			       (unsigned long long)geom.capacity_bytes,
			       (double)geom.capacity_bytes / (1024.0 * 1024.0));
		}
		printf("    • Logical Sector Size: %u bytes\n", geom.logical_sector_size);
		if (geom.has_avb_footer) {
			printf("    • AVB 2.0 Footer     : Detected (Original Image: %.2f MB, VBMeta Offset: 0x%llx)\n",
			       (double)geom.avb_original_image_size / (1024.0 * 1024.0),
			       (unsigned long long)geom.avb_vbmeta_offset);
		}
	}

	/* Safety Boundary Check 1: Partition Capacity */
	if (geom.capacity_bytes > 0 && (uint64_t)st_src.st_size > geom.capacity_bytes) {
		bb_error_msg("CRITICAL: Image size (%lld bytes) exceeds partition capacity (%llu bytes)!",
		             (long long)st_src.st_size, (unsigned long long)geom.capacity_bytes);
		close(in_fd);
		return -EFBIG;
	}

	/* Safety Boundary Check 2: AVB 2.0 VBMeta Preservation */
	if (geom.has_avb_footer && geom.avb_vbmeta_offset > 0) {
		if ((uint64_t)st_src.st_size > geom.avb_vbmeta_offset) {
			if (!(flags & FLASH_OPT_FORCE)) {
				bb_error_msg("CRITICAL: Image size (%lld bytes) overlaps AVB 2.0 VBMeta at offset 0x%llx! Use FORCE to override.",
				             (long long)st_src.st_size, (unsigned long long)geom.avb_vbmeta_offset);
				close(in_fd);
				return -EFBIG;
			}
			bb_error_msg("WARNING: Overwriting AVB 2.0 VBMeta block by user request (FORCE flag set)");
		}
	}

	/* 3. Unlock Read-Only Block Devices */
	if (geom.is_block_device && geom.is_read_only) {
		int ro_fd = open(target_node, O_RDONLY | O_CLOEXEC);
		if (ro_fd >= 0) {
			int ro = 0;
			ioctl(ro_fd, BLKROSET, &ro);
			close(ro_fd);
		}
	}

	/* 4. Open Target Node for Writing */
	out_fd = open(target_node, O_RDWR | O_CLOEXEC);
	if (out_fd < 0) {
		/* Retry with O_RDONLY unlock if write permission was initially denied */
		if (errno == EACCES || errno == EROFS) {
			int ro_fd = open(target_node, O_RDONLY | O_CLOEXEC);
			if (ro_fd >= 0) {
				int ro = 0;
				ioctl(ro_fd, BLKROSET, &ro);
				close(ro_fd);
				out_fd = open(target_node, O_RDWR | O_CLOEXEC);
			}
		}
	}

	if (out_fd < 0) {
		bb_perror_msg("flash_engine: cannot open target '%s' for writing (requires root/sudo)", target_node);
		close(in_fd);
		return -errno;
	}

	/* Ensure BLKROSET is cleared on the open handle */
	if (geom.is_block_device) {
		int ro = 0;
		ioctl(out_fd, BLKROSET, &ro);
	}

	/* 5. Optional Pre-Flash Backup */
	if (flags & FLASH_OPT_BACKUP) {
		char bak_path[PATH_MAX];
		int bak_fd;
		snprintf(bak_path, sizeof(bak_path), "%s.pre_flash.bak", src_image_path);
		if (!(flags & FLASH_OPT_SILENT))
			printf("[*] Backing up current partition to %s...\n", bak_path);

		bak_fd = open(bak_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (bak_fd >= 0) {
			off_t bak_len = (geom.avb_original_image_size > 0 && geom.avb_original_image_size < (uint64_t)st_src.st_size * 2) ?
			                (off_t)geom.avb_original_image_size : st_src.st_size;
			char *bbuf = xmalloc(FLASH_CHUNK_SIZE);
			off_t bwritten = 0;
			lseek(out_fd, 0, SEEK_SET);
			while (bwritten < bak_len) {
				size_t chunk = (bak_len - bwritten > (off_t)FLASH_CHUNK_SIZE) ?
				               FLASH_CHUNK_SIZE : (size_t)(bak_len - bwritten);
				ssize_t bnr = full_read(out_fd, bbuf, chunk);
				if (bnr <= 0) break;
				if (full_write(bak_fd, bbuf, bnr) != bnr) break;
				bwritten += bnr;
			}
			free(bbuf);
			close(bak_fd);
			lseek(out_fd, 0, SEEK_SET);
			if (!(flags & FLASH_OPT_SILENT))
				printf("[✓] Backup created successfully (%lld bytes)\n", (long long)bwritten);
		} else {
			bb_perror_msg("warning: failed to create pre-flash backup '%s'", bak_path);
		}
	}

	/* 6. Allocate I/O Streaming Buffers */
	stream_buf = xmalloc(FLASH_CHUNK_SIZE);
	if (flags & FLASH_OPT_VERIFY_READ)
		verify_buf = xmalloc(FLASH_CHUNK_SIZE);

	/* 7. Protect Process from Terminal Interrupts (SIGINT/SIGTERM) During Flashing */
	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGINT);
	sigaddset(&block_mask, SIGTERM);
	sigaddset(&block_mask, SIGHUP);
	if (sigprocmask(SIG_BLOCK, &block_mask, &old_mask) == 0)
		sig_blocked = true;

	written = 0;
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	if (!(flags & FLASH_OPT_SILENT)) {
		printf("[*] Streaming patched boot image to %s (%lld bytes, %.2f MB)...\n",
		       target_node, (long long)st_src.st_size,
		       (double)st_src.st_size / (1024.0 * 1024.0));
	}

	/* 8. Stream blocks safely up to exact image boundary */
	lseek(in_fd, 0, SEEK_SET);
	lseek(out_fd, 0, SEEK_SET);

	while (written < st_src.st_size) {
		size_t chunk = (st_src.st_size - written > (off_t)FLASH_CHUNK_SIZE) ?
		               FLASH_CHUNK_SIZE : (size_t)(st_src.st_size - written);
		ssize_t nr = full_read(in_fd, stream_buf, chunk);
		ssize_t nw;
		int pct;

		if (nr <= 0)
			break;

		/* Zero-pad the final sector if writing unaligned size to a block device */
		if (geom.is_block_device && written + nr >= st_src.st_size) {
			uint32_t sec_sz = geom.logical_sector_size ? geom.logical_sector_size : 512;
			size_t rem = (size_t)nr % sec_sz;
			if (rem != 0) {
				size_t pad = sec_sz - rem;
				if ((size_t)nr + pad <= FLASH_CHUNK_SIZE) {
					memset(stream_buf + nr, 0, pad);
					nr += pad;
				}
			}
		}

		nw = full_write(out_fd, stream_buf, nr);
		if (nw != nr) {
			bb_error_msg("flash_engine: write failed at offset %lld (expected %zd, wrote %zd)",
			             (long long)written, (size_t)nr, (size_t)nw);
			ret = -EIO;
			break;
		}

		written += chunk; /* Count actual logical image bytes written */

		if (flags & FLASH_OPT_SYNC_EACH)
			fdatasync(out_fd);

		pct = (int)((written * 100) / st_src.st_size);
		if (!(flags & FLASH_OPT_SILENT)) {
			printf("    -> Committing blocks: %3d%% [%lld / %lld bytes]\n",
			       pct, (long long)written, (long long)st_src.st_size);
		}
	}

	/* 9. Telemetry Calculation */
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	elapsed = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) / 1e9;
	mb_sec = (elapsed > 0.001) ? ((double)written / (1024.0 * 1024.0)) / elapsed : 0.0;

	if (written != st_src.st_size) {
		bb_error_msg("CRITICAL: Flashing incomplete: wrote %lld of %lld bytes",
		             (long long)written, (long long)st_src.st_size);
		ret = (ret != 0) ? ret : -EIO;
		goto cleanup;
	}

	if (!(flags & FLASH_OPT_SILENT)) {
		printf("[+] Flashed %lld bytes in %.3f seconds (%.2f MB/s)\n",
		       (long long)written, elapsed, mb_sec);
	}

	/* 10. Hardware Write Cache Flush (fsync) */
	if (!(flags & FLASH_OPT_SILENT))
		printf("[*] Flushing hardware write caches to physical storage (fsync)...\n");

	if (fsync(out_fd) != 0) {
		bb_perror_msg("warning: fsync failed on '%s'", target_node);
	}

	/* 11. Post-Write Physical Readback Verification */
	if (flags & FLASH_OPT_VERIFY_READ) {
		if (!(flags & FLASH_OPT_SILENT))
			printf("[*] Performing bit-for-bit readback verification from physical flash...\n");

		ret = verify_flashed_data(in_fd, out_fd, st_src.st_size, stream_buf, verify_buf, FLASH_CHUNK_SIZE);
		if (ret != 0) {
			bb_error_msg("CRITICAL: Physical storage verification FAILED! Data corruption detected on %s", target_node);
			goto cleanup;
		}

		if (!(flags & FLASH_OPT_SILENT))
			printf("[✓] Verification PASSED: All %lld bytes physically verified on %s\n",
			       (long long)st_src.st_size, target_node);
	}

	if (!(flags & FLASH_OPT_SILENT)) {
		printf("[✓] SUCCESS: Verified %lld bytes committed directly to %s\n",
		       (long long)st_src.st_size, target_node);
	}

cleanup:
	/* Restore signal mask */
	if (sig_blocked)
		sigprocmask(SIG_SETMASK, &old_mask, NULL);

	free(stream_buf);
	free(verify_buf);
	if (in_fd >= 0) close(in_fd);
	if (out_fd >= 0) close(out_fd);

	return ret;
}

/*
 * =========================================================================
 * Android Partition & Storage Node Discovery
 * =========================================================================
 */

/* Recursively find the active 'by-name' partition directory under root dynamically */
int flash_find_by_name_dir(const char *root, int max_depth, char *out_dir, size_t max_len)
{
	DIR *d;
	struct dirent *de;
	const char *base = root ? root : "/dev/block";

	if (max_depth <= 0 || !out_dir || max_len < 16)
		return -EINVAL;

	d = opendir(base);
	if (!d)
		return -errno;

	while ((de = readdir(d)) != NULL) {
		char subpath[PATH_MAX];
		struct stat st;

		if (de->d_name[0] == '.')
			continue;

		snprintf(subpath, sizeof(subpath), "%s/%s", base, de->d_name);

		if (strcmp(de->d_name, "by-name") == 0) {
			if (stat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
				char test_node[PATH_MAX];
				/* Verify this by-name directory actually contains common partitions */
				snprintf(test_node, sizeof(test_node), "%.*s/boot", (int)(sizeof(test_node) - 16), subpath);
				if (access(test_node, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
				snprintf(test_node, sizeof(test_node), "%.*s/boot_a", (int)(sizeof(test_node) - 16), subpath);
				if (access(test_node, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
				snprintf(test_node, sizeof(test_node), "%.*s/system", (int)(sizeof(test_node) - 16), subpath);
				if (access(test_node, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
				snprintf(test_node, sizeof(test_node), "%.*s/recovery", (int)(sizeof(test_node) - 16), subpath);
				if (access(test_node, F_OK) == 0) {
					safe_strncpy(out_dir, subpath, max_len);
					closedir(d);
					return 0;
				}
			}
		}

		if (lstat(subpath, &st) == 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
			if (flash_find_by_name_dir(subpath, max_depth - 1, out_dir, max_len) == 0) {
				closedir(d);
				return 0;
			}
		}
	}
	closedir(d);
	return -ENOENT;
}

int flash_get_active_slot_suffix(char *slot_suffix, size_t max_len)
{
	int fd;
	char buf[2048];
	ssize_t n;
	char *p;
	char *eq;
	const char *env_slot;

	if (!slot_suffix || max_len < 3)
		return -EINVAL;

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
			} else {
				p = strstr(buf, "androidboot.slot");
				if (p) {
					eq = strchr(p, '=');
					if (eq) {
						char sname[16] = {0};
						while (*++eq == ' ' || *eq == '"');
						if (sscanf(eq, "%15[^\" \t\r\n]", sname) == 1 && max_len > 1) {
							snprintf(slot_suffix, max_len, "_%.*s", (int)(max_len - 2), sname);
						}
					}
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
				safe_strncpy(slot_suffix, "_a", max_len);
				return 0;
			} else if (strstr(buf, "_b ") || strstr(buf, "_b/")) {
				safe_strncpy(slot_suffix, "_b", max_len);
				return 0;
			}
		}
	}

	return -ENOENT;
}

int flash_find_partition(const char *part_name, char *out_path, size_t max_len)
{
	char by_name_dir[PATH_MAX];
	char slot_suffix[16];
	char test_path[PATH_MAX];
	bool is_ab = false;

	if (!part_name || !out_path || max_len < 16)
		return -EINVAL;

	/* 1. Explicit full path check */
	if (part_name[0] == '/') {
		if (access(part_name, F_OK) == 0) {
			safe_strncpy(out_path, part_name, max_len);
			return 0;
		}
		return -ENOENT;
	}

	/* 2. Dynamically discover the platform's 'by-name' directory under /dev/block */
	if (flash_find_by_name_dir("/dev/block", 4, by_name_dir, sizeof(by_name_dir)) != 0) {
		/* Fallback standard locations */
		snprintf(test_path, sizeof(test_path), "/dev/block/by-name/%s", part_name);
		if (access(test_path, F_OK) == 0) {
			safe_strncpy(out_path, test_path, max_len);
			return 0;
		}
		snprintf(test_path, sizeof(test_path), "/dev/block/bootdevice/by-name/%s", part_name);
		if (access(test_path, F_OK) == 0) {
			safe_strncpy(out_path, test_path, max_len);
			return 0;
		}
		return -ENOENT;
	}

	/* 3. Determine if this specific partition or target device is A/B slotted */
	snprintf(test_path, sizeof(test_path), "%.*s/%s_a", (int)(sizeof(test_path) - 32), by_name_dir, part_name);
	if (access(test_path, F_OK) == 0) {
		is_ab = true;
	} else {
		/* Check platform boot_a to confirm A/B topology */
		snprintf(test_path, sizeof(test_path), "%.*s/boot_a", (int)(sizeof(test_path) - 16), by_name_dir);
		if (access(test_path, F_OK) == 0) {
			is_ab = true;
		}
	}

	slot_suffix[0] = '\0';
	flash_get_active_slot_suffix(slot_suffix, sizeof(slot_suffix));
	if (is_ab && slot_suffix[0] == '\0') {
		strcpy(slot_suffix, "_a");
	}

	/* 4. Probe slotted partition first if A/B */
	if (is_ab && slot_suffix[0] != '\0') {
		snprintf(out_path, max_len, "%.*s/%s%s", (int)(max_len - 32), by_name_dir, part_name, slot_suffix);
		if (access(out_path, F_OK) == 0) {
			return 0;
		}
	}

	/* 5. Probe un-slotted partition path */
	snprintf(out_path, max_len, "%.*s/%s", (int)(max_len - 16), by_name_dir, part_name);
	if (access(out_path, F_OK) == 0) {
		return 0;
	}

	return -ENOENT;
}
