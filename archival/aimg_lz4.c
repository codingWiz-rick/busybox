/* vi: set sw=4 ts=4: */
/*
 * aimg_lz4.c — In-Process LZ4 / LZ4_LEGACY Decompressor & Compressor for aimg
 *
 * Implements standalone C streaming decompression and compression for:
 *   - BOOT_FMT_LZ4_LEGACY (0x184c2102): 8 MB block streaming with LZ4HC
 *   - BOOT_FMT_LZ4_LG (0x184c2102): Legacy with trailing total uncompressed size
 *   - BOOT_FMT_LZ4 (0x184d2204): Official LZ4 frame format v1.6.1
 *
 * Conforms to Linux Kernel Coding Style & ISO C90/C99/C11 standards.
 */

#ifndef AIMG_LZ4_C
#define AIMG_LZ4_C 1

#ifndef LZ4_SRC_INCLUDED
#define LZ4_SRC_INCLUDED 1
#endif

#ifndef LZ4_STATIC_LINKING_ONLY
#define LZ4_STATIC_LINKING_ONLY
#endif

#ifndef LZ4_HC_STATIC_LINKING_ONLY
#define LZ4_HC_STATIC_LINKING_ONLY
#endif

#ifndef LZ4F_STATIC_LINKING_ONLY
#define LZ4F_STATIC_LINKING_ONLY
#endif

#ifndef XXH_STATIC_LINKING_ONLY
#define XXH_STATIC_LINKING_ONLY
#endif

#ifndef LZ4_DISABLE_DEPRECATE_WARNINGS
#define LZ4_DISABLE_DEPRECATE_WARNINGS
#endif

/* Include LZ4 library headers */
#include "lz4/lz4.h"
#include "lz4/lz4hc.h"
#include "lz4/xxhash.h"
#include "lz4/lz4frame.h"

/* Suppress compiler warnings for amalgamated third-party C sources */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

#undef MAX
#undef MIN

/* Include LZ4 implementation units */
#include "lz4/lz4.c"
#include "lz4/lz4hc.c"
#include "lz4/xxhash.c"
#include "lz4/lz4frame.c"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#define AIMG_LZ4_BLOCK_SIZE     0x800000  /* 8 MB blocks matching Magiskboot & kernel */
#define AIMG_LZ4_MAGIC          0x184c2102
#define AIMG_LZ4_FRAME_MAGIC    0x184d2204

/*
 * Detect whether legacy LZ4 stream includes the LG trailer (4-byte total size)
 */
static bool boot_hdr_is_lz4_lg(const uint8_t *buf, size_t sz)
{
	uint32_t off = 4;
	uint32_t block_sz = 0;

	if (!buf || sz < 8)
		return false;

	while (off + sizeof(block_sz) <= sz) {
		memcpy(&block_sz, buf + off, sizeof(block_sz));
		off += sizeof(block_sz);
		if (off + block_sz > sz)
			return true;
		off += block_sz;
	}
	return false;
}

/*
 * Decompress in-memory BOOT_FMT_LZ4_LEGACY / BOOT_FMT_LZ4_LG stream to out_fd
 */
static int lz4_legacy_decompress(const void *in, size_t in_sz, int out_fd)
{
	const uint8_t *p = (const uint8_t *)in;
	const uint8_t *end = p + in_sz;
	uint32_t magic = 0;
	uint32_t block_sz = 0;
	char *out_buf = NULL;
	size_t max_bound;
	int ret = 0;

	if (!in || in_sz < 4 || out_fd < 0)
		return -1;

	memcpy(&magic, p, sizeof(magic));
	if (magic != AIMG_LZ4_MAGIC)
		return -1;
	p += sizeof(magic);

	out_buf = malloc(AIMG_LZ4_BLOCK_SIZE);
	if (!out_buf)
		return -1;

	max_bound = LZ4_compressBound(AIMG_LZ4_BLOCK_SIZE);

	while (p + sizeof(block_sz) <= end) {
		int decomp_sz;

		memcpy(&block_sz, p, sizeof(block_sz));
		p += sizeof(block_sz);

		if (block_sz == AIMG_LZ4_MAGIC) {
			if (p + sizeof(block_sz) <= end) {
				memcpy(&block_sz, p, sizeof(block_sz));
				p += sizeof(block_sz);
			} else {
				break;
			}
		}

		/*
		 * If block_sz is 0, exceeds remaining bytes, or exceeds compression bound,
		 * we have reached EOF or the LG uncompressed total size trailer.
		 */
		if (block_sz == 0 || block_sz > (size_t)(end - p) || block_sz > max_bound)
			break;

		decomp_sz = LZ4_decompress_safe((const char *)p, out_buf, (int)block_sz, AIMG_LZ4_BLOCK_SIZE);
		if (decomp_sz < 0) {
			ret = -1;
			break;
		}

		if (decomp_sz > 0) {
			if (full_write(out_fd, out_buf, decomp_sz) != (ssize_t)decomp_sz) {
				ret = -1;
				break;
			}
		}

		p += block_sz;
	}

	free(out_buf);
	return ret;
}

/*
 * Decompress in-memory standard BOOT_FMT_LZ4 frame stream to out_fd
 */
static int lz4_frame_decompress(const void *in, size_t in_sz, int out_fd)
{
	LZ4F_dctx *dctx = NULL;
	LZ4F_errorCode_t err;
	const uint8_t *src = (const uint8_t *)in;
	const uint8_t *src_end = src + in_sz;
	char *dst_buf = NULL;
	size_t dst_capacity = 64 * 1024;
	int ret = 0;

	if (!in || in_sz < 4 || out_fd < 0)
		return -1;

	err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
	if (LZ4F_isError(err))
		return -1;

	dst_buf = malloc(dst_capacity);
	if (!dst_buf) {
		LZ4F_freeDecompressionContext(dctx);
		return -1;
	}

	while (src < src_end) {
		size_t dst_size = dst_capacity;
		size_t src_size = src_end - src;

		size_t res = LZ4F_decompress(dctx, dst_buf, &dst_size, src, &src_size, NULL);
		if (LZ4F_isError(res)) {
			ret = -1;
			break;
		}

		if (dst_size > 0) {
			if (full_write(out_fd, dst_buf, dst_size) != (ssize_t)dst_size) {
				ret = -1;
				break;
			}
		}

		src += src_size;
		if (res == 0)
			break;
	}

	free(dst_buf);
	LZ4F_freeDecompressionContext(dctx);
	return ret;
}

/*
 * Compress src_file to dst_file using BOOT_FMT_LZ4_LEGACY / BOOT_FMT_LZ4_LG
 */
static int lz4_legacy_compress(const char *src_file, const char *dst_file, bool is_lg)
{
	int ifd = -1;
	int ofd = -1;
	char *in_buf = NULL;
	char *out_buf = NULL;
	size_t out_capacity;
	uint32_t magic = AIMG_LZ4_MAGIC;
	uint32_t total_uncompressed = 0;
	ssize_t n_read;
	int ret = 0;

	ifd = open_or_warn(src_file, O_RDONLY);
	if (ifd < 0)
		return -1;

	ofd = open3_or_warn(dst_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (ofd < 0) {
		close(ifd);
		return -1;
	}

	in_buf = malloc(AIMG_LZ4_BLOCK_SIZE);
	out_capacity = (size_t)LZ4_compressBound(AIMG_LZ4_BLOCK_SIZE);
	out_buf = malloc(out_capacity);

	if (!in_buf || !out_buf) {
		free(in_buf);
		free(out_buf);
		close(ifd);
		close(ofd);
		unlink(dst_file);
		return -1;
	}

	/* Write 4-byte magic */
	if (full_write(ofd, &magic, sizeof(magic)) != sizeof(magic)) {
		ret = -1;
		goto out;
	}

	while ((n_read = full_read(ifd, in_buf, AIMG_LZ4_BLOCK_SIZE)) > 0) {
		int comp_sz;
		uint32_t block_sz;

		total_uncompressed += (uint32_t)n_read;

		comp_sz = LZ4_compress_HC(in_buf, out_buf, (int)n_read, (int)out_capacity, 9);
		if (comp_sz <= 0) {
			ret = -1;
			goto out;
		}

		block_sz = (uint32_t)comp_sz;
		if (full_write(ofd, &block_sz, sizeof(block_sz)) != sizeof(block_sz)) {
			ret = -1;
			goto out;
		}

		if (full_write(ofd, out_buf, comp_sz) != (ssize_t)comp_sz) {
			ret = -1;
			goto out;
		}
	}

	if (n_read < 0) {
		ret = -1;
		goto out;
	}

	if (is_lg) {
		if (full_write(ofd, &total_uncompressed, sizeof(total_uncompressed)) != sizeof(total_uncompressed)) {
			ret = -1;
			goto out;
		}
	}

out:
	free(in_buf);
	free(out_buf);
	close(ifd);
	close(ofd);
	if (ret != 0)
		unlink(dst_file);
	return ret;
}

/*
 * Compress src_file to dst_file using standard BOOT_FMT_LZ4 frame format
 */
static int lz4_frame_compress(const char *src_file, const char *dst_file)
{
	int ifd = -1;
	int ofd = -1;
	char *in_buf = NULL;
	char *out_buf = NULL;
	size_t in_chunk = 256 * 1024;
	size_t out_capacity;
	size_t hdr_sz;
	size_t end_sz;
	LZ4F_cctx *cctx = NULL;
	LZ4F_preferences_t prefs;
	LZ4F_errorCode_t err;
	ssize_t n_read;
	int ret = 0;

	ifd = open_or_warn(src_file, O_RDONLY);
	if (ifd < 0)
		return -1;

	ofd = open3_or_warn(dst_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (ofd < 0) {
		close(ifd);
		return -1;
	}

	memset(&prefs, 0, sizeof(prefs));
	prefs.compressionLevel = 9;
	prefs.frameInfo.blockSizeID = LZ4F_max4MB;
	prefs.frameInfo.blockMode = LZ4F_blockIndependent;
	prefs.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
	prefs.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;

	err = LZ4F_createCompressionContext(&cctx, LZ4F_VERSION);
	if (LZ4F_isError(err)) {
		close(ifd);
		close(ofd);
		unlink(dst_file);
		return -1;
	}

	out_capacity = LZ4F_compressBound(in_chunk, &prefs) + LZ4F_HEADER_SIZE_MAX;
	in_buf = malloc(in_chunk);
	out_buf = malloc(out_capacity);

	if (!in_buf || !out_buf) {
		free(in_buf);
		free(out_buf);
		LZ4F_freeCompressionContext(cctx);
		close(ifd);
		close(ofd);
		unlink(dst_file);
		return -1;
	}

	/* Write frame header */
	hdr_sz = LZ4F_compressBegin(cctx, out_buf, out_capacity, &prefs);
	if (LZ4F_isError(hdr_sz)) {
		ret = -1;
		goto out;
	}
	if (full_write(ofd, out_buf, hdr_sz) != (ssize_t)hdr_sz) {
		ret = -1;
		goto out;
	}

	while ((n_read = full_read(ifd, in_buf, in_chunk)) > 0) {
		size_t comp_sz = LZ4F_compressUpdate(cctx, out_buf, out_capacity, in_buf, n_read, NULL);
		if (LZ4F_isError(comp_sz)) {
			ret = -1;
			goto out;
		}
		if (comp_sz > 0) {
			if (full_write(ofd, out_buf, comp_sz) != (ssize_t)comp_sz) {
				ret = -1;
				goto out;
			}
		}
	}

	if (n_read < 0) {
		ret = -1;
		goto out;
	}

	end_sz = LZ4F_compressEnd(cctx, out_buf, out_capacity, NULL);
	if (LZ4F_isError(end_sz)) {
		ret = -1;
		goto out;
	}
	if (full_write(ofd, out_buf, end_sz) != (ssize_t)end_sz) {
		ret = -1;
		goto out;
	}

out:
	free(in_buf);
	free(out_buf);
	LZ4F_freeCompressionContext(cctx);
	close(ifd);
	close(ofd);
	if (ret != 0)
		unlink(dst_file);
	return ret;
}

#endif /* AIMG_LZ4_C */
