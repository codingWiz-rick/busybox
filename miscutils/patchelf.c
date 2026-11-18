/* vi: set sw=4 ts=4: */
/*
 * patchelf & termux-elf-cleaner
 *
 * Modify ELF executables and shared libraries:
 * - Dynamic linker (PT_INTERP)
 * - Dynamic tags (DT_SONAME, DT_RPATH, DT_RUNPATH, DT_NEEDED)
 * - Page size alignments (PT_LOAD p_align: 4k, 16k, 64k)
 * - Android ELF cleaner (removes unsupported versioning, rpath, and dynamic tags)
 *
 * Adapted and implemented in pure C for BusyBox by Rick & the BusyBox Team, 2026.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config PATCHELF
//config:	bool "patchelf (modify ELF executables and libraries)"
//config:	default y
//config:	help
//config:	  patchelf modifies the dynamic linker (PT_INTERP),
//config:	  dynamic tags (DT_SONAME, DT_RPATH, DT_RUNPATH, DT_NEEDED),
//config:	  page size alignments (4k/16k/64k), and cleans ELF files
//config:	  for Android (termux-elf-cleaner).

//applet:IF_PATCHELF(APPLET(patchelf, BB_DIR_USR_BIN, BB_SUID_DROP))
//applet:IF_PATCHELF(APPLET_ODDNAME(termux-elf-cleaner, patchelf, BB_DIR_USR_BIN, BB_SUID_DROP, termux_elf_cleaner))

//kbuild:lib-$(CONFIG_PATCHELF) += patchelf.o

//usage:#define patchelf_trivial_usage
//usage:       "[OPTIONS] FILE..."
//usage:#define patchelf_full_usage "\n\n"
//usage:       "Modify, align, or inspect ELF executables and shared libraries\n"
//usage:     "\n	--print-interpreter		Print PT_INTERP"
//usage:     "\n	--set-interpreter INTERP	Set PT_INTERP"
//usage:     "\n	--print-soname			Print DT_SONAME"
//usage:     "\n	--set-soname SONAME		Set DT_SONAME"
//usage:     "\n	--print-rpath			Print DT_RPATH / DT_RUNPATH"
//usage:     "\n	--set-rpath RPATH		Set DT_RPATH / DT_RUNPATH"
//usage:     "\n	--remove-rpath			Remove DT_RPATH / DT_RUNPATH"
//usage:     "\n	--print-needed			Print DT_NEEDED dependencies"
//usage:     "\n	--replace-needed OLD NEW	Replace a DT_NEEDED dependency"
//usage:     "\n	--add-needed LIB		Add a DT_NEEDED dependency"
//usage:     "\n	--remove-needed LIB		Remove a DT_NEEDED dependency"
//usage:     "\n	--page-size ALIGN		Change PT_LOAD page size alignment (4k, 16k, 64k)"
//usage:     "\n	--print-page-size		Print current PT_LOAD segment alignment"
//usage:     "\n	--clean-for-android		Clean ELF dynamic tags & sections for Android"
//usage:     "\n	--api-level NN			Target Android API level (default 21)"
//usage:     "\n	--dry-run			Report changes without writing to disk"
//usage:     "\n	--quiet				Suppress informational messages"
//usage:     "\n	--output FILE			Write output to FILE instead of in-place"
//usage:
//usage:#define termux_elf_cleaner_trivial_usage
//usage:       "[--api-level NN] [--dry-run] [--quiet] FILE..."
//usage:#define termux_elf_cleaner_full_usage "\n\n"
//usage:       "Clean ELF files for Android by removing unsupported dynamic tags and sections\n"
//usage:     "\n	--api-level NN	Target Android API level (default 21)"
//usage:     "\n	--dry-run	Print info but do not write changes"
//usage:     "\n	--quiet		Do not print info about removed entries"

#include "libbb.h"
#include <elf.h>

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif
#ifndef DT_VERSYM
#define DT_VERSYM 0x6ffffff0
#endif
#ifndef DT_FLAGS_1
#define DT_FLAGS_1 0x6ffffffb
#endif
#ifndef DT_VERDEF
#define DT_VERDEF 0x6ffffffc
#endif
#ifndef DT_VERDEFNUM
#define DT_VERDEFNUM 0x6ffffffd
#endif
#ifndef DT_VERNEED
#define DT_VERNEED 0x6ffffffe
#endif
#ifndef DT_VERNEEDNUM
#define DT_VERNEEDNUM 0x6fffffff
#endif
#ifndef DT_AARCH64_BTI_PLT
#define DT_AARCH64_BTI_PLT 0x70000001
#endif
#ifndef DT_AARCH64_PAC_PLT
#define DT_AARCH64_PAC_PLT 0x70000003
#endif
#ifndef DT_AARCH64_VARIANT_PCS
#define DT_AARCH64_VARIANT_PCS 0x70000005
#endif
#ifndef DF_1_NOW
#define DF_1_NOW 0x00000001
#endif
#ifndef DF_1_GLOBAL
#define DF_1_GLOBAL 0x00000002
#endif

#ifndef SHT_GNU_verdef
#define SHT_GNU_verdef 0x6ffffffd
#endif
#ifndef SHT_GNU_verneed
#define SHT_GNU_verneed 0x6ffffffe
#endif
#ifndef SHT_GNU_versym
#define SHT_GNU_versym 0x6fffffff
#endif

struct elf_ctx {
	int fd;
	const char *filename;
	uint8_t *buf;
	size_t size;
	size_t capacity;
	int is_64;
	int is_be;
	int is_aarch64;
	int modified;

	/* ELF Header fields */
	uint16_t machine;
	uint64_t phoff;
	uint16_t phentsize;
	uint16_t phnum;

	uint64_t shoff;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;

	/* Dynamic & interpreter info */
	int interp_ph_idx;
	uint64_t interp_off;
	uint64_t interp_filesz;

	int interp_sh_idx;
	uint64_t interp_sh_off;
	uint64_t interp_sh_size;

	uint64_t dynamic_off;
	uint64_t dynamic_size;
	uint64_t dynamic_entsize;

	int dynstr_sh_idx;
	uint64_t dynstr_off;
	uint64_t dynstr_size;
	uint64_t dt_strsz_dyn_off;
};

struct generic_phdr {
	uint32_t type;
	uint32_t flags;
	uint64_t offset;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t filesz;
	uint64_t memsz;
	uint64_t align;
	size_t hdr_offset;
};

struct generic_shdr {
	uint32_t name;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t addralign;
	uint64_t entsize;
	size_t hdr_offset;
};

struct generic_dyn {
	uint64_t tag;
	uint64_t val;
	size_t entry_offset;
};

/* Endian peek and poke helpers */
static uint16_t p_get_u16(const struct elf_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return (uint16_t)((b[0] << 8) | b[1]);
	return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t p_get_u32(const struct elf_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t p_get_u64(const struct elf_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be) {
		return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
		     | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | (uint64_t)b[7];
	}
	return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint32_t)b[3] << 24)
	     | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static void p_put_u32(const struct elf_ctx *ctx, void *p, uint32_t v)
{
	uint8_t *b = (uint8_t *)p;
	if (ctx->is_be) {
		b[0] = (uint8_t)(v >> 24);
		b[1] = (uint8_t)(v >> 16);
		b[2] = (uint8_t)(v >> 8);
		b[3] = (uint8_t)v;
	} else {
		b[0] = (uint8_t)v;
		b[1] = (uint8_t)(v >> 8);
		b[2] = (uint8_t)(v >> 16);
		b[3] = (uint8_t)(v >> 24);
	}
}

static void p_put_u64(const struct elf_ctx *ctx, void *p, uint64_t v)
{
	uint8_t *b = (uint8_t *)p;
	if (ctx->is_be) {
		b[0] = (uint8_t)(v >> 56);
		b[1] = (uint8_t)(v >> 48);
		b[2] = (uint8_t)(v >> 40);
		b[3] = (uint8_t)(v >> 32);
		b[4] = (uint8_t)(v >> 24);
		b[5] = (uint8_t)(v >> 16);
		b[6] = (uint8_t)(v >> 8);
		b[7] = (uint8_t)v;
	} else {
		b[0] = (uint8_t)v;
		b[1] = (uint8_t)(v >> 8);
		b[2] = (uint8_t)(v >> 16);
		b[3] = (uint8_t)(v >> 24);
		b[4] = (uint8_t)(v >> 32);
		b[5] = (uint8_t)(v >> 40);
		b[6] = (uint8_t)(v >> 48);
		b[7] = (uint8_t)(v >> 56);
	}
}

/* Ensure capacity when appending data */
static void ensure_capacity(struct elf_ctx *ctx, size_t needed)
{
	size_t new_cap;
	if (needed <= ctx->capacity)
		return;
	new_cap = ctx->capacity ? ctx->capacity * 2 : 4096;
	while (new_cap < needed)
		new_cap *= 2;
	ctx->buf = xrealloc(ctx->buf, new_cap);
	ctx->capacity = new_cap;
}

static int read_phdr(const struct elf_ctx *ctx, int idx, struct generic_phdr *ph)
{
	size_t off;
	uint8_t *p;

	off = (size_t)ctx->phoff + (size_t)idx * ctx->phentsize;
	if (off + ctx->phentsize > ctx->size)
		return 0;

	ph->hdr_offset = off;
	p = ctx->buf + off;

	if (ctx->is_64) {
		ph->type   = p_get_u32(ctx, p + 0);
		ph->flags  = p_get_u32(ctx, p + 4);
		ph->offset = p_get_u64(ctx, p + 8);
		ph->vaddr  = p_get_u64(ctx, p + 16);
		ph->paddr  = p_get_u64(ctx, p + 24);
		ph->filesz = p_get_u64(ctx, p + 32);
		ph->memsz  = p_get_u64(ctx, p + 40);
		ph->align  = p_get_u64(ctx, p + 48);
	} else {
		ph->type   = p_get_u32(ctx, p + 0);
		ph->offset = p_get_u32(ctx, p + 4);
		ph->vaddr  = p_get_u32(ctx, p + 8);
		ph->paddr  = p_get_u32(ctx, p + 12);
		ph->filesz = p_get_u32(ctx, p + 16);
		ph->memsz  = p_get_u32(ctx, p + 20);
		ph->flags  = p_get_u32(ctx, p + 24);
		ph->align  = p_get_u32(ctx, p + 28);
	}
	return 1;
}

static void write_phdr(struct elf_ctx *ctx, const struct generic_phdr *ph)
{
	uint8_t *p = ctx->buf + ph->hdr_offset;
	if (ctx->is_64) {
		p_put_u32(ctx, p + 0, ph->type);
		p_put_u32(ctx, p + 4, ph->flags);
		p_put_u64(ctx, p + 8, ph->offset);
		p_put_u64(ctx, p + 16, ph->vaddr);
		p_put_u64(ctx, p + 24, ph->paddr);
		p_put_u64(ctx, p + 32, ph->filesz);
		p_put_u64(ctx, p + 40, ph->memsz);
		p_put_u64(ctx, p + 48, ph->align);
	} else {
		p_put_u32(ctx, p + 0, ph->type);
		p_put_u32(ctx, p + 4, (uint32_t)ph->offset);
		p_put_u32(ctx, p + 8, (uint32_t)ph->vaddr);
		p_put_u32(ctx, p + 12, (uint32_t)ph->paddr);
		p_put_u32(ctx, p + 16, (uint32_t)ph->filesz);
		p_put_u32(ctx, p + 20, (uint32_t)ph->memsz);
		p_put_u32(ctx, p + 24, ph->flags);
		p_put_u32(ctx, p + 28, (uint32_t)ph->align);
	}
	ctx->modified = 1;
}

static int read_shdr(const struct elf_ctx *ctx, int idx, struct generic_shdr *sh)
{
	size_t off;
	uint8_t *p;

	off = (size_t)ctx->shoff + (size_t)idx * ctx->shentsize;
	if (off + ctx->shentsize > ctx->size)
		return 0;

	sh->hdr_offset = off;
	p = ctx->buf + off;

	if (ctx->is_64) {
		sh->name      = p_get_u32(ctx, p + 0);
		sh->type      = p_get_u32(ctx, p + 4);
		sh->flags     = p_get_u64(ctx, p + 8);
		sh->addr      = p_get_u64(ctx, p + 16);
		sh->offset    = p_get_u64(ctx, p + 24);
		sh->size      = p_get_u64(ctx, p + 32);
		sh->link      = p_get_u32(ctx, p + 40);
		sh->info      = p_get_u32(ctx, p + 44);
		sh->addralign = p_get_u64(ctx, p + 48);
		sh->entsize   = p_get_u64(ctx, p + 56);
	} else {
		sh->name      = p_get_u32(ctx, p + 0);
		sh->type      = p_get_u32(ctx, p + 4);
		sh->flags     = p_get_u32(ctx, p + 8);
		sh->addr      = p_get_u32(ctx, p + 12);
		sh->offset    = p_get_u32(ctx, p + 16);
		sh->size      = p_get_u32(ctx, p + 20);
		sh->link      = p_get_u32(ctx, p + 24);
		sh->info      = p_get_u32(ctx, p + 28);
		sh->addralign = p_get_u32(ctx, p + 32);
		sh->entsize   = p_get_u32(ctx, p + 36);
	}
	return 1;
}

static void write_shdr(struct elf_ctx *ctx, const struct generic_shdr *sh)
{
	uint8_t *p = ctx->buf + sh->hdr_offset;
	if (ctx->is_64) {
		p_put_u32(ctx, p + 0, sh->name);
		p_put_u32(ctx, p + 4, sh->type);
		p_put_u64(ctx, p + 8, sh->flags);
		p_put_u64(ctx, p + 16, sh->addr);
		p_put_u64(ctx, p + 24, sh->offset);
		p_put_u64(ctx, p + 32, sh->size);
		p_put_u32(ctx, p + 40, sh->link);
		p_put_u32(ctx, p + 44, sh->info);
		p_put_u64(ctx, p + 48, sh->addralign);
		p_put_u64(ctx, p + 56, sh->entsize);
	} else {
		p_put_u32(ctx, p + 0, sh->name);
		p_put_u32(ctx, p + 4, sh->type);
		p_put_u32(ctx, p + 8, (uint32_t)sh->flags);
		p_put_u32(ctx, p + 12, (uint32_t)sh->addr);
		p_put_u32(ctx, p + 16, (uint32_t)sh->offset);
		p_put_u32(ctx, p + 20, (uint32_t)sh->size);
		p_put_u32(ctx, p + 24, sh->link);
		p_put_u32(ctx, p + 28, sh->info);
		p_put_u32(ctx, p + 32, (uint32_t)sh->addralign);
		p_put_u32(ctx, p + 36, (uint32_t)sh->entsize);
	}
	ctx->modified = 1;
}

static int read_dyn(const struct elf_ctx *ctx, size_t entry_offset, struct generic_dyn *dyn)
{
	uint8_t *p;

	if (entry_offset + ctx->dynamic_entsize > ctx->size)
		return 0;

	dyn->entry_offset = entry_offset;
	p = ctx->buf + entry_offset;
	if (ctx->is_64) {
		dyn->tag = p_get_u64(ctx, p + 0);
		dyn->val = p_get_u64(ctx, p + 8);
	} else {
		dyn->tag = p_get_u32(ctx, p + 0);
		dyn->val = p_get_u32(ctx, p + 4);
	}
	return 1;
}

static void write_dyn(struct elf_ctx *ctx, const struct generic_dyn *dyn)
{
	uint8_t *p = ctx->buf + dyn->entry_offset;
	if (ctx->is_64) {
		p_put_u64(ctx, p + 0, dyn->tag);
		p_put_u64(ctx, p + 8, dyn->val);
	} else {
		p_put_u32(ctx, p + 0, (uint32_t)dyn->tag);
		p_put_u32(ctx, p + 4, (uint32_t)dyn->val);
	}
	ctx->modified = 1;
}

static int elf_load(struct elf_ctx *ctx, const char *filename, int write_access)
{
	struct stat sb;
	int fd;
	int i;
	const char *shstrtab = NULL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->filename = filename;
	ctx->interp_ph_idx = -1;
	ctx->interp_sh_idx = -1;
	ctx->dynstr_sh_idx = -1;

	fd = open(filename, write_access ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		bb_perror_msg("%s", filename);
		return 0;
	}
	ctx->fd = fd;

	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size < 45) {
		bb_error_msg("%s: invalid ELF file", filename);
		close(fd);
		return 0;
	}

	ctx->size = (size_t)sb.st_size;
	ctx->capacity = ctx->size;
	ctx->buf = xmalloc(ctx->capacity);
	xread(fd, ctx->buf, ctx->size);

	if (memcmp(ctx->buf, "\177ELF", 4) != 0) {
		bb_error_msg("%s: not an ELF file", filename);
		free(ctx->buf);
		close(fd);
		return 0;
	}

	ctx->is_64 = (ctx->buf[4] == 2);
	ctx->is_be = (ctx->buf[5] == 2);

	/* Machine architecture */
	ctx->machine = p_get_u16(ctx, ctx->buf + 18);
	ctx->is_aarch64 = (ctx->machine == 183); /* EM_AARCH64 */

	/* Extract program header and section header table offsets */
	if (ctx->is_64) {
		ctx->phoff     = p_get_u64(ctx, ctx->buf + 32);
		ctx->shoff     = p_get_u64(ctx, ctx->buf + 40);
		ctx->phentsize = p_get_u16(ctx, ctx->buf + 54);
		ctx->phnum     = p_get_u16(ctx, ctx->buf + 56);
		ctx->shentsize = p_get_u16(ctx, ctx->buf + 58);
		ctx->shnum     = p_get_u16(ctx, ctx->buf + 60);
		ctx->shstrndx  = p_get_u16(ctx, ctx->buf + 62);
	} else {
		ctx->phoff     = p_get_u32(ctx, ctx->buf + 28);
		ctx->shoff     = p_get_u32(ctx, ctx->buf + 32);
		ctx->phentsize = p_get_u16(ctx, ctx->buf + 42);
		ctx->phnum     = p_get_u16(ctx, ctx->buf + 44);
		ctx->shentsize = p_get_u16(ctx, ctx->buf + 46);
		ctx->shnum     = p_get_u16(ctx, ctx->buf + 48);
		ctx->shstrndx  = p_get_u16(ctx, ctx->buf + 50);
	}

	ctx->dynamic_entsize = ctx->is_64 ? 16 : 8;

	/* Parse Program Headers */
	for (i = 0; i < ctx->phnum; i++) {
		struct generic_phdr ph;
		if (!read_phdr(ctx, i, &ph))
			continue;
		if (ph.type == PT_INTERP) {
			ctx->interp_ph_idx = i;
			ctx->interp_off    = ph.offset;
			ctx->interp_filesz = ph.filesz;
		} else if (ph.type == PT_DYNAMIC) {
			ctx->dynamic_off  = ph.offset;
			ctx->dynamic_size = ph.filesz;
		}
	}

	/* Find Section Names String Table (.shstrtab) */
	if (ctx->shstrndx && ctx->shstrndx < ctx->shnum) {
		struct generic_shdr sh;
		if (read_shdr(ctx, ctx->shstrndx, &sh) && sh.type == SHT_STRTAB) {
			if (sh.offset < ctx->size)
				shstrtab = (const char *)(ctx->buf + sh.offset);
		}
	}

	/* Parse Section Headers */
	for (i = 0; i < ctx->shnum; i++) {
		struct generic_shdr sh;
		const char *sname = "";

		if (!read_shdr(ctx, i, &sh))
			continue;

		if (shstrtab && sh.name < ctx->size - (size_t)shstrtab)
			sname = shstrtab + sh.name;

		if (sh.type == SHT_PROGBITS && !strcmp(sname, ".interp")) {
			ctx->interp_sh_idx  = i;
			ctx->interp_sh_off  = sh.offset;
			ctx->interp_sh_size = sh.size;
		} else if (sh.type == SHT_DYNAMIC) {
			if (!ctx->dynamic_off) {
				ctx->dynamic_off  = sh.offset;
				ctx->dynamic_size = sh.size;
			}
		} else if (sh.type == SHT_STRTAB && !strcmp(sname, ".dynstr")) {
			ctx->dynstr_sh_idx = i;
			ctx->dynstr_off    = sh.offset;
			ctx->dynstr_size   = sh.size;
		}
	}

	/* Locate DT_STRSZ in dynamic table if dynamic exists */
	if (ctx->dynamic_off && ctx->dynamic_size) {
		size_t off;
		for (off = ctx->dynamic_off; off + ctx->dynamic_entsize <= ctx->dynamic_off + ctx->dynamic_size; off += ctx->dynamic_entsize) {
			struct generic_dyn dyn;
			if (!read_dyn(ctx, off, &dyn) || !dyn.tag)
				break;
			if (dyn.tag == DT_STRSZ)
				ctx->dt_strsz_dyn_off = off;
		}
	}

	return 1;
}

static void elf_save_and_close(struct elf_ctx *ctx, const char *output_file)
{
	if (output_file) {
		int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
		if (out_fd < 0)
			bb_perror_msg_and_die("%s", output_file);
		xwrite(out_fd, ctx->buf, ctx->size);
		close(out_fd);
	} else if (ctx->modified && ctx->fd >= 0) {
		if (lseek(ctx->fd, 0, SEEK_SET) == (off_t)-1)
			bb_perror_msg_and_die("%s: lseek", ctx->filename);
		xwrite(ctx->fd, ctx->buf, ctx->size);
		if (ftruncate(ctx->fd, (off_t)ctx->size) != 0)
			bb_perror_msg("%s: ftruncate", ctx->filename);
	}
	if (ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
	}
	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
}

/* Helper to append string to .dynstr section */
static uint64_t dynstr_append_string(struct elf_ctx *ctx, const char *str)
{
	size_t len;
	uint64_t old_dynstr_size;
	uint64_t target_dyn_offset;
	uint64_t next_sec_offset;
	uint64_t available_padding;
	int i;

	len = strlen(str) + 1;
	old_dynstr_size = ctx->dynstr_size;
	target_dyn_offset = old_dynstr_size;

	if (!ctx->dynstr_off)
		bb_error_msg_and_die("%s: no .dynstr section found", ctx->filename);

	/* Check available padding between .dynstr and the next section */
	next_sec_offset = (uint64_t)-1;
	for (i = 0; i < ctx->shnum; i++) {
		struct generic_shdr sh;
		if (read_shdr(ctx, i, &sh) && sh.type != SHT_NOBITS && sh.offset > ctx->dynstr_off) {
			if (sh.offset < next_sec_offset)
				next_sec_offset = sh.offset;
		}
	}

	available_padding = (next_sec_offset != (uint64_t)-1) ?
		(next_sec_offset - (ctx->dynstr_off + ctx->dynstr_size)) : 0;

	if (len <= available_padding) {
		/* Write directly into the existing section alignment gap */
		memcpy(ctx->buf + ctx->dynstr_off + ctx->dynstr_size, str, len);
		ctx->dynstr_size += len;

		if (ctx->dynstr_sh_idx >= 0) {
			struct generic_shdr sh;
			if (read_shdr(ctx, ctx->dynstr_sh_idx, &sh)) {
				sh.size = ctx->dynstr_size;
				write_shdr(ctx, &sh);
			}
		}
		if (ctx->dt_strsz_dyn_off) {
			struct generic_dyn dyn;
			if (read_dyn(ctx, ctx->dt_strsz_dyn_off, &dyn)) {
				dyn.val = ctx->dynstr_size;
				write_dyn(ctx, &dyn);
			}
		}
		ctx->modified = 1;
		return target_dyn_offset;
	}

	bb_error_msg_and_die("%s: insufficient padding to expand .dynstr for '%s'",
		ctx->filename, str);
}

/* Parse page size alignment value (e.g. 4k, 16k, 64k, 0x1000, 4096) */
static uint64_t parse_size_align(const char *s)
{
	char *end;
	uint64_t val;

	if (!strcasecmp(s, "4k")) return 4096;
	if (!strcasecmp(s, "16k")) return 16384;
	if (!strcasecmp(s, "64k")) return 65536;

	val = strtoull(s, &end, 0);
	if (*end == 'k' || *end == 'K') val *= 1024;
	else if (*end == 'm' || *end == 'M') val *= 1024 * 1024;

	if (!val || (val & (val - 1)) != 0)
		bb_error_msg_and_die("page size %llu must be a power of 2", (unsigned long long)val);
	return val;
}

/* termux-elf-cleaner implementation */
static void run_clean_for_android(struct elf_ctx *ctx, int api_level, int dry_run, int quiet)
{
	int i;
	size_t last_nonnull_off = 0;
	size_t off;

	/* 1. TLS segment alignment check (Android Bionic requirement) */
	uint64_t tls_min_alignment = ctx->is_64 ? 64 : 32;
	for (i = 0; i < ctx->phnum; i++) {
		struct generic_phdr ph;
		if (read_phdr(ctx, i, &ph) && ph.type == PT_TLS && ph.align < tls_min_alignment) {
			if (!quiet)
				printf("termux-elf-cleaner: Changing TLS alignment for '%s' to %u, instead of %u\n",
				       ctx->filename, (unsigned)tls_min_alignment, (unsigned)ph.align);
			if (!dry_run) {
				ph.align = tls_min_alignment;
				write_phdr(ctx, &ph);
			}
		}
	}

	/* 2. Dynamic Section Entries */
	if (ctx->dynamic_off && ctx->dynamic_size) {
		/* Find last non-null entry */
		for (off = ctx->dynamic_off + ctx->dynamic_size - ctx->dynamic_entsize;
		     off >= ctx->dynamic_off; off -= ctx->dynamic_entsize) {
			struct generic_dyn d;
			if (read_dyn(ctx, off, &d) && d.tag != DT_NULL) {
				last_nonnull_off = off;
				break;
			}
			if (off == ctx->dynamic_off)
				break;
		}

		for (off = ctx->dynamic_off; off <= last_nonnull_off && off + ctx->dynamic_entsize <= ctx->dynamic_off + ctx->dynamic_size; off += ctx->dynamic_entsize) {
			struct generic_dyn dyn;
			const char *removed_name = NULL;

			if (!read_dyn(ctx, off, &dyn))
				break;

			switch (dyn.tag) {
			case DT_GNU_HASH:
				if (api_level < 23) removed_name = "DT_GNU_HASH";
				break;
			case DT_VERSYM:
				if (api_level < 23) removed_name = "DT_VERSYM";
				break;
			case DT_VERNEED:
				if (api_level < 23) removed_name = "DT_VERNEED";
				break;
			case DT_VERNEEDNUM:
				if (api_level < 23) removed_name = "DT_VERNEEDNUM";
				break;
			case DT_VERDEF:
				if (api_level < 23) removed_name = "DT_VERDEF";
				break;
			case DT_VERDEFNUM:
				if (api_level < 23) removed_name = "DT_VERDEFNUM";
				break;
			case DT_RPATH:
				removed_name = "DT_RPATH";
				break;
			case DT_RUNPATH:
				if (api_level < 24) removed_name = "DT_RUNPATH";
				break;
			case DT_AARCH64_BTI_PLT:
				if (ctx->is_aarch64 && api_level < 31) removed_name = "DT_AARCH64_BTI_PLT";
				break;
			case DT_AARCH64_PAC_PLT:
				if (ctx->is_aarch64 && api_level < 31) removed_name = "DT_AARCH64_PAC_PLT";
				break;
			case DT_AARCH64_VARIANT_PCS:
				if (ctx->is_aarch64 && api_level < 31) removed_name = "DT_AARCH64_VARIANT_PCS";
				break;
			}

			if (removed_name) {
				if (!quiet)
					printf("termux-elf-cleaner: Removing the %s dynamic section entry from '%s'\n",
					       removed_name, ctx->filename);
				if (!dry_run) {
					if (off < last_nonnull_off) {
						struct generic_dyn last_entry;
						read_dyn(ctx, last_nonnull_off, &last_entry);
						last_entry.entry_offset = off;
						write_dyn(ctx, &last_entry);

						dyn.tag = DT_NULL;
						dyn.val = 0;
						dyn.entry_offset = last_nonnull_off;
						write_dyn(ctx, &dyn);

						while (last_nonnull_off > ctx->dynamic_off) {
							last_nonnull_off -= ctx->dynamic_entsize;
							if (read_dyn(ctx, last_nonnull_off, &last_entry) && last_entry.tag != DT_NULL)
								break;
						}
						/* Recheck this index since a new entry was swapped in */
						off -= ctx->dynamic_entsize;
					} else {
						dyn.tag = DT_NULL;
						dyn.val = 0;
						write_dyn(ctx, &dyn);
					}
					ctx->modified = 1;
				}
			} else if (dyn.tag == DT_FLAGS_1) {
				uint64_t orig_val = dyn.val;
				uint64_t new_val = orig_val & (DF_1_NOW | DF_1_GLOBAL);
				if (new_val != orig_val) {
					if (!quiet)
						printf("termux-elf-cleaner: Replacing unsupported DF_1_* flags %llu with %llu in '%s'\n",
						       (unsigned long long)orig_val, (unsigned long long)new_val, ctx->filename);
					if (!dry_run) {
						dyn.val = new_val;
						write_dyn(ctx, &dyn);
						ctx->modified = 1;
					}
				}
			}
		}
	}

	/* 3. Section Headers Cleanup (GNU versioning sections) */
	if (api_level < 23) {
		for (i = 0; i < ctx->shnum; i++) {
			struct generic_shdr sh;
			if (!read_shdr(ctx, i, &sh))
				continue;
			if (sh.type == SHT_GNU_verdef || sh.type == SHT_GNU_verneed || sh.type == SHT_GNU_versym) {
				if (!quiet) {
					const char *vname = "VERSYM";
					if (sh.type == SHT_GNU_verdef) vname = "VERDEF";
					else if (sh.type == SHT_GNU_verneed) vname = "VERNEED";
					printf("termux-elf-cleaner: Removing %s section from '%s'\n", vname, ctx->filename);
				}
				if (!dry_run) {
					sh.type = SHT_NULL;
					write_shdr(ctx, &sh);
					ctx->modified = 1;
				}
			}
		}
	}
}

int patchelf_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int patchelf_main(int argc, char **argv)
{
	const char *opt_set_interpreter = NULL;
	const char *opt_set_soname = NULL;
	const char *opt_set_rpath = NULL;
	const char *opt_replace_needed_old = NULL;
	const char *opt_replace_needed_new = NULL;
	const char *opt_add_needed = NULL;
	const char *opt_remove_needed = NULL;
	const char *opt_output = NULL;
	uint64_t opt_page_size = 0;

	int do_print_interpreter = 0;
	int do_print_soname = 0;
	int do_print_rpath = 0;
	int do_print_needed = 0;
	int do_print_page_size = 0;
	int do_remove_rpath = 0;
	int do_clean_for_android = 0;
	int opt_api_level = 21;
	int opt_dry_run = 0;
	int opt_quiet = 0;

	int file_count = 0;
	int file_start_idx = 0;
	int needs_write;
	int fidx;
	int i;
	const char *target_file;
	struct elf_ctx ctx;
	const char *dynstr;

	/* Detect if invoked under termux-elf-cleaner name */
	if (applet_name && strstr(applet_name, "cleaner")) {
		do_clean_for_android = 1;
	}

	if (argc < 2)
		bb_show_usage();

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "--print-interpreter")) {
			do_print_interpreter = 1;
		} else if (!strcmp(arg, "--set-interpreter")) {
			if (++i >= argc) bb_show_usage();
			opt_set_interpreter = argv[i];
		} else if (!strcmp(arg, "--print-soname")) {
			do_print_soname = 1;
		} else if (!strcmp(arg, "--set-soname")) {
			if (++i >= argc) bb_show_usage();
			opt_set_soname = argv[i];
		} else if (!strcmp(arg, "--print-rpath") || !strcmp(arg, "--print-runpath")) {
			do_print_rpath = 1;
		} else if (!strcmp(arg, "--set-rpath") || !strcmp(arg, "--set-runpath")) {
			if (++i >= argc) bb_show_usage();
			opt_set_rpath = argv[i];
		} else if (!strcmp(arg, "--remove-rpath")) {
			do_remove_rpath = 1;
		} else if (!strcmp(arg, "--print-needed")) {
			do_print_needed = 1;
		} else if (!strcmp(arg, "--replace-needed")) {
			if (i + 2 >= argc) bb_show_usage();
			opt_replace_needed_old = argv[++i];
			opt_replace_needed_new = argv[++i];
		} else if (!strcmp(arg, "--add-needed")) {
			if (++i >= argc) bb_show_usage();
			opt_add_needed = argv[i];
		} else if (!strcmp(arg, "--remove-needed")) {
			if (++i >= argc) bb_show_usage();
			opt_remove_needed = argv[i];
		} else if (!strcmp(arg, "--page-size") || !strcmp(arg, "--set-page-size")) {
			if (++i >= argc) bb_show_usage();
			opt_page_size = parse_size_align(argv[i]);
		} else if (!strcmp(arg, "--print-page-size")) {
			do_print_page_size = 1;
		} else if (!strcmp(arg, "--clean-for-android") || !strcmp(arg, "--clean-elf")) {
			do_clean_for_android = 1;
		} else if (!strcmp(arg, "--api-level")) {
			if (++i >= argc) bb_show_usage();
			opt_api_level = xatoi(argv[i]);
		} else if (!strcmp(arg, "--dry-run")) {
			opt_dry_run = 1;
		} else if (!strcmp(arg, "--quiet")) {
			opt_quiet = 1;
		} else if (!strcmp(arg, "--output")) {
			if (++i >= argc) bb_show_usage();
			opt_output = argv[i];
		} else if (arg[0] == '-') {
			bb_error_msg_and_die("unknown option: %s", arg);
		} else {
			if (!file_start_idx)
				file_start_idx = i;
			file_count++;
		}
	}

	if (!file_count)
		bb_show_usage();

	needs_write = (opt_set_interpreter || opt_set_soname || opt_set_rpath
		|| do_remove_rpath || opt_replace_needed_old || opt_add_needed
		|| opt_remove_needed || opt_page_size || do_clean_for_android) && !opt_dry_run;

	for (fidx = file_start_idx; fidx < argc; fidx++) {
		target_file = argv[fidx];

		if (argv[fidx][0] == '-')
			continue;

		if (!elf_load(&ctx, target_file, needs_write))
			continue;

		/* 1. Print interpreter */
		if (do_print_interpreter) {
			if (ctx.interp_off && ctx.interp_filesz) {
				printf("%.*s\n", (int)(ctx.interp_filesz - 1), (char *)(ctx.buf + ctx.interp_off));
			} else if (ctx.interp_sh_off && ctx.interp_sh_size) {
				printf("%.*s\n", (int)(ctx.interp_sh_size - 1), (char *)(ctx.buf + ctx.interp_sh_off));
			} else {
				bb_error_msg("%s: no PT_INTERP section", target_file);
			}
		}

		/* 2. Set interpreter */
		if (opt_set_interpreter) {
			size_t new_len = strlen(opt_set_interpreter) + 1;
			if (ctx.interp_ph_idx >= 0 && ctx.interp_filesz >= new_len) {
				/* In-place overwrite */
				memcpy(ctx.buf + ctx.interp_off, opt_set_interpreter, new_len);
				memset(ctx.buf + ctx.interp_off + new_len, 0, (size_t)ctx.interp_filesz - new_len);
				ctx.modified = 1;
			} else {
				/* Append interpreter at file end and point PT_INTERP to it */
				uint64_t new_off;
				ensure_capacity(&ctx, ctx.size + new_len + 16);
				new_off = (uint64_t)ctx.size;
				memcpy(ctx.buf + new_off, opt_set_interpreter, new_len);
				ctx.size += new_len;

				if (ctx.interp_ph_idx >= 0) {
					struct generic_phdr ph;
					if (read_phdr(&ctx, ctx.interp_ph_idx, &ph)) {
						ph.offset = new_off;
						ph.filesz = new_len;
						ph.memsz  = new_len;
						write_phdr(&ctx, &ph);
					}
				}
				if (ctx.interp_sh_idx >= 0) {
					struct generic_shdr sh;
					if (read_shdr(&ctx, ctx.interp_sh_idx, &sh)) {
						sh.offset = new_off;
						sh.size   = new_len;
						write_shdr(&ctx, &sh);
					}
				}
				ctx.modified = 1;
			}
		}

		/* Dynamic Table Operations */
		dynstr = (ctx.dynstr_off && ctx.dynstr_size) ? (const char *)(ctx.buf + ctx.dynstr_off) : NULL;

		/* 3. Print needed */
		if (do_print_needed) {
			if (ctx.dynamic_off && dynstr) {
				size_t off;
				for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn dyn;
					if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
						break;
					if (dyn.tag == DT_NEEDED && dyn.val < ctx.dynstr_size)
						printf("%s\n", dynstr + dyn.val);
				}
			}
		}

		/* 4. Print soname */
		if (do_print_soname) {
			if (ctx.dynamic_off && dynstr) {
				size_t off;
				for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn dyn;
					if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
						break;
					if (dyn.tag == DT_SONAME && dyn.val < ctx.dynstr_size)
						printf("%s\n", dynstr + dyn.val);
				}
			}
		}

		/* 5. Print rpath / runpath */
		if (do_print_rpath) {
			if (ctx.dynamic_off && dynstr) {
				size_t off;
				for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn dyn;
					if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
						break;
					if ((dyn.tag == DT_RPATH || dyn.tag == DT_RUNPATH) && dyn.val < ctx.dynstr_size)
						printf("%s\n", dynstr + dyn.val);
				}
			}
		}

		/* 6. Replace needed */
		if (opt_replace_needed_old && opt_replace_needed_new) {
			int found = 0;
			size_t off;

			if (!ctx.dynamic_off || !dynstr)
				bb_error_msg_and_die("%s: no dynamic table found", target_file);

			for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
				struct generic_dyn dyn;
				if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
					break;
				if (dyn.tag == DT_NEEDED && dyn.val < ctx.dynstr_size) {
					if (!strcmp(dynstr + dyn.val, opt_replace_needed_old)) {
						size_t old_len = strlen(opt_replace_needed_old);
						size_t new_len = strlen(opt_replace_needed_new);
						if (new_len <= old_len) {
							memcpy(ctx.buf + ctx.dynstr_off + dyn.val, opt_replace_needed_new, new_len + 1);
							memset(ctx.buf + ctx.dynstr_off + dyn.val + new_len + 1, 0, old_len - new_len);
						} else {
							uint64_t n_off = dynstr_append_string(&ctx, opt_replace_needed_new);
							dyn.val = n_off;
							write_dyn(&ctx, &dyn);
						}
						ctx.modified = 1;
						found = 1;
						break;
					}
				}
			}
			if (!found)
				bb_error_msg("%s: needed library '%s' not found", target_file, opt_replace_needed_old);
		}

		/* 7. Remove needed */
		if (opt_remove_needed) {
			if (ctx.dynamic_off && dynstr) {
				size_t off;
				for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn dyn;
					if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
						break;
					if (dyn.tag == DT_NEEDED && dyn.val < ctx.dynstr_size) {
						if (!strcmp(dynstr + dyn.val, opt_remove_needed)) {
							dyn.tag = DT_DEBUG;
							dyn.val = 0;
							write_dyn(&ctx, &dyn);
							ctx.modified = 1;
							break;
						}
					}
				}
			}
		}

		/* 8. Add needed */
		if (opt_add_needed) {
			int added = 0;
			size_t off;

			if (!ctx.dynamic_off)
				bb_error_msg_and_die("%s: no dynamic table found", target_file);

			for (off = ctx.dynamic_off; off + 2 * ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
				struct generic_dyn cur, next;
				if (read_dyn(&ctx, off, &cur) && cur.tag == DT_NULL) {
					if (read_dyn(&ctx, off + ctx.dynamic_entsize, &next) && next.tag == DT_NULL) {
						uint64_t n_off = dynstr_append_string(&ctx, opt_add_needed);
						cur.tag = DT_NEEDED;
						cur.val = n_off;
						write_dyn(&ctx, &cur);
						ctx.modified = 1;
						added = 1;
						break;
					}
				}
			}
			if (!added)
				bb_error_msg_and_die("%s: no spare dynamic entry available to add needed library", target_file);
		}

		/* 9. Set soname */
		if (opt_set_soname) {
			int found = 0;
			size_t off;

			if (!ctx.dynamic_off || !dynstr)
				bb_error_msg_and_die("%s: no dynamic table found", target_file);

			for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
				struct generic_dyn dyn;
				if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
					break;
				if (dyn.tag == DT_SONAME) {
					const char *old_soname = (dyn.val < ctx.dynstr_size) ? (dynstr + dyn.val) : "";
					size_t old_len = strlen(old_soname);
					size_t new_len = strlen(opt_set_soname);
					if (new_len <= old_len) {
						memcpy(ctx.buf + ctx.dynstr_off + dyn.val, opt_set_soname, new_len + 1);
						memset(ctx.buf + ctx.dynstr_off + dyn.val + new_len + 1, 0, old_len - new_len);
					} else {
						uint64_t n_off = dynstr_append_string(&ctx, opt_set_soname);
						dyn.val = n_off;
						write_dyn(&ctx, &dyn);
					}
					ctx.modified = 1;
					found = 1;
					break;
				}
			}
			if (!found) {
				for (off = ctx.dynamic_off; off + 2 * ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn cur, next;
					if (read_dyn(&ctx, off, &cur) && cur.tag == DT_NULL) {
						if (read_dyn(&ctx, off + ctx.dynamic_entsize, &next) && next.tag == DT_NULL) {
							uint64_t n_off = dynstr_append_string(&ctx, opt_set_soname);
							cur.tag = DT_SONAME;
							cur.val = n_off;
							write_dyn(&ctx, &cur);
							ctx.modified = 1;
							found = 1;
							break;
						}
					}
				}
			}
		}

		/* 10. Remove rpath / runpath */
		if (do_remove_rpath) {
			if (ctx.dynamic_off) {
				size_t off;
				for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn dyn;
					if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
						break;
					if (dyn.tag == DT_RPATH || dyn.tag == DT_RUNPATH) {
						dyn.tag = DT_DEBUG;
						dyn.val = 0;
						write_dyn(&ctx, &dyn);
						ctx.modified = 1;
					}
				}
			}
		}

		/* 11. Set rpath / runpath */
		if (opt_set_rpath) {
			int found = 0;
			size_t off;

			if (!ctx.dynamic_off || !dynstr)
				bb_error_msg_and_die("%s: no dynamic table found", target_file);

			for (off = ctx.dynamic_off; off + ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
				struct generic_dyn dyn;
				if (!read_dyn(&ctx, off, &dyn) || !dyn.tag)
					break;
				if (dyn.tag == DT_RUNPATH || dyn.tag == DT_RPATH) {
					const char *old_rpath = (dyn.val < ctx.dynstr_size) ? (dynstr + dyn.val) : "";
					size_t old_len = strlen(old_rpath);
					size_t new_len = strlen(opt_set_rpath);
					if (new_len <= old_len) {
						memcpy(ctx.buf + ctx.dynstr_off + dyn.val, opt_set_rpath, new_len + 1);
						memset(ctx.buf + ctx.dynstr_off + dyn.val + new_len + 1, 0, old_len - new_len);
					} else {
						uint64_t n_off = dynstr_append_string(&ctx, opt_set_rpath);
						dyn.val = n_off;
						write_dyn(&ctx, &dyn);
					}
					ctx.modified = 1;
					found = 1;
					break;
				}
			}
			if (!found) {
				for (off = ctx.dynamic_off; off + 2 * ctx.dynamic_entsize <= ctx.dynamic_off + ctx.dynamic_size; off += ctx.dynamic_entsize) {
					struct generic_dyn cur, next;
					if (read_dyn(&ctx, off, &cur) && cur.tag == DT_NULL) {
						if (read_dyn(&ctx, off + ctx.dynamic_entsize, &next) && next.tag == DT_NULL) {
							uint64_t n_off = dynstr_append_string(&ctx, opt_set_rpath);
							cur.tag = DT_RUNPATH;
							cur.val = n_off;
							write_dyn(&ctx, &cur);
							ctx.modified = 1;
							found = 1;
							break;
						}
					}
				}
			}
		}

		/* 12. Page Size Alignments (PT_LOAD segments) */
		if (do_print_page_size) {
			uint64_t max_align = 0;
			for (int pidx = 0; pidx < ctx.phnum; pidx++) {
				struct generic_phdr ph;
				if (read_phdr(&ctx, pidx, &ph) && ph.type == PT_LOAD) {
					if (ph.align > max_align)
						max_align = ph.align;
				}
			}
			printf("%s: PT_LOAD page size alignment: 0x%llx (%llu bytes)\n",
			       target_file, (unsigned long long)max_align, (unsigned long long)max_align);
		}

		if (opt_page_size) {
			for (int pidx = 0; pidx < ctx.phnum; pidx++) {
				struct generic_phdr ph;
				if (read_phdr(&ctx, pidx, &ph) && ph.type == PT_LOAD) {
					if (ph.align != opt_page_size) {
						if (!opt_quiet)
							printf("%s: Updating PT_LOAD [%d] alignment from 0x%llx to 0x%llx\n",
							       target_file, pidx, (unsigned long long)ph.align, (unsigned long long)opt_page_size);
						if (!opt_dry_run) {
							ph.align = opt_page_size;
							write_phdr(&ctx, &ph);
						}
					}
				}
			}
		}

		/* 13. termux-elf-cleaner Android dynamic cleanup */
		if (do_clean_for_android) {
			run_clean_for_android(&ctx, opt_api_level, opt_dry_run, opt_quiet);
		}

		elf_save_and_close(&ctx, (file_count == 1) ? opt_output : NULL);
	}

	return 0;
}
