/* vi: set sw=4 ts=4: */
/*
 * strip - discard symbols and debugging sections from ELF files
 *
 * Implemented in pure C for BusyBox by Rick & the BusyBox Team, 2026.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config STRIP
//config:	bool "strip (discard symbols and debug from ELF files)"
//config:	default y
//config:	help
//config:	  strip discards symbols, debugging sections, and comments
//config:	  from ELF object files and binaries to minimize size.

//applet:IF_STRIP(APPLET(strip, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_STRIP) += strip.o

//usage:#define strip_trivial_usage
//usage:       "[-s|-d|-g|-S] [-R SECTION] [-o OUTFILE] FILE..."
//usage:#define strip_full_usage "\n\n"
//usage:       "Discard symbols and sections from ELF files\n"
//usage:     "\n	-s, --strip-all		Strip all symbols and unallocated sections"
//usage:     "\n	-g, -d, -S, --strip-debug Strip debugging sections and symbols"
//usage:     "\n	--strip-unneeded	Strip symbols not needed for relocations"
//usage:     "\n	-R, --remove-section S	Remove named section (can be repeated)"
//usage:     "\n	-o FILE			Write output to FILE instead of in-place"
//usage:     "\n	-v, --verbose		Verbose progress output"

#include "libbb.h"
#include <elf.h>

struct strip_shdr {
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
	int keep;
	int is_removed;
	char *name_str;
};

struct strip_ctx {
	const char *filename;
	uint8_t *buf;
	size_t size;
	int is_64;
	int is_be;

	uint64_t phoff;
	uint16_t phentsize;
	uint16_t phnum;

	uint64_t shoff;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;

	const char *shstrtab;
	struct strip_shdr *shdrs;
};

/* Endian helpers */
static uint16_t s_get_u16(const struct strip_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return (uint16_t)((b[0] << 8) | b[1]);
	return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t s_get_u32(const struct strip_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t s_get_u64(const struct strip_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be) {
		return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
		     | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | (uint64_t)b[7];
	}
	return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint32_t)b[3] << 24)
	     | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static void s_put_u16(const struct strip_ctx *ctx, void *p, uint16_t v)
{
	uint8_t *b = (uint8_t *)p;
	if (ctx->is_be) {
		b[0] = (uint8_t)(v >> 8);
		b[1] = (uint8_t)v;
	} else {
		b[0] = (uint8_t)v;
		b[1] = (uint8_t)(v >> 8);
	}
}

static void s_put_u32(const struct strip_ctx *ctx, void *p, uint32_t v)
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

static void s_put_u64(const struct strip_ctx *ctx, void *p, uint64_t v)
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

static int s_read_shdr(const struct strip_ctx *ctx, int idx, struct strip_shdr *sh)
{
	size_t off;
	uint8_t *p;

	off = (size_t)ctx->shoff + (size_t)idx * ctx->shentsize;
	if (off + ctx->shentsize > ctx->size)
		return 0;

	p = ctx->buf + off;
	if (ctx->is_64) {
		sh->name      = s_get_u32(ctx, p + 0);
		sh->type      = s_get_u32(ctx, p + 4);
		sh->flags     = s_get_u64(ctx, p + 8);
		sh->addr      = s_get_u64(ctx, p + 16);
		sh->offset    = s_get_u64(ctx, p + 24);
		sh->size      = s_get_u64(ctx, p + 32);
		sh->link      = s_get_u32(ctx, p + 40);
		sh->info      = s_get_u32(ctx, p + 44);
		sh->addralign = s_get_u64(ctx, p + 48);
		sh->entsize   = s_get_u64(ctx, p + 56);
	} else {
		sh->name      = s_get_u32(ctx, p + 0);
		sh->type      = s_get_u32(ctx, p + 4);
		sh->flags     = s_get_u32(ctx, p + 8);
		sh->addr      = s_get_u32(ctx, p + 12);
		sh->offset    = s_get_u32(ctx, p + 16);
		sh->size      = s_get_u32(ctx, p + 20);
		sh->link      = s_get_u32(ctx, p + 24);
		sh->info      = s_get_u32(ctx, p + 28);
		sh->addralign = s_get_u32(ctx, p + 32);
		sh->entsize   = s_get_u32(ctx, p + 36);
	}
	sh->keep = 1;
	sh->is_removed = 0;
	sh->name_str = NULL;
	return 1;
}

static void s_write_shdr(const struct strip_ctx *ctx, uint8_t *dest, const struct strip_shdr *sh)
{
	if (ctx->is_64) {
		s_put_u32(ctx, dest + 0, sh->name);
		s_put_u32(ctx, dest + 4, sh->type);
		s_put_u64(ctx, dest + 8, sh->flags);
		s_put_u64(ctx, dest + 16, sh->addr);
		s_put_u64(ctx, dest + 24, sh->offset);
		s_put_u64(ctx, dest + 32, sh->size);
		s_put_u32(ctx, dest + 40, sh->link);
		s_put_u32(ctx, dest + 44, sh->info);
		s_put_u64(ctx, dest + 48, sh->addralign);
		s_put_u64(ctx, dest + 56, sh->entsize);
	} else {
		s_put_u32(ctx, dest + 0, sh->name);
		s_put_u32(ctx, dest + 4, sh->type);
		s_put_u32(ctx, dest + 8, (uint32_t)sh->flags);
		s_put_u32(ctx, dest + 12, (uint32_t)sh->addr);
		s_put_u32(ctx, dest + 16, (uint32_t)sh->offset);
		s_put_u32(ctx, dest + 20, (uint32_t)sh->size);
		s_put_u32(ctx, dest + 24, sh->link);
		s_put_u32(ctx, dest + 28, sh->info);
		s_put_u32(ctx, dest + 32, (uint32_t)sh->addralign);
		s_put_u32(ctx, dest + 36, (uint32_t)sh->entsize);
	}
}

int strip_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int strip_main(int argc, char **argv)
{
	int opt_strip_all = 0;
	int opt_strip_debug = 0;
	int opt_verbose = 0;
	const char *opt_output = NULL;
	char **remove_sections = NULL;
	int num_remove_sections = 0;
	int file_count = 0;
	int file_start_idx = 0;
	int i;

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "-s") || !strcmp(arg, "--strip-all")) {
			opt_strip_all = 1;
		} else if (!strcmp(arg, "-g") || !strcmp(arg, "-d") || !strcmp(arg, "-S") || !strcmp(arg, "--strip-debug")) {
			opt_strip_debug = 1;
		} else if (!strcmp(arg, "--strip-unneeded")) {
			opt_strip_all = 1;
		} else if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
			opt_verbose = 1;
		} else if (!strcmp(arg, "-o")) {
			if (++i >= argc) bb_show_usage();
			opt_output = argv[i];
		} else if (!strcmp(arg, "-R") || !strcmp(arg, "--remove-section")) {
			if (++i >= argc) bb_show_usage();
			remove_sections = xrealloc_vector(remove_sections, 2, num_remove_sections);
			remove_sections[num_remove_sections++] = argv[i];
		} else if (!strncmp(arg, "--remove-section=", 17)) {
			remove_sections = xrealloc_vector(remove_sections, 2, num_remove_sections);
			remove_sections[num_remove_sections++] = (char *)(arg + 17);
		} else if (arg[0] == '-' && arg[1] != '\0') {
			const char *p = arg + 1;
			while (*p) {
				if (*p == 's') opt_strip_all = 1;
				else if (*p == 'g' || *p == 'd' || *p == 'S') opt_strip_debug = 1;
				else if (*p == 'v') opt_verbose = 1;
				else bb_error_msg_and_die("invalid option -- '%c'", *p);
				p++;
			}
		} else {
			if (!file_start_idx)
				file_start_idx = i;
			file_count++;
		}
	}

	if (!file_count)
		bb_show_usage();

	/* Default to strip-all if neither -g nor -R was specified */
	if (!opt_strip_debug && !num_remove_sections)
		opt_strip_all = 1;

	for (int fidx = file_start_idx; fidx < argc; fidx++) {
		const char *filename = argv[fidx];
		int fd;
		struct stat sb;
		struct strip_ctx ctx;
		uint64_t max_load_end = 0;
		int symtab_idx = -1;
		int symtab_strtab_idx = -1;
		uint8_t *out_buf;
		size_t out_size;
		int *old_to_new;
		int new_shnum;
		uint64_t sh_align;
		uint64_t new_shoff;
		size_t sh_table_size;
		uint8_t *sh_table_dest;
		const char *dest_name;
		int out_fd;

		if (argv[fidx][0] == '-')
			continue;

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			bb_perror_msg("%s", filename);
			continue;
		}

		if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size < 45) {
			bb_error_msg("%s: invalid file", filename);
			close(fd);
			continue;
		}

		memset(&ctx, 0, sizeof(ctx));
		ctx.filename = filename;
		ctx.size = (size_t)sb.st_size;
		ctx.buf = xmalloc(ctx.size);
		xread(fd, ctx.buf, ctx.size);
		close(fd);

		if (memcmp(ctx.buf, "\177ELF", 4) != 0) {
			bb_error_msg("%s: not an ELF file", filename);
			free(ctx.buf);
			continue;
		}

		ctx.is_64 = (ctx.buf[4] == 2);
		ctx.is_be = (ctx.buf[5] == 2);

		if (ctx.is_64) {
			ctx.phoff     = s_get_u64(&ctx, ctx.buf + 32);
			ctx.shoff     = s_get_u64(&ctx, ctx.buf + 40);
			ctx.phentsize = s_get_u16(&ctx, ctx.buf + 54);
			ctx.phnum     = s_get_u16(&ctx, ctx.buf + 56);
			ctx.shentsize = s_get_u16(&ctx, ctx.buf + 58);
			ctx.shnum     = s_get_u16(&ctx, ctx.buf + 60);
			ctx.shstrndx  = s_get_u16(&ctx, ctx.buf + 62);
		} else {
			ctx.phoff     = s_get_u32(&ctx, ctx.buf + 28);
			ctx.shoff     = s_get_u32(&ctx, ctx.buf + 32);
			ctx.phentsize = s_get_u16(&ctx, ctx.buf + 42);
			ctx.phnum     = s_get_u16(&ctx, ctx.buf + 44);
			ctx.shentsize = s_get_u16(&ctx, ctx.buf + 46);
			ctx.shnum     = s_get_u16(&ctx, ctx.buf + 48);
			ctx.shstrndx  = s_get_u16(&ctx, ctx.buf + 50);
		}

		/* Find highest PT_LOAD segment end in file */
		for (i = 0; i < ctx.phnum; i++) {
			size_t poff = (size_t)ctx.phoff + (size_t)i * ctx.phentsize;
			if (poff + ctx.phentsize <= ctx.size) {
				uint8_t *pp = ctx.buf + poff;
				uint32_t ptype = s_get_u32(&ctx, pp + 0);
				if (ptype == PT_LOAD) {
					uint64_t poffset = ctx.is_64 ? s_get_u64(&ctx, pp + 8) : s_get_u32(&ctx, pp + 4);
					uint64_t pfilesz = ctx.is_64 ? s_get_u64(&ctx, pp + 32) : s_get_u32(&ctx, pp + 16);
					if (poffset + pfilesz > max_load_end)
						max_load_end = poffset + pfilesz;
				}
			}
		}

		/* Read all section headers */
		ctx.shdrs = xzalloc(ctx.shnum * sizeof(struct strip_shdr));
		for (i = 0; i < ctx.shnum; i++)
			s_read_shdr(&ctx, i, &ctx.shdrs[i]);

		/* Resolve shstrtab */
		if (ctx.shstrndx < ctx.shnum && ctx.shdrs[ctx.shstrndx].offset < ctx.size)
			ctx.shstrtab = (const char *)(ctx.buf + ctx.shdrs[ctx.shstrndx].offset);

		for (i = 0; i < ctx.shnum; i++) {
			if (ctx.shstrtab && ctx.shdrs[i].name < ctx.shdrs[ctx.shstrndx].size)
				ctx.shdrs[i].name_str = (char *)(ctx.shstrtab + ctx.shdrs[i].name);
			else
				ctx.shdrs[i].name_str = (char *)"";

			if (ctx.shdrs[i].type == SHT_SYMTAB) {
				symtab_idx = i;
				symtab_strtab_idx = (int)ctx.shdrs[i].link;
			}
		}

		/* Determine which sections to strip */
		for (i = 1; i < ctx.shnum; i++) {
			struct strip_shdr *sh = &ctx.shdrs[i];
			const char *sname = sh->name_str;

			/* Check explicit -R section removal */
			for (int r = 0; r < num_remove_sections; r++) {
				if (!strcmp(sname, remove_sections[r])) {
					sh->keep = 0;
					break;
				}
			}

			/* Debug section removal (-g or -s) */
			if (opt_strip_debug || opt_strip_all) {
				if (!strncmp(sname, ".debug", 6) || !strncmp(sname, ".zdebug", 7)
				    || !strncmp(sname, ".line", 5)) {
					sh->keep = 0;
				}
			}

			/* Full symbol removal (-s) */
			if (opt_strip_all) {
				if (i == symtab_idx || i == symtab_strtab_idx)
					sh->keep = 0;
				if (!strcmp(sname, ".comment"))
					sh->keep = 0;
				if (sh->type == SHT_NOTE && !(sh->flags & SHF_ALLOC))
					sh->keep = 0;
			}
		}

		/* Compact sections: preserve allocated sections at original offsets,
		   and pack kept unallocated sections at file tail */
		out_buf = xzalloc(ctx.size);
		out_size = (size_t)max_load_end;
		memcpy(out_buf, ctx.buf, out_size);

		old_to_new = xmalloc(ctx.shnum * sizeof(int));
		old_to_new[0] = 0;
		new_shnum = 1; /* Keep section 0 */

		for (i = 1; i < ctx.shnum; i++) {
			if (ctx.shdrs[i].keep) {
				old_to_new[i] = new_shnum++;
			} else {
				old_to_new[i] = 0;
				if (opt_verbose)
					printf("%s: stripped section %s\n", filename, ctx.shdrs[i].name_str);
			}
		}

		/* Copy kept unallocated sections */
		for (i = 1; i < ctx.shnum; i++) {
			struct strip_shdr *sh = &ctx.shdrs[i];
			uint64_t align;

			if (!sh->keep)
				continue;

			if (sh->flags & SHF_ALLOC) {
				/* Stays in the mapped loadable region */
				continue;
			}

			/* Align offset */
			align = sh->addralign ? sh->addralign : 1;
			out_size = (out_size + align - 1) & ~(align - 1);

			sh->offset = out_size;
			if (sh->type != SHT_NOBITS && sh->size > 0 && sh->offset < ctx.size) {
				out_buf = xrealloc(out_buf, out_size + sh->size);
				memcpy(out_buf + out_size, ctx.buf + ctx.shdrs[i].offset, sh->size);
				out_size += sh->size;
			}
		}

		/* Align and append new section headers */
		sh_align = ctx.is_64 ? 8 : 4;
		out_size = (out_size + sh_align - 1) & ~(sh_align - 1);
		new_shoff = out_size;

		sh_table_size = (size_t)new_shnum * ctx.shentsize;
		out_buf = xrealloc(out_buf, out_size + sh_table_size);
		sh_table_dest = out_buf + out_size;

		for (i = 0; i < ctx.shnum; i++) {
			struct strip_shdr cur;
			if (i != 0 && !ctx.shdrs[i].keep)
				continue;
			cur = ctx.shdrs[i];
			cur.link = (uint32_t)old_to_new[cur.link < ctx.shnum ? cur.link : 0];
			if (cur.type == SHT_REL || cur.type == SHT_RELA)
				cur.info = (uint32_t)old_to_new[cur.info < ctx.shnum ? cur.info : 0];

			s_write_shdr(&ctx, sh_table_dest, &cur);
			sh_table_dest += ctx.shentsize;
		}
		out_size += sh_table_size;

		/* Update ELF Header with new section header table */
		if (ctx.is_64) {
			s_put_u64(&ctx, out_buf + 40, new_shoff);
			s_put_u16(&ctx, out_buf + 60, (uint16_t)new_shnum);
			s_put_u16(&ctx, out_buf + 62, (uint16_t)old_to_new[ctx.shstrndx < ctx.shnum ? ctx.shstrndx : 0]);
		} else {
			s_put_u32(&ctx, out_buf + 32, (uint32_t)new_shoff);
			s_put_u16(&ctx, out_buf + 48, (uint16_t)new_shnum);
			s_put_u16(&ctx, out_buf + 50, (uint16_t)old_to_new[ctx.shstrndx < ctx.shnum ? ctx.shstrndx : 0]);
		}

		/* Write out stripped binary */
		dest_name = (opt_output && file_count == 1) ? opt_output : filename;
		out_fd = open(dest_name, O_WRONLY | O_CREAT | O_TRUNC, 0755);
		if (out_fd < 0)
			bb_perror_msg_and_die("%s", dest_name);

		xwrite(out_fd, out_buf, out_size);
		close(out_fd);

		free(old_to_new);
		free(out_buf);
		free(ctx.shdrs);
		free(ctx.buf);
	}

	free(remove_sections);
	return 0;
}
