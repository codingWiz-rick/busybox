/* vi: set sw=4 ts=4: */
/*
 * nm - list symbols from ELF object files and binaries
 *
 * Implemented in pure C for BusyBox by Rick & the BusyBox Team, 2026.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config NM
//config:	bool "nm (list symbols from ELF object files)"
//config:	default y
//config:	help
//config:	  nm lists symbols from ELF object files, shared libraries,
//config:	  and executables, displaying addresses, symbol types, and names.

//applet:IF_NM(APPLET(nm, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_NM) += nm.o

//usage:#define nm_trivial_usage
//usage:       "[-aADgnpruC] [FILE]..."
//usage:#define nm_full_usage "\n\n"
//usage:       "List symbols from ELF files\n"
//usage:     "\n	-a, --debug-syms	Display all symbols, including debugger-only symbols"
//usage:     "\n	-A, -o, --print-file-name Prepend file name to each symbol line"
//usage:     "\n	-D, --dynamic		Display dynamic symbols instead of normal symbols"
//usage:     "\n	-g, --extern-only	Display only external (global/weak) symbols"
//usage:     "\n	-n, -v, --numeric-sort	Sort symbols numerically by address"
//usage:     "\n	-p, --no-sort		Do not sort symbols; display in order"
//usage:     "\n	-r, --reverse-sort	Reverse the sense of the sort"
//usage:     "\n	-u, --undefined-only	Display only undefined symbols"
//usage:     "\n	--defined-only		Display only defined symbols"
//usage:     "\n	-C, --demangle		Decode low-level symbol names into user-level names"

#include "libbb.h"
#include <elf.h>
#include <sys/mman.h>

struct nm_sym {
	uint64_t val;
	uint64_t size;
	char type;
	int is_undef;
	const char *name;
};

struct nm_ctx {
	const char *filename;
	uint8_t *buf;
	size_t size;
	int is_64;
	int is_be;

	uint64_t shoff;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;

	const char *shstrtab;
};

/* Endian helpers */
static uint16_t nm_get_u16(const struct nm_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return (uint16_t)((b[0] << 8) | b[1]);
	return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t nm_get_u32(const struct nm_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t nm_get_u64(const struct nm_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be) {
		return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
		     | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | (uint64_t)b[7];
	}
	return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint32_t)b[3] << 24)
	     | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

struct nm_shdr {
	uint32_t name;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t entsize;
};

static int nm_read_shdr(const struct nm_ctx *ctx, int idx, struct nm_shdr *sh)
{
	size_t off;
	uint8_t *p;

	off = (size_t)ctx->shoff + (size_t)idx * ctx->shentsize;
	if (off + ctx->shentsize > ctx->size)
		return 0;

	p = ctx->buf + off;
	if (ctx->is_64) {
		sh->name    = nm_get_u32(ctx, p + 0);
		sh->type    = nm_get_u32(ctx, p + 4);
		sh->flags   = nm_get_u64(ctx, p + 8);
		sh->addr    = nm_get_u64(ctx, p + 16);
		sh->offset  = nm_get_u64(ctx, p + 24);
		sh->size    = nm_get_u64(ctx, p + 32);
		sh->link    = nm_get_u32(ctx, p + 40);
		sh->info    = nm_get_u32(ctx, p + 44);
		sh->entsize = nm_get_u64(ctx, p + 56);
	} else {
		sh->name    = nm_get_u32(ctx, p + 0);
		sh->type    = nm_get_u32(ctx, p + 4);
		sh->flags   = nm_get_u32(ctx, p + 8);
		sh->addr    = nm_get_u32(ctx, p + 12);
		sh->offset  = nm_get_u32(ctx, p + 16);
		sh->size    = nm_get_u32(ctx, p + 20);
		sh->link    = nm_get_u32(ctx, p + 24);
		sh->info    = nm_get_u32(ctx, p + 28);
		sh->entsize = nm_get_u32(ctx, p + 36);
	}
	return 1;
}

static char get_symbol_type_char(const struct nm_ctx *ctx, uint16_t shndx, uint8_t info, uint8_t other)
{
	uint8_t bind = info >> 4;
	uint8_t type = info & 0xf;
	char c = '?';

	(void)other;

	if (bind == STB_WEAK) {
		if (type == STT_OBJECT)
			c = (shndx == SHN_UNDEF) ? 'v' : 'V';
		else
			c = (shndx == SHN_UNDEF) ? 'w' : 'W';
		return c;
	}

	if (shndx == SHN_UNDEF)
		return 'U';
	if (shndx == SHN_ABS)
		return (bind == STB_GLOBAL) ? 'A' : 'a';
	if (shndx == SHN_COMMON)
		return 'C';

	if (shndx < ctx->shnum) {
		struct nm_shdr sh;
		if (nm_read_shdr(ctx, shndx, &sh)) {
			if (sh.flags & SHF_EXECINSTR) {
				c = 'T';
			} else if ((sh.flags & SHF_ALLOC) && (sh.flags & SHF_WRITE)) {
				c = (sh.type == SHT_NOBITS) ? 'B' : 'D';
			} else if (sh.flags & SHF_ALLOC) {
				c = 'R';
			} else if (sh.type == SHT_PROGBITS || sh.type == SHT_NOTE) {
				c = 'N';
			} else {
				c = 'D';
			}
		}
	}

	if (bind == STB_LOCAL && c >= 'A' && c <= 'Z')
		c = (char)(c + ('a' - 'A'));

	return c;
}

static int sym_cmp_alpha(const void *a, const void *b)
{
	const struct nm_sym *sa = (const struct nm_sym *)a;
	const struct nm_sym *sb = (const struct nm_sym *)b;
	int res = strcmp(sa->name, sb->name);
	if (!res) {
		if (sa->val < sb->val) return -1;
		if (sa->val > sb->val) return 1;
	}
	return res;
}

static int sym_cmp_numeric(const void *a, const void *b)
{
	const struct nm_sym *sa = (const struct nm_sym *)a;
	const struct nm_sym *sb = (const struct nm_sym *)b;
	if (sa->val < sb->val) return -1;
	if (sa->val > sb->val) return 1;
	return strcmp(sa->name, sb->name);
}

int nm_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int nm_main(int argc, char **argv)
{
	int opt_debug_syms = 0;
	int opt_print_file = 0;
	int opt_dynamic = 0;
	int opt_extern_only = 0;
	int opt_numeric_sort = 0;
	int opt_no_sort = 0;
	int opt_reverse_sort = 0;
	int opt_undefined_only = 0;
	int opt_defined_only = 0;
	int file_count = 0;
	int file_start_idx = 0;
	int i;

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "-a") || !strcmp(arg, "--debug-syms")) {
			opt_debug_syms = 1;
		} else if (!strcmp(arg, "-A") || !strcmp(arg, "-o") || !strcmp(arg, "--print-file-name")) {
			opt_print_file = 1;
		} else if (!strcmp(arg, "-D") || !strcmp(arg, "--dynamic")) {
			opt_dynamic = 1;
		} else if (!strcmp(arg, "-g") || !strcmp(arg, "--extern-only")) {
			opt_extern_only = 1;
		} else if (!strcmp(arg, "-n") || !strcmp(arg, "-v") || !strcmp(arg, "--numeric-sort")) {
			opt_numeric_sort = 1;
		} else if (!strcmp(arg, "-p") || !strcmp(arg, "--no-sort")) {
			opt_no_sort = 1;
		} else if (!strcmp(arg, "-r") || !strcmp(arg, "--reverse-sort")) {
			opt_reverse_sort = 1;
		} else if (!strcmp(arg, "-u") || !strcmp(arg, "--undefined-only")) {
			opt_undefined_only = 1;
		} else if (!strcmp(arg, "--defined-only")) {
			opt_defined_only = 1;
		} else if (!strcmp(arg, "-C") || !strcmp(arg, "--demangle")) {
			/* Accepted for compatibility */
		} else if (arg[0] == '-' && arg[1] != '\0') {
			/* Check multiple short flags */
			const char *p = arg + 1;
			while (*p) {
				if (*p == 'a') opt_debug_syms = 1;
				else if (*p == 'A' || *p == 'o') opt_print_file = 1;
				else if (*p == 'D') opt_dynamic = 1;
				else if (*p == 'g') opt_extern_only = 1;
				else if (*p == 'n' || *p == 'v') opt_numeric_sort = 1;
				else if (*p == 'p') opt_no_sort = 1;
				else if (*p == 'r') opt_reverse_sort = 1;
				else if (*p == 'u') opt_undefined_only = 1;
				else if (*p == 'C') {}
				else bb_error_msg_and_die("invalid option -- '%c'", *p);
				p++;
			}
		} else {
			if (!file_start_idx)
				file_start_idx = i;
			file_count++;
		}
	}

	if (!file_count) {
		/* Default to a.out if no file specified */
		argv[argc] = (char *)"a.out";
		file_start_idx = argc;
		file_count = 1;
		argc++;
	}

	for (int fidx = file_start_idx; fidx < argc; fidx++) {
		const char *filename = argv[fidx];
		int fd;
		struct stat sb;
		struct nm_ctx ctx;
		int symtab_idx = -1;
		int dynsym_idx = -1;
		int target_idx;
		struct nm_shdr sym_sh;
		struct nm_shdr str_sh;
		const char *strtab;
		size_t sym_entsize;
		size_t num_syms;
		struct nm_sym *symbols;
		size_t sym_count = 0;

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
		ctx.buf = mmap(NULL, ctx.size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);

		if (ctx.buf == MAP_FAILED) {
			bb_perror_msg("%s: mmap", filename);
			continue;
		}

		if (memcmp(ctx.buf, "\177ELF", 4) != 0) {
			bb_error_msg("%s: file format not recognized", filename);
			munmap(ctx.buf, ctx.size);
			continue;
		}

		ctx.is_64 = (ctx.buf[4] == 2);
		ctx.is_be = (ctx.buf[5] == 2);

		if (ctx.is_64) {
			ctx.shoff     = nm_get_u64(&ctx, ctx.buf + 40);
			ctx.shentsize = nm_get_u16(&ctx, ctx.buf + 58);
			ctx.shnum     = nm_get_u16(&ctx, ctx.buf + 60);
			ctx.shstrndx  = nm_get_u16(&ctx, ctx.buf + 62);
		} else {
			ctx.shoff     = nm_get_u32(&ctx, ctx.buf + 32);
			ctx.shentsize = nm_get_u16(&ctx, ctx.buf + 46);
			ctx.shnum     = nm_get_u16(&ctx, ctx.buf + 48);
			ctx.shstrndx  = nm_get_u16(&ctx, ctx.buf + 50);
		}

		/* Find section headers */
		for (i = 0; i < ctx.shnum; i++) {
			struct nm_shdr sh;
			if (nm_read_shdr(&ctx, i, &sh)) {
				if (sh.type == SHT_SYMTAB)
					symtab_idx = i;
				else if (sh.type == SHT_DYNSYM)
					dynsym_idx = i;
			}
		}

		target_idx = opt_dynamic ? dynsym_idx : (symtab_idx >= 0 ? symtab_idx : dynsym_idx);
		if (target_idx < 0) {
			bb_error_msg("%s: no symbols", filename);
			munmap(ctx.buf, ctx.size);
			continue;
		}

		if (!nm_read_shdr(&ctx, target_idx, &sym_sh) || !nm_read_shdr(&ctx, sym_sh.link, &str_sh)) {
			bb_error_msg("%s: corrupt symbol table", filename);
			munmap(ctx.buf, ctx.size);
			continue;
		}

		strtab = (const char *)(ctx.buf + str_sh.offset);
		sym_entsize = ctx.is_64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
		num_syms = sym_sh.size / sym_entsize;

		if (!num_syms) {
			munmap(ctx.buf, ctx.size);
			continue;
		}

		symbols = xzalloc(num_syms * sizeof(struct nm_sym));
		sym_count = 0;

		for (size_t sidx = 0; sidx < num_syms; sidx++) {
			uint8_t *sp = ctx.buf + sym_sh.offset + sidx * sym_entsize;
			uint32_t st_name;
			uint64_t st_value;
			uint64_t st_size;
			uint8_t st_info;
			uint8_t st_other;
			uint16_t st_shndx;
			const char *sname;
			char type_char;
			uint8_t bind;
			uint8_t st_type;

			if (ctx.is_64) {
				st_name  = nm_get_u32(&ctx, sp + 0);
				st_info  = sp[4];
				st_other = sp[5];
				st_shndx = nm_get_u16(&ctx, sp + 6);
				st_value = nm_get_u64(&ctx, sp + 8);
				st_size  = nm_get_u64(&ctx, sp + 16);
			} else {
				st_name  = nm_get_u32(&ctx, sp + 0);
				st_value = nm_get_u32(&ctx, sp + 4);
				st_size  = nm_get_u32(&ctx, sp + 8);
				st_info  = sp[12];
				st_other = sp[13];
				st_shndx = nm_get_u16(&ctx, sp + 14);
			}

			bind = st_info >> 4;
			st_type = st_info & 0xf;

			sname = (st_name < str_sh.size) ? (strtab + st_name) : "";
			if (!*sname)
				continue;

			if (!opt_debug_syms && st_type == STT_FILE)
				continue;
			if (opt_extern_only && bind != STB_GLOBAL && bind != STB_WEAK)
				continue;
			if (opt_undefined_only && st_shndx != SHN_UNDEF)
				continue;
			if (opt_defined_only && st_shndx == SHN_UNDEF)
				continue;

			type_char = get_symbol_type_char(&ctx, st_shndx, st_info, st_other);

			symbols[sym_count].val = st_value;
			symbols[sym_count].size = st_size;
			symbols[sym_count].type = type_char;
			symbols[sym_count].is_undef = (st_shndx == SHN_UNDEF);
			symbols[sym_count].name = sname;
			sym_count++;
		}

		/* Sort symbols */
		if (!opt_no_sort) {
			qsort(symbols, sym_count, sizeof(struct nm_sym),
			      opt_numeric_sort ? sym_cmp_numeric : sym_cmp_alpha);
		}

		if (file_count > 1 && !opt_print_file)
			printf("\n%s:\n", filename);

		/* Print symbols */
		for (size_t sidx = 0; sidx < sym_count; sidx++) {
			size_t idx = opt_reverse_sort ? (sym_count - 1 - sidx) : sidx;
			const struct nm_sym *s = &symbols[idx];

			if (opt_print_file)
				printf("%s:", filename);

			if (s->is_undef) {
				if (ctx.is_64)
					printf("                 %c %s\n", s->type, s->name);
				else
					printf("         %c %s\n", s->type, s->name);
			} else {
				if (ctx.is_64)
					printf("%016llx %c %s\n", (unsigned long long)s->val, s->type, s->name);
				else
					printf("%08llx %c %s\n", (unsigned long long)s->val, s->type, s->name);
			}
		}

		free(symbols);
		munmap(ctx.buf, ctx.size);
	}

	return 0;
}
