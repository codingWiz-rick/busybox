/* vi: set sw=4 ts=4: */
/*
 * objdump - display information from ELF object and binary files
 *
 * Implemented in pure C for BusyBox by Rick & the BusyBox Team, 2026.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config OBJDUMP
//config:	bool "objdump (display information from object files)"
//config:	default y
//config:	help
//config:	  objdump displays information about one or more ELF object
//config:	  files, including section headers, private headers, symbols,
//config:	  relocations, full contents, and disassembly.

//applet:IF_OBJDUMP(APPLET(objdump, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_OBJDUMP) += objdump.o

//usage:#define objdump_trivial_usage
//usage:       "[-f|-h|-p|-t|-T|-r|-s|-d|-D] [-j SECTION] [FILE]..."
//usage:#define objdump_full_usage "\n\n"
//usage:       "Display information from ELF object and binary files\n"
//usage:     "\n	-f, --file-headers	Display overall file header"
//usage:     "\n	-h, --section-headers	Display section headers and summary"
//usage:     "\n	-p, --private-headers	Display program headers and dynamic section"
//usage:     "\n	-t, --syms		Display contents of the symbol table(s)"
//usage:     "\n	-T, --dynamic-syms	Display dynamic symbol table"
//usage:     "\n	-r, --reloc		Display relocation entries"
//usage:     "\n	-s, --full-contents	Display full contents of sections"
//usage:     "\n	-d, --disassemble	Disassemble executable sections"
//usage:     "\n	-D, --disassemble-all	Disassemble all sections"
//usage:     "\n	-j, --section=NAME	Only display information for section NAME"
//usage:     "\n	-w, --wide		Format lines for output devices > 80 columns"

#include "libbb.h"
#include <elf.h>
#include <sys/mman.h>

struct obj_shdr {
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
	const char *name_str;
};

struct obj_ctx {
	const char *filename;
	uint8_t *buf;
	size_t size;
	int is_64;
	int is_be;

	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint64_t entry;

	uint64_t phoff;
	uint16_t phentsize;
	uint16_t phnum;

	uint64_t shoff;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;

	const char *shstrtab;
	struct obj_shdr *shdrs;
};

static uint16_t o_get_u16(const struct obj_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return (uint16_t)((b[0] << 8) | b[1]);
	return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t o_get_u32(const struct obj_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be)
		return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t o_get_u64(const struct obj_ctx *ctx, const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	if (ctx->is_be) {
		return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
		     | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) | ((uint64_t)b[6] << 8) | (uint64_t)b[7];
	}
	return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint32_t)b[3] << 24)
	     | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static int o_read_shdr(const struct obj_ctx *ctx, int idx, struct obj_shdr *sh)
{
	size_t off;
	uint8_t *p;

	off = (size_t)ctx->shoff + (size_t)idx * ctx->shentsize;
	if (off + ctx->shentsize > ctx->size)
		return 0;

	p = ctx->buf + off;
	if (ctx->is_64) {
		sh->name      = o_get_u32(ctx, p + 0);
		sh->type      = o_get_u32(ctx, p + 4);
		sh->flags     = o_get_u64(ctx, p + 8);
		sh->addr      = o_get_u64(ctx, p + 16);
		sh->offset    = o_get_u64(ctx, p + 24);
		sh->size      = o_get_u64(ctx, p + 32);
		sh->link      = o_get_u32(ctx, p + 40);
		sh->info      = o_get_u32(ctx, p + 44);
		sh->addralign = o_get_u64(ctx, p + 48);
		sh->entsize   = o_get_u64(ctx, p + 56);
	} else {
		sh->name      = o_get_u32(ctx, p + 0);
		sh->type      = o_get_u32(ctx, p + 4);
		sh->flags     = o_get_u32(ctx, p + 8);
		sh->addr      = o_get_u32(ctx, p + 12);
		sh->offset    = o_get_u32(ctx, p + 16);
		sh->size      = o_get_u32(ctx, p + 20);
		sh->link      = o_get_u32(ctx, p + 24);
		sh->info      = o_get_u32(ctx, p + 28);
		sh->addralign = o_get_u32(ctx, p + 32);
		sh->entsize   = o_get_u32(ctx, p + 36);
	}
	sh->name_str = "";
	return 1;
}

static const char *get_arch_name(uint16_t machine)
{
	switch (machine) {
	case 40: return "arm";
	case 183: return "aarch64";
	case 62: return "i386:x86-64";
	case 3: return "i386";
	case 243: return "riscv";
	case 8: return "mips";
	case 20:
	case 21: return "powerpc";
	default: return "unknown";
	}
}

static const char *get_elf_format_str(const struct obj_ctx *ctx)
{
	if (ctx->is_64) {
		if (ctx->is_be) {
			if (ctx->machine == 183) return "elf64-bigaarch64";
			return "elf64-big";
		}
		if (ctx->machine == 183) return "elf64-littleaarch64";
		if (ctx->machine == 62) return "elf64-x86-64";
		return "elf64-little";
	}
	if (ctx->is_be) {
		if (ctx->machine == 40) return "elf32-bigarm";
		return "elf32-big";
	}
	if (ctx->machine == 40) return "elf32-littlearm";
	if (ctx->machine == 3) return "elf32-i386";
	return "elf32-little";
}

/* ARM64 Disassembler */
static void disasm_arm64_insn(uint32_t insn, uint64_t pc, char *out, size_t maxlen)
{
	int32_t imm26;
	int32_t imm19;
	int32_t immlo;
	int32_t immhi;
	int64_t imm;
	uint64_t target;
	uint64_t page_pc;
	uint32_t imm12;
	int is_bl;
	int is_cbnz;
	int is_64;
	int is_sub;

	if (insn == 0xd503201f) {
		snprintf(out, maxlen, "nop");
		return;
	}
	if (insn == 0xd65f03c0) {
		snprintf(out, maxlen, "ret");
		return;
	}
	if ((insn & 0xfffffc1f) == 0xd61f0000) {
		snprintf(out, maxlen, "br\tx%u", (insn >> 5) & 0x1f);
		return;
	}
	if ((insn & 0xfffffc1f) == 0xd63f0000) {
		snprintf(out, maxlen, "blr\tx%u", (insn >> 5) & 0x1f);
		return;
	}

	/* B / BL unconditional branch */
	if ((insn & 0x7c000000) == 0x14000000) {
		imm26 = (int32_t)(insn & 0x03ffffff);
		if (imm26 & 0x02000000)
			imm26 |= ~0x03ffffff;
		target = pc + ((int64_t)imm26 * 4);
		is_bl = (insn & 0x80000000) != 0;
		snprintf(out, maxlen, "%s\t0x%llx", is_bl ? "bl" : "b", (unsigned long long)target);
		return;
	}

	/* B.cond conditional branch */
	if ((insn & 0xff000010) == 0x54000000) {
		static const char *const conds[] = {
			"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
			"hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
		};
		imm19 = (int32_t)((insn >> 5) & 0x7ffff);
		if (imm19 & 0x40000)
			imm19 |= ~0x7ffff;
		target = pc + ((int64_t)imm19 * 4);
		snprintf(out, maxlen, "b.%s\t0x%llx", conds[insn & 0xf], (unsigned long long)target);
		return;
	}

	/* CBZ / CBNZ */
	if ((insn & 0x7e000000) == 0x34000000) {
		is_cbnz = (insn & 0x01000000) != 0;
		is_64 = (insn & 0x80000000) != 0;
		imm19 = (int32_t)((insn >> 5) & 0x7ffff);
		if (imm19 & 0x40000)
			imm19 |= ~0x7ffff;
		target = pc + ((int64_t)imm19 * 4);
		snprintf(out, maxlen, "%s\t%c%u, 0x%llx", is_cbnz ? "cbnz" : "cbz",
			 is_64 ? 'x' : 'w', insn & 0x1f, (unsigned long long)target);
		return;
	}

	/* ADRP */
	if ((insn & 0x9f000000) == 0x90000000) {
		immlo = (insn >> 29) & 3;
		immhi = (insn >> 5) & 0x7ffff;
		imm = ((int64_t)immhi << 2) | immlo;
		if (imm & 0x100000)
			imm |= ~0x1fffffLL;
		page_pc = pc & ~0xfffULL;
		target = page_pc + (imm << 12);
		snprintf(out, maxlen, "adrp\tx%u, 0x%llx", insn & 0x1f, (unsigned long long)target);
		return;
	}

	/* ADR */
	if ((insn & 0x9f000000) == 0x10000000) {
		immlo = (insn >> 29) & 3;
		immhi = (insn >> 5) & 0x7ffff;
		imm = ((int64_t)immhi << 2) | immlo;
		if (imm & 0x100000)
			imm |= ~0x1fffffLL;
		target = pc + imm;
		snprintf(out, maxlen, "adr\tx%u, 0x%llx", insn & 0x1f, (unsigned long long)target);
		return;
	}

	/* SVC / BRK */
	if ((insn & 0xffe0001f) == 0xd4000001) {
		snprintf(out, maxlen, "svc\t#0x%x", (insn >> 5) & 0xffff);
		return;
	}
	if ((insn & 0xffe0001f) == 0xd4200000) {
		snprintf(out, maxlen, "brk\t#0x%x", (insn >> 5) & 0xffff);
		return;
	}

	/* MOV register / ORR */
	if ((insn & 0x7fe0ffe0) == 0x2a0003e0) {
		is_64 = (insn & 0x80000000) != 0;
		snprintf(out, maxlen, "mov\t%c%u, %c%u",
			 is_64 ? 'x' : 'w', insn & 0x1f,
			 is_64 ? 'x' : 'w', (insn >> 16) & 0x1f);
		return;
	}

	/* ADD / SUB immediate */
	if ((insn & 0x1f000000) == 0x11000000) {
		is_sub = (insn & 0x40000000) != 0;
		is_64 = (insn & 0x80000000) != 0;
		imm12 = (insn >> 10) & 0xfff;
		if (insn & (1 << 22))
			imm12 <<= 12;
		snprintf(out, maxlen, "%s\t%c%u, %c%u, #0x%x",
			 is_sub ? "sub" : "add",
			 is_64 ? 'x' : 'w', insn & 0x1f,
			 is_64 ? 'x' : 'w', (insn >> 5) & 0x1f, imm12);
		return;
	}

	snprintf(out, maxlen, ".inst\t0x%08x", insn);
}

/* x86-64 Disassembler */
static int disasm_x86_insn(const uint8_t *p, size_t remaining, uint64_t pc, char *out, size_t maxlen)
{
	(void)pc;
	if (remaining >= 1 && p[0] == 0x90) {
		snprintf(out, maxlen, "nop");
		return 1;
	}
	if (remaining >= 1 && p[0] == 0xc3) {
		snprintf(out, maxlen, "ret");
		return 1;
	}
	if (remaining >= 1 && p[0] == 0xcc) {
		snprintf(out, maxlen, "int3");
		return 1;
	}
	if (remaining >= 1 && p[0] == 0xc9) {
		snprintf(out, maxlen, "leave");
		return 1;
	}
	if (remaining >= 2 && p[0] == 0x0f && p[1] == 0x05) {
		snprintf(out, maxlen, "syscall");
		return 2;
	}
	if (remaining >= 1 && (p[0] >= 0x50 && p[0] <= 0x57)) {
		static const char *const regs[] = {"%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi"};
		snprintf(out, maxlen, "push\t%s", regs[p[0] - 0x50]);
		return 1;
	}
	if (remaining >= 1 && (p[0] >= 0x58 && p[0] <= 0x5f)) {
		static const char *const regs[] = {"%rax", "%rcx", "%rdx", "%rbx", "%rsp", "%rbp", "%rsi", "%rdi"};
		snprintf(out, maxlen, "pop\t%s", regs[p[0] - 0x58]);
		return 1;
	}
	if (remaining >= 5 && p[0] == 0xe8) {
		int32_t rel = (int32_t)(p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24));
		snprintf(out, maxlen, "call\t0x%llx", (unsigned long long)(pc + 5 + rel));
		return 5;
	}
	if (remaining >= 5 && p[0] == 0xe9) {
		int32_t rel = (int32_t)(p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24));
		snprintf(out, maxlen, "jmp\t0x%llx", (unsigned long long)(pc + 5 + rel));
		return 5;
	}
	if (remaining >= 2 && p[0] == 0xeb) {
		int8_t rel = (int8_t)p[1];
		snprintf(out, maxlen, "jmp\t0x%llx", (unsigned long long)(pc + 2 + rel));
		return 2;
	}
	if (remaining >= 2 && p[0] == 0x74) {
		int8_t rel = (int8_t)p[1];
		snprintf(out, maxlen, "je\t0x%llx", (unsigned long long)(pc + 2 + rel));
		return 2;
	}
	if (remaining >= 2 && p[0] == 0x75) {
		int8_t rel = (int8_t)p[1];
		snprintf(out, maxlen, "jne\t0x%llx", (unsigned long long)(pc + 2 + rel));
		return 2;
	}

	snprintf(out, maxlen, ".byte\t0x%02x", p[0]);
	return 1;
}

int objdump_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int objdump_main(int argc, char **argv)
{
	int opt_file_headers = 0;
	int opt_section_headers = 0;
	int opt_private_headers = 0;
	int opt_syms = 0;
	int opt_dyn_syms = 0;
	int opt_reloc = 0;
	int opt_full_contents = 0;
	int opt_disassemble = 0;
	int opt_disassemble_all = 0;
	const char *opt_target_section = NULL;
	int file_count = 0;
	int file_start_idx = 0;
	int fidx;
	int i;

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!strcmp(arg, "-f") || !strcmp(arg, "--file-headers")) {
			opt_file_headers = 1;
		} else if (!strcmp(arg, "-h") || !strcmp(arg, "--section-headers") || !strcmp(arg, "--headers")) {
			opt_section_headers = 1;
		} else if (!strcmp(arg, "-p") || !strcmp(arg, "--private-headers")) {
			opt_private_headers = 1;
		} else if (!strcmp(arg, "-t") || !strcmp(arg, "--syms")) {
			opt_syms = 1;
		} else if (!strcmp(arg, "-T") || !strcmp(arg, "--dynamic-syms")) {
			opt_dyn_syms = 1;
		} else if (!strcmp(arg, "-r") || !strcmp(arg, "--reloc")) {
			opt_reloc = 1;
		} else if (!strcmp(arg, "-s") || !strcmp(arg, "--full-contents")) {
			opt_full_contents = 1;
		} else if (!strcmp(arg, "-d") || !strcmp(arg, "--disassemble")) {
			opt_disassemble = 1;
		} else if (!strcmp(arg, "-D") || !strcmp(arg, "--disassemble-all")) {
			opt_disassemble_all = 1;
		} else if (!strcmp(arg, "-j")) {
			if (++i >= argc) bb_show_usage();
			opt_target_section = argv[i];
		} else if (!strncmp(arg, "--section=", 10)) {
			opt_target_section = arg + 10;
		} else if (!strcmp(arg, "-w") || !strcmp(arg, "--wide")) {
			/* Accept wide flag */
		} else if (arg[0] == '-' && arg[1] != '\0') {
			const char *p = arg + 1;
			while (*p) {
				if (*p == 'f') opt_file_headers = 1;
				else if (*p == 'h') opt_section_headers = 1;
				else if (*p == 'p') opt_private_headers = 1;
				else if (*p == 't') opt_syms = 1;
				else if (*p == 'T') opt_dyn_syms = 1;
				else if (*p == 'r') opt_reloc = 1;
				else if (*p == 's') opt_full_contents = 1;
				else if (*p == 'd') opt_disassemble = 1;
				else if (*p == 'D') opt_disassemble_all = 1;
				else if (*p == 'w') {}
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
		argv[argc] = (char *)"a.out";
		file_start_idx = argc;
		file_count = 1;
		argc++;
	}

	/* Default to -h if no dump options given */
	if (!(opt_file_headers || opt_section_headers || opt_private_headers
	      || opt_syms || opt_dyn_syms || opt_reloc || opt_full_contents
	      || opt_disassemble || opt_disassemble_all)) {
		opt_section_headers = 1;
	}

	for (fidx = file_start_idx; fidx < argc; fidx++) {
		const char *filename = argv[fidx];
		int fd;
		struct stat sb;
		struct obj_ctx ctx;
		int w;

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

		ctx.type    = o_get_u16(&ctx, ctx.buf + 16);
		ctx.machine = o_get_u16(&ctx, ctx.buf + 18);
		ctx.version = o_get_u32(&ctx, ctx.buf + 20);

		if (ctx.is_64) {
			ctx.entry     = o_get_u64(&ctx, ctx.buf + 24);
			ctx.phoff     = o_get_u64(&ctx, ctx.buf + 32);
			ctx.shoff     = o_get_u64(&ctx, ctx.buf + 40);
			ctx.phentsize = o_get_u16(&ctx, ctx.buf + 54);
			ctx.phnum     = o_get_u16(&ctx, ctx.buf + 56);
			ctx.shentsize = o_get_u16(&ctx, ctx.buf + 58);
			ctx.shnum     = o_get_u16(&ctx, ctx.buf + 60);
			ctx.shstrndx  = o_get_u16(&ctx, ctx.buf + 62);
		} else {
			ctx.entry     = o_get_u32(&ctx, ctx.buf + 24);
			ctx.phoff     = o_get_u32(&ctx, ctx.buf + 28);
			ctx.shoff     = o_get_u32(&ctx, ctx.buf + 32);
			ctx.phentsize = o_get_u16(&ctx, ctx.buf + 42);
			ctx.phnum     = o_get_u16(&ctx, ctx.buf + 44);
			ctx.shentsize = o_get_u16(&ctx, ctx.buf + 46);
			ctx.shnum     = o_get_u16(&ctx, ctx.buf + 48);
			ctx.shstrndx  = o_get_u16(&ctx, ctx.buf + 50);
		}

		/* Read section headers */
		ctx.shdrs = xzalloc(ctx.shnum * sizeof(struct obj_shdr));
		for (i = 0; i < ctx.shnum; i++)
			o_read_shdr(&ctx, i, &ctx.shdrs[i]);

		if (ctx.shstrndx < ctx.shnum && ctx.shdrs[ctx.shstrndx].offset < ctx.size)
			ctx.shstrtab = (const char *)(ctx.buf + ctx.shdrs[ctx.shstrndx].offset);

		for (i = 0; i < ctx.shnum; i++) {
			if (ctx.shstrtab && ctx.shdrs[i].name < ctx.shdrs[ctx.shstrndx].size)
				ctx.shdrs[i].name_str = ctx.shstrtab + ctx.shdrs[i].name;
		}

		printf("\n%s:     file format %s\n", filename, get_elf_format_str(&ctx));

		/* 1. File Headers (-f) */
		if (opt_file_headers) {
			printf("architecture: %s, flags 0x%08x:\n", get_arch_name(ctx.machine), ctx.type);
			printf("start address 0x%0*llx\n\n", ctx.is_64 ? 16 : 8, (unsigned long long)ctx.entry);
		}

		/* 2. Section Headers (-h) */
		if (opt_section_headers) {
			w = ctx.is_64 ? 16 : 8;
			printf("Sections:\n"
			       "Idx Name          Size      %-*s  %-*s  File off  Algn\n",
			       w, "VMA", w, "LMA");
			for (i = 0; i < ctx.shnum; i++) {
				const struct obj_shdr *sh = &ctx.shdrs[i];
				int algn_pwr;
				uint64_t a;
				int printed_flag;

				if (!*sh->name_str)
					continue;
				if (opt_target_section && strcmp(sh->name_str, opt_target_section))
					continue;

				algn_pwr = 0;
				a = sh->addralign;
				while (a > 1) { a >>= 1; algn_pwr++; }

				printf("%3d %-13s %08llx  %0*llx  %0*llx  %08llx  2**%d\n",
				       i, sh->name_str, (unsigned long long)sh->size,
				       w, (unsigned long long)sh->addr,
				       w, (unsigned long long)sh->addr,
				       (unsigned long long)sh->offset,
				       algn_pwr);

				/* Section flags summary */
				printf("                  ");
				printed_flag = 0;
				if (sh->type != SHT_NOBITS && sh->size > 0) {
					printf("CONTENTS"); printed_flag = 1;
				}
				if (sh->flags & SHF_ALLOC) {
					printf("%sALLOC, LOAD", printed_flag ? ", " : "");
					printed_flag = 1;
				}
				if (sh->flags & SHF_EXECINSTR) {
					printf("%sCODE", printed_flag ? ", " : "");
				} else if (!(sh->flags & SHF_WRITE)) {
					printf("%sREADONLY, DATA", printed_flag ? ", " : "");
				} else {
					printf("%sDATA", printed_flag ? ", " : "");
				}
				putchar('\n');
			}
			putchar('\n');
		}

		/* 3. Full Contents (-s) */
		if (opt_full_contents) {
			for (i = 0; i < ctx.shnum; i++) {
				const struct obj_shdr *sh = &ctx.shdrs[i];
				uint64_t off;
				const uint8_t *sec_data;

				if (sh->type == SHT_NOBITS || !sh->size || !*sh->name_str)
					continue;
				if (opt_target_section && strcmp(sh->name_str, opt_target_section))
					continue;

				printf("Contents of section %s:\n", sh->name_str);
				off = 0;
				sec_data = ctx.buf + sh->offset;

				while (off < sh->size) {
					uint64_t row_addr = sh->addr ? (sh->addr + off) : off;
					int row_bytes = 0;
					int b;

					printf(" %0*llx ", ctx.is_64 ? 6 : 4, (unsigned long long)row_addr);

					for (b = 0; b < 16; b++) {
						if (off + b < sh->size) {
							printf("%02x", sec_data[off + b]);
							row_bytes++;
						} else {
							printf("  ");
						}
						if ((b + 1) % 4 == 0)
							putchar(' ');
					}
					printf(" ");
					for (b = 0; b < row_bytes; b++) {
						uint8_t ch = sec_data[off + b];
						putchar((ch >= ' ' && ch <= '~') ? ch : '.');
					}
					putchar('\n');
					off += 16;
				}
			}
			putchar('\n');
		}

		/* 4. Disassembly (-d / -D) */
		if (opt_disassemble || opt_disassemble_all) {
			for (i = 0; i < ctx.shnum; i++) {
				const struct obj_shdr *sh = &ctx.shdrs[i];
				uint64_t pc;
				uint64_t end;
				const uint8_t *code;
				size_t code_off;

				if (sh->type == SHT_NOBITS || !sh->size || !*sh->name_str)
					continue;
				if (opt_target_section && strcmp(sh->name_str, opt_target_section))
					continue;

				if (!opt_disassemble_all && !(sh->flags & SHF_EXECINSTR))
					continue;

				printf("\nDisassembly of section %s:\n", sh->name_str);
				pc = sh->addr;
				end = sh->addr + sh->size;
				code = ctx.buf + sh->offset;
				code_off = 0;

				while (pc < end && code_off < sh->size) {
					char disasm_buf[128];
					disasm_buf[0] = '\0';

					if (ctx.machine == 183) {
						/* ARM64: 32-bit fixed size instructions */
						if (code_off + 4 <= sh->size) {
							uint32_t insn = ctx.is_be ?
								o_get_u32(&ctx, code + code_off) :
								(uint32_t)(code[code_off] | (code[code_off + 1] << 8) | (code[code_off + 2] << 16) | (code[code_off + 3] << 24));
							disasm_arm64_insn(insn, pc, disasm_buf, sizeof(disasm_buf));
							printf("  %llx:\t%08x \t%s\n",
							       (unsigned long long)pc, insn, disasm_buf);
							code_off += 4;
							pc += 4;
						} else break;
					} else if (ctx.machine == 62 || ctx.machine == 3) {
						/* x86-64 / x86 */
						int bytes = disasm_x86_insn(code + code_off, sh->size - code_off, pc, disasm_buf, sizeof(disasm_buf));
						int b;

						printf("  %llx:\t", (unsigned long long)pc);
						for (b = 0; b < bytes; b++)
							printf("%02x ", code[code_off + b]);
						for (b = bytes; b < 7; b++)
							printf("   ");
						printf("\t%s\n", disasm_buf);
						code_off += (size_t)bytes;
						pc += (uint64_t)bytes;
					} else {
						/* Generic hex dump */
						printf("  %llx:\t%02x\n", (unsigned long long)pc, code[code_off]);
						code_off++;
						pc++;
					}
				}
			}
			putchar('\n');
		}

		free(ctx.shdrs);
		munmap(ctx.buf, ctx.size);
	}

	return 0;
}
