/* vi: set sw=4 ts=4: */
/*
 * readelf - display information about ELF files
 *
 * Copyright 2019 The Android Open Source Project
 * Adapted for BusyBox by Rick & the BusyBox Team, 2026.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//config:config READELF
//config:	bool "readelf (display information about ELF files)"
//config:	default y
//config:	help
//config:	  Displays information about ELF files including headers, segments,
//config:	  sections, symbols, dynamic tags, notes, and architecture attributes.

//applet:IF_READELF(APPLET(readelf, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_READELF) += readelf.o

//usage:#define readelf_trivial_usage
//usage:       "[-AadehlnSsW] [-p SECTION] [-x SECTION] [--dyn-syms] FILE..."
//usage:#define readelf_full_usage "\n\n"
//usage:       "Display information about ELF files\n"
//usage:     "\n	-a	Equivalent to -AdhlnSs"
//usage:     "\n	-A	Show architecture-specific info"
//usage:     "\n	-d	Show dynamic section"
//usage:     "\n	-e	Headers (equivalent to -hlS)"
//usage:     "\n	-h	Show ELF header"
//usage:     "\n	-l	Show program headers"
//usage:     "\n	-n	Show notes"
//usage:     "\n	-p S	Dump strings found in named/numbered section"
//usage:     "\n	-S	Show section headers"
//usage:     "\n	-s	Show symbol tables (.dynsym and .symtab)"
//usage:     "\n	-x S	Hex dump of named/numbered section"
//usage:     "\n	-W	Wide output format"
//usage:     "\n	--dyn-syms	Show just .dynsym symbol table"

#include "libbb.h"
#include <elf.h>
#include <sys/mman.h>

struct globals {
	const char *opt_x;
	const char *opt_p;
	const char *f;
	char *elf;
	char *shstrtab;
	unsigned long long shoff;
	unsigned long long phoff;
	unsigned long long size;
	unsigned long long shstrtabsz;
	int bits;
	int endian;
	int shnum;
	int shentsize;
	int phentsize;
	unsigned opt_flags;
	int file_count;
};

static struct globals G;

/* Section header representation */
struct r_sh {
	unsigned type;
	unsigned link;
	unsigned info;
	unsigned long long flags;
	unsigned long long addr;
	unsigned long long offset;
	unsigned long long size;
	unsigned long long addralign;
	unsigned long long entsize;
	char *name;
};

/* Program header representation */
struct r_ph {
	unsigned type;
	unsigned flags;
	unsigned long long offset;
	unsigned long long vaddr;
	unsigned long long paddr;
	unsigned long long filesz;
	unsigned long long memsz;
	unsigned long long align;
};

#define EM_ARM_VAL     40
#define EM_ARM64_VAL   183
#define EM_RISCV_VAL   243
#define EM_X86_64_VAL  62

enum {
	OPT_A        = (1 << 0),
	OPT_a        = (1 << 1),
	OPT_d        = (1 << 2),
	OPT_e        = (1 << 3),
	OPT_h        = (1 << 4),
	OPT_l        = (1 << 5),
	OPT_n        = (1 << 6),
	OPT_p        = (1 << 7),
	OPT_S        = (1 << 8),
	OPT_s        = (1 << 9),
	OPT_W        = (1 << 10),
	OPT_x        = (1 << 11),
	OPT_dyn_syms = (1 << 12),
};

static const char readelf_longopts[] ALIGN1 =
	"dyn-syms\0"        No_argument       "\xff"
	"all\0"             No_argument       "a"
	"file-header\0"     No_argument       "h"
	"program-headers\0" No_argument       "l"
	"segments\0"        No_argument       "l"
	"section-headers\0" No_argument       "S"
	"sections\0"        No_argument       "S"
	"symbols\0"         No_argument       "s"
	"syms\0"            No_argument       "s"
	"dynamic\0"         No_argument       "d"
	"notes\0"           No_argument       "n"
	"wide\0"            No_argument       "W"
	"arch-specific\0"   No_argument       "A"
	"string-dump\0"     Required_argument "p"
	"hex-dump\0"        Required_argument "x"
	;

static long long r_peek_le(const void *ptr, unsigned size)
{
	long long ret = 0;
	const unsigned char *c = (const unsigned char *)ptr;
	for (unsigned i = 0; i < size; i++)
		ret |= ((long long)c[i]) << (i * 8);
	return ret;
}

static long long r_peek_be(const void *ptr, unsigned size)
{
	long long ret = 0;
	const unsigned char *c = (const unsigned char *)ptr;
	for (unsigned i = 0; i < size; i++)
		ret = (ret << 8) | c[i];
	return ret;
}

static long long elf_get(char **p, int len)
{
	long long result;

	if (*p + len - G.elf > (ptrdiff_t)G.size)
		bb_error_msg_and_die("Access off end: %td[%d] of %llu",
			*p - G.elf, len, G.size);

	result = (G.endian == 2) ? r_peek_be(*p, len) : r_peek_le(*p, len);
	*p += len;
	return result;
}

static unsigned long long elf_long(char **p)
{
	return elf_get(p, 4 * (G.bits + 1));
}

static unsigned elf_int(char **p)
{
	return (unsigned)elf_get(p, 4);
}

static unsigned short elf_short(char **p)
{
	return (unsigned short)elf_get(p, 2);
}

static int fits(const char *what, int n, unsigned long long off, unsigned long long size)
{
	if (off > G.size || size > G.size || off > G.size - size) {
		char buf[32];
		buf[0] = '\0';
		if (n != -1)
			snprintf(buf, sizeof(buf), " %d", n);
		printf("%s%s's offset %llu + size %llu > file size %llu\n",
			what, buf, off, size, G.size);
		return 0;
	}
	return 1;
}

static int get_sh(unsigned i, struct r_sh *s)
{
	char *shdr = G.elf + G.shoff + i * G.shentsize;
	unsigned name_offset;

	if (i >= (unsigned)G.shnum || shdr > G.elf + G.size - G.shentsize) {
		printf("No shdr %u\n", i);
		return 0;
	}

	name_offset = elf_int(&shdr);
	s->type = elf_int(&shdr);
	s->flags = elf_long(&shdr);
	s->addr = elf_long(&shdr);
	s->offset = elf_long(&shdr);
	s->size = elf_long(&shdr);
	s->link = elf_int(&shdr);
	s->info = elf_int(&shdr);
	s->addralign = elf_long(&shdr);
	s->entsize = elf_long(&shdr);

	if (s->type != 8 && !fits("section header", (int)i, s->offset, s->size))
		return 0;

	if (!G.shstrtab) {
		s->name = (char *)"?";
	} else {
		s->name = G.shstrtab + name_offset;
		if (name_offset > G.shstrtabsz || s->name >= G.elf + G.size) {
			printf("Bad name for sh %u\n", i);
			return 0;
		}
	}

	return 1;
}

static int find_section(const char *spec, struct r_sh *s)
{
	char *end;
	unsigned i;

	if (!spec)
		return 0;

	/* Valid section number? */
	i = (unsigned)strtoul(spec, &end, 0);
	if (!*end && i < (unsigned)G.shnum)
		return get_sh(i, s);

	/* Search the section names */
	for (i = 0; i < (unsigned)G.shnum; i++) {
		if (get_sh(i, s) && !strcmp(s->name, spec))
			return 1;
	}

	bb_error_msg("%s: no section '%s'", G.f, spec);
	return 0;
}

static int get_ph(int i, struct r_ph *ph)
{
	char *phdr = G.elf + G.phoff + i * G.phentsize;

	if (phdr > G.elf + G.size - G.phentsize) {
		printf("Bad phdr %d\n", i);
		return 0;
	}

	/* Elf64_Phdr reordered fields */
	ph->type = elf_int(&phdr);
	if (G.bits) {
		ph->flags = elf_int(&phdr);
		ph->offset = elf_long(&phdr);
		ph->vaddr = elf_long(&phdr);
		ph->paddr = elf_long(&phdr);
		ph->filesz = elf_long(&phdr);
		ph->memsz = elf_long(&phdr);
		ph->align = elf_long(&phdr);
	} else {
		ph->offset = elf_int(&phdr);
		ph->vaddr = elf_int(&phdr);
		ph->paddr = elf_int(&phdr);
		ph->filesz = elf_int(&phdr);
		ph->memsz = elf_int(&phdr);
		ph->flags = elf_int(&phdr);
		ph->align = elf_int(&phdr);
	}

	if (!fits("program header", i, ph->offset, ph->filesz))
		return 0;
	return 1;
}

#define MAP(...) __VA_ARGS__
#define DECODER(name, values) \
	static const char *name(int type) { \
		static char unknown[4][32]; \
		static unsigned u_idx; \
		static const struct {int v; const char *s;} a[] = values; \
		char *buf; \
		for (unsigned i = 0; i < ARRAY_SIZE(a); i++) \
			if (type == a[i].v) return a[i].s; \
		buf = unknown[(u_idx++) & 3]; \
		snprintf(buf, 32, "0x%x", type); \
		return buf; \
	}

DECODER(dt_type, MAP({{0,"x(NULL)"},{1,"N(NEEDED)"},{2,"b(PLTRELSZ)"},
	{3,"x(PLTGOT)"},{4,"x(HASH)"},{5,"x(STRTAB)"},{6,"x(SYMTAB)"},{7,"x(RELA)"},
	{8,"b(RELASZ)"},{9,"b(RELAENT)"},{10,"b(STRSZ)"},{11,"b(SYMENT)"},
	{12,"x(INIT)"},{13,"x(FINI)"},{14,"S(SONAME)"},{15,"R(RPATH)"},
	{16,"x(SYMBOLIC)"},{17,"x(REL)"},{18,"b(RELSZ)"},{19,"b(RELENT)"},
	{20,"P(PLTREL)"},{21,"x(DEBUG)"},{22,"x(TEXTREL)"},{23,"x(JMPREL)"},
	{24,"d(BIND_NOW)"},{25,"x(INIT_ARRAY)"},{26,"x(FINI_ARRAY)"},
	{27,"b(INIT_ARRAYSZ)"},{28,"b(FINI_ARRAYSZ)"},{29,"R(RUNPATH)"},
	{30,"f(FLAGS)"},{32,"x(PREINIT_ARRAY)"},{33,"b(PREINIT_ARRAYSZ)"},
	{35,"b(RELRSZ)"},{36,"x(RELR)"},{37,"b(RELRENT)"},
	{0x6000000f,"x(ANDROID_REL)"},{0x60000010,"b(ANDROID_RELSZ)"},
	{0x60000011,"x(ANDROID_RELA)"},{0x60000012,"b(ANDROID_RELASZ)"},
	{0x6fffe000,"x(ANDROID_RELR)"},{0x6fffe001,"b(ANDROID_RELRSZ)"},
	{0x6fffe003,"x(ANDROID_RELRENT)"},{0x6ffffef5,"x(GNU_HASH)"},
	{0x6ffffef6,"x(TLSDESC_PLT)"},{0x6ffffef7,"x(TLSDESC_GOT)"},
	{0x6ffffff0,"x(VERSYM)"},{0x6ffffff9,"d(RELACOUNT)"},
	{0x6ffffffa,"d(RELCOUNT)"},{0x6ffffffb,"F(FLAGS_1)"},
	{0x6ffffffc," (VERDEF)"},{0x6ffffffd,"d(VERDEFNUM)"},
	{0x6ffffffe,"x(VERNEED)"},{0x6fffffff,"d(VERNEEDNUM)"}}))

DECODER(et_type, MAP({{0,"NONE (None)"},{1,"REL (Relocatable file)"},
	{2,"EXEC (Executable file)"},{3,"DYN (Shared object file)"},
	{4,"CORE (Core file)"}}))

DECODER(nt_type_core, MAP({{1,"NT_PRSTATUS"},{2,"NT_FPREGSET"},
	{3,"NT_PRPSINFO"},{5,"NT_PLATFORM"},{6,"NT_AUXV"},
	{0x46494c45,"NT_FILE"},{0x53494749,"NT_SIGINFO"}}))

DECODER(nt_type_linux, MAP({{0x200,"NT_386_TLS"},{0x202,"NT_X86_XSTATE"},
	{0x400,"NT_ARM_VFP"},{0x401,"NT_ARM_TLS"},{0x405,"NT_ARM_SVE"}}))

DECODER(os_abi, MAP({{0,"UNIX - System V"}}))

DECODER(ph_type, MAP({{0,"NULL"},{1,"LOAD"},{2,"DYNAMIC"},{3,"INTERP"},
	{4,"NOTE"},{5,"SHLIB"},{6,"PHDR"},{7,"TLS"},{0x6474e550,"GNU_EH_FRAME"},
	{0x6474e551,"GNU_STACK"},{0x6474e552,"GNU_RELRO"},{0x70000001,"EXIDX"}}))

DECODER(sh_type, MAP({{0,"NULL"},{1,"PROGBITS"},{2,"SYMTAB"},{3,"STRTAB"},
	{4,"RELA"},{5,"HASH"},{6,"DYNAMIC"},{7,"NOTE"},{8,"NOBITS"},{9,"REL"},
	{10,"SHLIB"},{11,"DYNSYM"},{14,"INIT_ARRAY"},{15,"FINI_ARRAY"},
	{16,"PREINIT_ARRAY"},{17,"GROUP"},{18,"SYMTAB_SHNDX"},{19,"RELR"},
	{0x60000001,"ANDROID_REL"},{0x60000002,"ANDROID_RELA"},
	{0x6fffff00,"ANDROID_RELR"},{0x6ffffff6,"GNU_HASH"},
	{0x6ffffffd,"VERDEF"},{0x6ffffffe,"VERNEED"},
	{0x6fffffff,"VERSYM"},{0x70000001,"ARM_EXIDX"},
	{0x70000003,"ARM_ATTRIBUTES"}}))

DECODER(stb_type, MAP({{0,"LOCAL"},{1,"GLOBAL"},{2,"WEAK"}}))

DECODER(stt_type, MAP({{0,"NOTYPE"},{1,"OBJECT"},{2,"FUNC"},{3,"SECTION"},
	{4,"FILE"},{5,"COMMON"},{6,"TLS"},{10,"GNU_IFUNC"}}))

DECODER(stv_type, MAP({{0,"DEFAULT"},{1,"INTERNAL"},{2,"HIDDEN"},
	{3,"PROTECTED"}}))

DECODER(riscv_attr_tag, MAP({{4,"stack_align"},{5,"arch"},
	{6,"unaligned_access"},{8,"priv_spec"},{10,"priv_spec_minor"},
	{12,"priv_spec_revision"},{14,"atomic_abi"},{16,"x3_reg_usage"}}))

static const char *elf_arch_name(int type)
{
	static char unknown_arch[32];
	static const struct {int val; const char *name;} types[] = {
		{0x9026, "alpha"}, {93, "arc"}, {195, "arcv2"}, {40, "arm"},
		{183, "arm64"}, {0x18ad, "avr32"}, {247, "bpf"}, {106, "blackfin"},
		{140, "c6x"}, {23, "cell"}, {76, "cris"}, {252, "csky"},
		{0x5441, "frv"}, {46, "h8300"}, {164, "hexagon"}, {50, "ia64"},
		{258, "loongarch"}, {88, "m32r"}, {0x9041, "m32r"}, {4, "m68k"},
		{174, "metag"}, {189, "microblaze"}, {0xbaab, "microblaze-old"},
		{8, "mips"}, {10, "mips-old"}, {89, "mn10300"}, {0xbeef, "mn10300-old"},
		{113, "nios2"}, {92, "openrisc"}, {0x8472, "openrisc-old"},
		{15, "parisc"}, {20, "ppc"}, {21, "ppc64"}, {243, "riscv"},
		{22, "s390"}, {0xa390, "s390-old"}, {135, "score"}, {42, "sh"},
		{2, "sparc"}, {18, "sparc8+"}, {43, "sparc9"}, {188, "tile"},
		{191, "tilegx"}, {3, "386"}, {6, "486"}, {62, "x86-64"},
		{94, "xtensa"}, {0xabc7, "xtensa-old"}
	};

	for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
		if (type == types[i].val)
			return types[i].name;
	}

	snprintf(unknown_arch, sizeof(unknown_arch), "unknown arch %d", type);
	return unknown_arch;
}

static void elf_print_flags(int arch, int flags)
{
	static const char *const flt[] = {"soft", "single", "double", "quad"};
	if (arch == 40) { /* arm32 */
		printf(", EABI%u", (flags >> 24) & 0xf);
		if (flags & 0x200)
			printf(", soft float");
		else if (flags & 0x400)
			printf(", hard float");
	} else if (arch == 243) { /* riscv */
		if (flags & 1)
			printf(", C");
		if (flags & 8)
			printf(", E");
		if (flags & 0x10)
			printf(", TSO");
		printf(", %s float", flt[(flags & 0x6) / 2]);
	}
}

static void show_symbols(struct r_sh *table, struct r_sh *strtab)
{
	char *symtab = G.elf + table->offset;
	const char *ndx;
	int numsym = (int)(table->size / (G.bits ? 24 : 16));

	if (!numsym)
		return;

	putchar('\n');
	printf("Symbol table '%s' contains %d entries:\n"
	       "   Num:    %*s  Size Type    Bind   Vis      Ndx Name\n",
	       table->name, numsym, 5 + 8 * G.bits, "Value");

	for (int i = 0; i < numsym; i++) {
		unsigned st_name = elf_int(&symtab);
		unsigned st_value, st_shndx, st_info, st_other;
		unsigned long st_size;
		const char *name;
		char buf[16];

		if (G.bits) {
			st_info = (unsigned char)*symtab++;
			st_other = (unsigned char)*symtab++;
			st_shndx = elf_short(&symtab);
			st_value = (unsigned)elf_long(&symtab);
			st_size = (unsigned long)elf_long(&symtab);
		} else {
			st_value = elf_int(&symtab);
			st_size = elf_int(&symtab);
			st_info = (unsigned char)*symtab++;
			st_other = (unsigned char)*symtab++;
			st_shndx = elf_short(&symtab);
		}

		name = G.elf + strtab->offset + st_name;
		if (name >= G.elf + G.size)
			name = "???";

		if (!st_shndx)
			ndx = "UND";
		else if (st_shndx == 0xfff1)
			ndx = "ABS";
		else {
			snprintf(buf, sizeof(buf), "%d", st_shndx);
			ndx = buf;
		}

		printf("%6d: %0*x %5lu %-7s %-6s %-9s%3s %s\n",
			i, 8 * (G.bits + 1), st_value, st_size,
			stt_type(st_info & 0xf), stb_type(st_info >> 4),
			stv_type(st_other & 3), ndx, name);
	}
}

static int notematch(int namesz, char **p, const char *expected)
{
	if (namesz != (int)(strlen(expected) + 1) || strcmp(*p, expected))
		return 0;
	*p += namesz;
	return 1;
}

static unsigned long long uleb(char **ptr, const char *end)
{
	unsigned long long result = 0;
	int shift = 0;
	unsigned char b;

	do {
		if (*ptr >= end)
			bb_error_msg_and_die("EOF in uleb128");
		b = (unsigned char)**ptr;
		*ptr = *ptr + 1;
		result |= (unsigned long long)(b & 0x7f) << shift;
		shift += 7;
		if (shift > 56)
			bb_error_msg_and_die("uleb128 too long");
	} while (b & 0x80);

	return result;
}

static void show_attributes(unsigned long offset, unsigned long size)
{
	char *attr = G.elf + offset;
	const char *end = G.elf + offset + size;
	unsigned long long tag;
	unsigned len;

	if (offset == size || *attr++ != 'A') {
		bb_error_msg("%s: bad attributes @%lu", G.f, offset);
		return;
	}

	len = elf_int(&attr);
	if (!memchr(attr, 0, 32)) {
		bb_error_msg("%s: bad vendor name", G.f);
		return;
	}
	printf("\nAttribute Section: %s\n", attr);
	attr += strlen(attr) + 1;

	tag = uleb(&attr, end);
	len = elf_int(&attr);
	if (tag == 1) {
		printf("File Attributes\n");
		while (attr < end) {
			tag = uleb(&attr, end);
			printf("  Tag_RISCV_%s: ", riscv_attr_tag((int)tag));
			if (!(tag & 1))
				printf("%lld\n", (long long)uleb(&attr, end));
			else {
				printf("%s\n", attr);
				attr += strlen(attr) + 1;
			}
		}
	} else {
		bb_error_msg("%s: unknown attributes tag=%llx (size=%u)", G.f, tag, len);
	}
}

static void show_notes(unsigned long offset, unsigned long size)
{
	char *note = G.elf + offset;
	const char *end = G.elf + offset + size;

	if (!fits("note", -1, offset, size))
		return;

	printf("  %-20s%11s\tDescription\n", "Owner", "Data size");
	while (note < end) {
		char *p = note;
		const char *desc;
		unsigned namesz = elf_int(&p);
		unsigned descsz = elf_int(&p);
		unsigned type = elf_int(&p);
		unsigned j = 0;

		if (namesz > size || descsz > size) {
			bb_error_msg("%s: bad note @%lu", G.f, offset);
			return;
		}
		printf("  %-20.*s 0x%08x\t", (int)namesz, p, descsz);
		if (notematch((int)namesz, &p, "GNU")) {
			if (type == 1) {
				printf("NT_GNU_ABI_TAG\tOS: %s, ABI: %u.%u.%u",
					!elf_int(&p) ? "Linux" : "?",
					elf_int(&p), elf_int(&p), elf_int(&p));
				j = 1;
			} else if (type == 3) {
				printf("NT_GNU_BUILD_ID\t");
				for (; j < descsz; j++)
					printf("%02x", (unsigned char)*p++);
			} else if (type == 4) {
				printf("NT_GNU_GOLD_VERSION\t%.*s", (int)descsz, p);
				j = 1;
			} else if (type == 5) {
				printf("NT_GNU_PROPERTY_TYPE_0\n    Properties:");
				while (descsz - j > 0) {
					int pr_type = (int)elf_int(&p);
					int pr_size = (int)elf_int(&p);
					j += 8;
					if (p > end) {
						bb_error_msg("%s: bad property @%lu", G.f, offset);
						return;
					}
					if (pr_size != 4) {
						for (int k = 0; k < pr_size; k++)
							printf("%02x", (unsigned char)*p++);
						putchar('\n');
						j += (unsigned)pr_size;
					} else {
						int pr_data = (int)elf_int(&p);
						elf_int(&p); /* Skip padding */
						j += 8;
						if (pr_type == 0xc0000000) {
							printf("\tarm64 features:");
							if (pr_data & 1) printf(" bti");
							if (pr_data & 2) printf(" pac");
							putchar('\n');
						} else if (pr_type == 0xc0000002) {
							printf("\tx86 feature:");
							if (pr_data & 1) printf(" ibt");
							if (pr_data & 2) printf(" shstk");
							putchar('\n');
						} else if (pr_type == 0xc0008002) {
							printf("\tx86 isa needed: x86-64v%d\n", ffs(pr_data));
						} else {
							printf("\tother (%#x): %#x\n", pr_type, pr_data);
						}
					}
				}
			} else
				p -= 4;
		} else if (notematch((int)namesz, &p, "Android")) {
			if (type == 1) {
				printf("NT_VERSION\tAPI level %u", elf_int(&p));
				if (descsz >= 132)
					printf(", NDK %.64s (%.64s)", p, p + 64);
				j = 1;
			} else if (type == 5) {
				printf("NT_PAD_SEGMENT\tpad_segment=%u", elf_int(&p));
				j = 1;
			} else
				p -= 8;
		} else if (notematch((int)namesz, &p, "CORE")) {
			desc = nt_type_core((int)type);
			if (*desc != '0') {
				printf("%s", desc);
				j = 1;
			}
		} else if (notematch((int)namesz, &p, "LINUX")) {
			desc = nt_type_linux((int)type);
			if (*desc != '0') {
				printf("%s", desc);
				j = 1;
			}
		}

		if (!j) {
			printf("0x%x\t", type);
			for (; j < descsz; j++)
				printf("%c%02x", j ? ' ' : '\t', (unsigned char)*p++);
		}
		putchar('\n');
		note += 3 * 4 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3);
	}
}

static void do_flag(int shift, long long *flags, char **out, char c)
{
	long long bit = 1LL << shift;
	if (bit & *flags) {
		*(*out)++ = c;
		*flags ^= bit;
	}
}

static void scan_elf(void)
{
	struct r_sh dynamic = {0}, dynstr = {0}, dynsym = {0};
	struct r_sh shstr = {0}, strtab = {0}, symtab = {0}, s;
	struct r_ph ph;
	char *hdr = G.elf;
	int type, machine, version, flags, entry, ehsize, phnum, shstrndx, w;

	if (G.size < 45 || memcmp(hdr, "\177ELF", 4) != 0) {
		bb_error_msg("%s: not ELF", G.f);
		return;
	}

	G.bits = hdr[4] - 1;
	G.endian = hdr[5];
	if (G.bits < 0 || G.bits > 1 || G.endian < 1 || G.endian > 2 || hdr[6] != 1) {
		bb_error_msg("%s: bad ELF", G.f);
		return;
	}

	hdr += 16; /* EI_NIDENT */
	type = elf_short(&hdr);
	machine = elf_short(&hdr);
	version = (int)elf_int(&hdr);
	entry = (int)elf_long(&hdr);
	G.phoff = elf_long(&hdr);
	G.shoff = elf_long(&hdr);
	flags = (int)elf_int(&hdr);
	ehsize = elf_short(&hdr);
	G.phentsize = elf_short(&hdr);
	phnum = elf_short(&hdr);
	G.shentsize = elf_short(&hdr);
	G.shnum = elf_short(&hdr);
	shstrndx = elf_short(&hdr);

	if (G.file_count > 1)
		printf("\nFile: %s\n", G.f);

	if (G.opt_flags & OPT_h) {
		printf("ELF Header:\n");
		printf("  Magic:   ");
		for (int i = 0; i < 16; i++)
			printf("%02x%c", (unsigned char)G.elf[i], (i == 15) ? '\n' : ' ');
		printf("  Class:                             ELF%d\n", G.bits ? 64 : 32);
		printf("  Data:                              2's complement, %s endian\n",
			(G.endian == 2) ? "big" : "little");
		printf("  Version:                           1 (current)\n");
		printf("  OS/ABI:                            %s\n", os_abi((unsigned char)G.elf[7]));
		printf("  ABI Version:                       %d\n", (unsigned char)G.elf[8]);
		printf("  Type:                              %s\n", et_type(type));
		printf("  Machine:                           %s\n", elf_arch_name(machine));
		printf("  Version:                           0x%x\n", version);
		printf("  Entry point address:               0x%x\n", entry);
		printf("  Start of program headers:          %llu (bytes into file)\n", G.phoff);
		printf("  Start of section headers:          %llu (bytes into file)\n", G.shoff);
		printf("  Flags:                             0x%x", flags);
		elf_print_flags(machine, flags);
		putchar('\n');
		printf("  Size of this header:               %d (bytes)\n", ehsize);
		printf("  Size of program headers:           %d (bytes)\n", G.phentsize);
		printf("  Number of program headers:         %d\n", phnum);
		printf("  Size of section headers:           %d (bytes)\n", G.shentsize);
		printf("  Number of section headers:         %d\n", G.shnum);
		printf("  Section header string table index: %d\n", shstrndx);
	}

	if (G.phoff > G.size) {
		bb_error_msg("%s: bad phoff", G.f);
		return;
	}
	if (G.shoff > G.size) {
		bb_error_msg("%s: bad shoff", G.f);
		return;
	}

	G.shstrtab = NULL;
	G.shstrtabsz = 0;
	if (shstrndx) {
		if (!get_sh((unsigned)shstrndx, &shstr) || shstr.type != 3 /* SHT_STRTAB */) {
			bb_error_msg("%s: bad shstrndx", G.f);
			return;
		}
		G.shstrtab = G.elf + shstr.offset;
		G.shstrtabsz = shstr.size;
	}

	w = 8 << G.bits;
	if (G.opt_flags & OPT_S) {
		if (!G.shnum)
			printf("\nThere are no sections in this file.\n");
		else {
			if (!(G.opt_flags & OPT_h))
				printf("There are %d section headers, starting at offset %#llx:\n",
					G.shnum, G.shoff);
			printf("\nSection Headers:\n"
			       "  [Nr] %-17s %-15s %-*s %-6s %-6s ES Flg Lk Inf Al\n",
			       "Name", "Type", w, G.bits ? "Address" : "Addr", "Off", "Size");
		}
	}

	for (int i = 0; i < G.shnum; i++) {
		if (!get_sh((unsigned)i, &s))
			continue;
		if (s.type == 2 /* SHT_SYMTAB */) symtab = s;
		else if (s.type == 6 /* SHT_DYNAMIC */) dynamic = s;
		else if (s.type == 11 /* SHT_DYNSYM */) dynsym = s;
		else if (s.type == 3 /* SHT_STRTAB */) {
			if (!strcmp(s.name, ".strtab")) strtab = s;
			else if (!strcmp(s.name, ".dynstr")) dynstr = s;
		}

		if (G.opt_flags & OPT_S) {
			char sh_flags[16] = {0}, *p = sh_flags;
			long long sflags = (long long)s.flags;

			for (int j = 0; j < 12; j++)
				do_flag(j, &sflags, &p, "WAXxMSILOGTC"[j]);
			if (machine == EM_ARM_VAL || machine == EM_ARM64_VAL)
				do_flag(29, &sflags, &p, 'y');
			else if (machine == EM_X86_64_VAL)
				do_flag(28, &sflags, &p, 'l');
			if (sflags)
				*p++ = 'x';
			printf("  [%2d] %-17s %-15s %0*llx %06llx %06llx %02llx %3s %2u %2u %2lld\n",
				i, s.name, sh_type((int)s.type), w, s.addr, s.offset, s.size,
				s.entsize, sh_flags, s.link, s.info, s.addralign);
		}
	}

	if ((G.opt_flags & OPT_S) && G.shnum) {
		printf("Key:\n  (W)rite, (A)lloc, e(X)ecute, (M)erge, (S)trings, (I)nfo\n"
		       "  (L)ink order, (O)S, (G)roup, (T)LS, (C)ompressed, (x) unknown\n");
		if (machine == EM_ARM_VAL || machine == EM_ARM64_VAL)
			printf("  (y) purecode\n");
		else if (machine == EM_X86_64_VAL)
			printf("  (l) large\n");
	}

	if (G.opt_flags & OPT_l) {
		putchar('\n');
		if (!phnum)
			printf("There are no program headers in this file.\n");
		else {
			if (!(G.opt_flags & OPT_h))
				printf("Elf file type is %s\nEntry point %#x\n"
				       "There are %d program headers, starting at offset %llu\n\n",
				       et_type(type), entry, phnum, G.phoff);
			printf("Program Headers:\n"
			       "  %-14s %-8s %-*s   %-*s   %-7s %-7s Flg Align\n", "Type",
			       "Offset", w, "VirtAddr", w, "PhysAddr", "FileSiz", "MemSiz");
			for (int i = 0; i < phnum; i++) {
				if (!get_ph(i, &ph))
					continue;
				printf("  %-14s 0x%06llx 0x%0*llx 0x%0*llx 0x%05llx 0x%05llx %c%c%c %#llx\n",
					ph_type((int)ph.type), ph.offset, w, ph.vaddr, w, ph.paddr,
					ph.filesz, ph.memsz,
					(ph.flags & 4) ? 'R' : ' ',
					(ph.flags & 2) ? 'W' : ' ',
					(ph.flags & 1) ? 'E' : ' ',
					ph.align);
				if (ph.type == 3 /* PT_INTERP */ && ph.filesz < G.size &&
				    ph.offset < G.size && ph.filesz - 1 < G.size - ph.offset) {
					printf("      [Requesting program interpreter: %.*s]\n",
						(int)ph.filesz - 1, G.elf + ph.offset);
				}
			}

			printf("\n Section to Segment mapping:\n  Segment Sections...\n");
			for (int i = 0; i < phnum; i++) {
				if (!get_ph(i, &ph))
					continue;
				printf("   %02d     ", i);
				for (int j = 0; j < G.shnum; j++) {
					if (!get_sh((unsigned)j, &s))
						continue;
					if (!*s.name)
						continue;
					if (s.offset >= ph.offset && s.offset + s.size <= ph.offset + ph.filesz)
						printf("%s ", s.name);
				}
				putchar('\n');
			}
		}
	}

	if (G.opt_flags & OPT_d) {
		char *dyn = G.elf + dynamic.offset;
		const char *end = dyn + dynamic.size;
		char *dyn_type = dyn;
		unsigned long long tag, val;
		unsigned len = 0;

		while (dyn_type < end) {
			len++;
			if (!elf_long(&dyn_type))
				break;
			elf_long(&dyn_type);
		}

		putchar('\n');
		if (!dynamic.size)
			printf("There is no dynamic section in this file.\n");
		else if (!dynamic.entsize)
			printf("Bad dynamic entry size 0!\n");
		else {
			printf("Dynamic section at offset 0x%llx contains %u entries:\n"
			       "  %-*s %-20s %s\n", dynamic.offset, len,
			       w + 2, "Tag", "Type", "Name/Value");
			while (dyn < end) {
				const char *dtype;
				tag = elf_long(&dyn);
				val = elf_long(&dyn);
				dtype = dt_type((int)tag);

				printf(" 0x%0*llx %-20s ", w, tag, dtype + (*dtype != '0'));
				if (*dtype == 'd')
					printf("%lld\n", (long long)val);
				else if (*dtype == 'b')
					printf("%lld (bytes)\n", (long long)val);
				else if (*dtype == 's') {
					const char *sval = G.elf + dynstr.offset + val;
					if (dynstr.offset > G.size || val > G.size || dynstr.offset > G.size - val)
						sval = "???";
					printf("%s\n", sval);
				} else if (*dtype == 'f' || *dtype == 'F') {
					static const struct {int bit; const char *s;}
						df_names[] = {{0,"ORIGIN"},{1,"SYMBOLIC"},{2,"TEXTREL"},{3,"BIND_NOW"},{4,"STATIC_TLS"},{0,NULL}},
						df_1_names[] = {{0,"NOW"},{1,"GLOBAL"},{2,"GROUP"},{3,"NODELETE"},{5,"INITFIRST"},{27,"PIE"},{0,NULL}};
					const void *pnames = (*dtype == 'f') ? (const void *)df_names : (const void *)df_1_names;
					const struct {int bit; const char *s;} *names = pnames;

					if (*dtype == 'F')
						printf("Flags: ");
					for (int j = 0; names[j].s; j++) {
						unsigned long long mask = 1ULL << names[j].bit;
						if (val & mask) {
							val &= ~mask;
							printf("%s%s", names[j].s, val ? " " : "");
						}
					}
					if (val)
						printf("0x%llx", val);
					putchar('\n');
				} else if (*dtype == 'N' || *dtype == 'R' || *dtype == 'S') {
					const char *sval = G.elf + dynstr.offset + val;
					if (dynstr.offset > G.size || val > G.size || dynstr.offset > G.size - val)
						sval = "???";
					printf("%s: [%s]\n",
						*dtype == 'N' ? "Shared library" :
						(*dtype == 'R' ? "Library runpath" : "Library soname"), sval);
				} else if (*dtype == 'P') {
					const char *ptype = dt_type((int)val);
					int j = (int)strlen(ptype);
					if (*ptype != '0') {
						ptype += 2;
						j -= 3;
					}
					printf("%*.*s\n", j, j, ptype);
				} else {
					printf("0x%llx\n", val);
				}

				if (!tag)
					break;
			}
		}
	}

	if (G.opt_flags & OPT_dyn_syms)
		show_symbols(&dynsym, &dynstr);
	if (G.opt_flags & OPT_s)
		show_symbols(&symtab, &strtab);

	if (G.opt_flags & OPT_n) {
		int found = 0;
		for (int i = 0; i < G.shnum; i++) {
			if (!get_sh((unsigned)i, &s))
				continue;
			if (s.type == 7 /* SHT_NOTE */) {
				printf("\nDisplaying notes found in: %s\n", s.name);
				show_notes((unsigned long)s.offset, (unsigned long)s.size);
				found = 1;
			}
		}
		for (int i = 0; !found && i < phnum; i++) {
			if (!get_ph(i, &ph))
				continue;
			if (ph.type == 4 /* PT_NOTE */) {
				printf("\nDisplaying notes found at file offset 0x%llx with length 0x%llx:\n",
					ph.offset, ph.filesz);
				show_notes((unsigned long)ph.offset, (unsigned long)ph.filesz);
			}
		}
	}

	if ((G.opt_flags & OPT_A) && machine == EM_RISCV_VAL) {
		for (int i = 0; i < G.shnum; i++) {
			if (!get_sh((unsigned)i, &s))
				continue;
			if (s.type == 0x70000003 /* SHT_RISCV_ATTRIBUTES */)
				show_attributes((unsigned long)s.offset, (unsigned long)s.size);
		}
	}

	if (find_section(G.opt_x, &s)) {
		char *p = G.elf + s.offset;
		unsigned long offset = 0;

		printf("\nHex dump of section '%s':\n", s.name);
		while (offset < s.size) {
			int space = 2 * 16 + 16 / 4;
			int i = 0;

			printf("  0x%08lx ", offset);
			for (i = 0; i < 16 && offset < s.size; offset++)
				space -= printf("%02x%s", (unsigned char)*p++, " " + !(++i % 4));
			printf("%*s", space, "");
			for (p -= i; i; i--, p++)
				putchar((*p >= ' ' && *p <= '~') ? *p : '.');
			putchar('\n');
		}
		putchar('\n');
	}

	if (find_section(G.opt_p, &s)) {
		char *begin = G.elf + s.offset;
		const char *end = begin + s.size;
		char *p = begin;
		int any = 0;

		printf("\nString dump of section '%s':\n", s.name);
		for (; p < end; p++) {
			if ((unsigned char)*p >= ' ' && (unsigned char)*p <= '~') {
				printf("  [%6tx]  ", p - begin);
				while (p < end && (unsigned char)*p >= ' ' && (unsigned char)*p <= '~')
					putchar(*p++);
				putchar('\n');
				any = 1;
			}
		}
		if (!any)
			printf("  No strings found in this section.\n");
		putchar('\n');
	}
}

int readelf_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int readelf_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned opts;
	unsigned all_flags = OPT_A | OPT_d | OPT_h | OPT_l | OPT_n | OPT_S | OPT_s | OPT_dyn_syms;

	memset(&G, 0, sizeof(G));

	opts = getopt32long(argv, "aAdehlnSsp:Wx:", readelf_longopts, &G.opt_p, &G.opt_x);
	argv += optind;

	if (opts & OPT_a)
		opts |= all_flags;
	if (opts & OPT_e)
		opts |= OPT_h | OPT_l | OPT_S;
	if (opts & OPT_s)
		opts |= OPT_dyn_syms;

	G.opt_flags = opts;

	if (!(opts & (all_flags | OPT_p | OPT_x)))
		bb_show_usage();

	if (!*argv)
		bb_show_usage();

	G.file_count = 0;
	for (char **a = argv; *a; a++)
		G.file_count++;

	while (*argv) {
		int fd;
		struct stat sb;

		G.f = *argv++;
		fd = open(G.f, O_RDONLY);
		if (fd < 0) {
			bb_perror_msg("%s", G.f);
			continue;
		}

		if (fstat(fd, &sb) != 0) {
			bb_perror_msg("%s", G.f);
			close(fd);
			continue;
		}

		if (!sb.st_size) {
			bb_error_msg("%s: empty file", G.f);
			close(fd);
			continue;
		}

		if (!S_ISREG(sb.st_mode)) {
			bb_error_msg("%s: not a regular file", G.f);
			close(fd);
			continue;
		}

		G.size = (unsigned long long)sb.st_size;
		G.elf = mmap(NULL, (size_t)G.size, PROT_READ, MAP_SHARED, fd, 0);
		if (G.elf == MAP_FAILED) {
			bb_perror_msg("%s: mmap", G.f);
			close(fd);
			continue;
		}

		scan_elf();

		munmap(G.elf, (size_t)G.size);
		close(fd);
	}

	return 0;
}
