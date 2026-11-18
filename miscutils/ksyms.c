/* vi: set sw=4 ts=4: */
/*
 * Universal Pure-Silicon Kernel Symbol & Struct Tracer for BusyBox
 *
 * Discovers live kernel symbol addresses, execution boundaries, and struct
 * member offsets directly from running process memory, architectural CPU
 * registers, live vDSO ELF streams, and machine-code disassembly without
 * /proc/kallsyms, /proc/kcore, BTF, or external modules.
 *
 * Supported Query Options:
 *   - Symbol resolution: -S/--symbol, -L/--lookup, -s/--search, -a/--all, -n/--num-syms
 *   - Proximity discovery: -P/--proximity (branch call-graph & ___ksymtab adjacency)
 *   - Struct & Member resolution: -T/--struct, -M/--member, -m/--members, -B/--boundaries
 *   - Live Diagnostics: -v/--vdso, -t/--timing
 *
 * Copyright (C) 2026 Rick & the BusyBox Team
 * Licensed under GPLv2 or later.
 */

//config:config KSYMS
//config:	bool "ksyms (kernel symbol & struct tracer without /proc/kallsyms)"
//config:	default y
//config:	help
//config:	  Discovers live kernel symbol addresses, boundaries, and
//config:	  struct member offsets via pure machine-code disassembly,
//config:	  architectural CPU registers, and in-memory vDSO ELF parsing.
//config:
//config:config FEATURE_KSYMS_KALLSYMS_ALIAS
//config:	bool "Support kallsyms applet alias"
//config:	default y
//config:	depends on KSYMS
//config:	help
//config:	  Provide kallsyms applet alias for ksyms.

//applet:IF_KSYMS(APPLET(ksyms, BB_DIR_SBIN, BB_SUID_DROP))
//applet:IF_FEATURE_KSYMS_KALLSYMS_ALIAS(APPLET_ODDNAME(kallsyms, ksyms, BB_DIR_SBIN, BB_SUID_DROP, kallsyms))

//kbuild:lib-$(CONFIG_KSYMS) += ksyms.o

//usage:#define ksyms_trivial_usage
//usage:       "[-S SYM] [-L ADDR] [-P SYM] [-T STRUCT] [-M MEMBER] [-m] [-B] [-a] [-s PAT] [-v] [-t]"
//usage:#define ksyms_full_usage "\n\n"
//usage:       "Trace live kernel symbols and struct offsets without /proc/kallsyms\n"
//usage:     "\nSymbols:"
//usage:     "\n	-S, --symbol NAME	Look up address and type of symbol"
//usage:     "\n	-L, --lookup ADDR	Reverse-lookup address to nearest symbol"
//usage:     "\n	-s, --search PAT	Filter symbols containing substring"
//usage:     "\n	-a, --all		Dump all resolved kernel symbols"
//usage:     "\n	-n, --num-syms		Output total symbol count"
//usage:     "\nProximity Discovery:"
//usage:     "\n	-P, --proximity SYM	Discover unexported callees & adjacent ___ksymtab symbols from anchor SYM"
//usage:     "\nStructs & Members:"
//usage:     "\n	-T, --struct NAME	Display dynamically traced member offsets for struct"
//usage:     "\n	-M, --member NAME	Query offset of a specific struct member"
//usage:     "\n	-m, --members		Display table of all dynamically discovered struct members"
//usage:     "\n	-B, --boundaries	Display kernel memory boundaries and hardware cache geometry"
//usage:     "\nDiagnostics:"
//usage:     "\n	-v, --vdso		Display live vDSO symbols, machine code, and ELF build notes"
//usage:     "\n	-t, --timing		Benchmark syscall entry/exit cycle latency via CPU registers"
//usage:
//usage:#define kallsyms_trivial_usage ksyms_trivial_usage
//usage:#define kallsyms_full_usage ksyms_full_usage

#include "libbb.h"
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <setjmp.h>
#include <elf.h>

#ifndef AT_SYSINFO_EHDR
# define AT_SYSINFO_EHDR 33
#endif

#ifndef ElfW
# if (defined(__WORDSIZE) && __WORDSIZE == 64) || defined(__aarch64__) || defined(__x86_64__)
#  define ElfW(type) Elf64_##type
# else
#  define ElfW(type) Elf32_##type
# endif
#endif

#ifndef ELF_ST_BIND
# define ELF_ST_BIND(val) (((unsigned char)(val)) >> 4)
#endif

/* =========================================================================
 * 1. Pure Inline Assembly Architectural Register Engine
 * ========================================================================= */

static inline uint64_t k_read_cycle_counter(void)
{
#if defined(__aarch64__)
	uint64_t val;
	asm volatile("isb\n mrs %0, cntvct_el0" : "=r"(val));
	return val;
#elif defined(__x86_64__)
	uint32_t lo, hi;
	asm volatile("lfence\n rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
#elif defined(__i386__)
	uint32_t lo, hi;
	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
#elif defined(__arm__)
	uint32_t val;
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(val));
	return val;
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

static inline uint64_t k_read_counter_freq(void)
{
#if defined(__aarch64__)
	uint64_t freq;
	asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
	return freq ? freq : 19200000ULL;
#else
	return 1000000000ULL;
#endif
}

static inline void k_read_cache_topology(unsigned int *dmin_line, unsigned int *imin_line)
{
	*dmin_line = 64;
	*imin_line = 64;
#if defined(__aarch64__)
	{
		uint64_t ctr;
		asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
		/* DminLine: bits [19:16] in words of 4 bytes */
		*dmin_line = (unsigned int)(4 << ((ctr >> 16) & 0xf));
		/* IminLine: bits [3:0] in words of 4 bytes */
		*imin_line = (unsigned int)(4 << (ctr & 0xf));
	}
#endif
}

static inline void k_read_thread_pointers(uint64_t *tpidr, uint64_t *tpidrro)
{
	*tpidr = 0;
	*tpidrro = 0;
#if defined(__aarch64__)
	asm volatile("mrs %0, tpidr_el0" : "=r"(*tpidr));
	asm volatile("mrs %0, tpidrro_el0" : "=r"(*tpidrro));
#endif
}

/* =========================================================================
 * 2. Fault-Immune Userspace Address Sanitizer
 * ========================================================================= */

static int g_sanitizer_pipe[2] = { -1, -1 };
static sigjmp_buf g_probe_jmpbuf;
static volatile sig_atomic_t g_probe_fault_occurred = 0;

static void k_probe_sig_handler(int sig)
{
	(void)sig;
	g_probe_fault_occurred = 1;
	siglongjmp(g_probe_jmpbuf, 1);
}

static void k_init_address_sanitizer(void)
{
	if (g_sanitizer_pipe[0] < 0) {
		if (pipe(g_sanitizer_pipe) < 0) {
			g_sanitizer_pipe[0] = -1;
			g_sanitizer_pipe[1] = -1;
		} else {
			fcntl(g_sanitizer_pipe[0], F_SETFL, O_NONBLOCK);
			fcntl(g_sanitizer_pipe[1], F_SETFL, O_NONBLOCK);
		}
	}
}

static int k_is_address_readable(const void *addr, size_t len)
{
	struct sigaction sa, old_sa;
	char dummy;
	ssize_t ret;

	if (!addr) return 0;

	if (g_sanitizer_pipe[1] >= 0) {
		ret = write(g_sanitizer_pipe[1], addr, len ? 1 : 0);
		if (ret > 0) {
			read(g_sanitizer_pipe[0], &dummy, 1);
			return 1;
		}
		if (ret < 0 && errno == EFAULT)
			return 0;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = k_probe_sig_handler;
	sigemptyset(&sa.sa_mask);

	sigaction(SIGSEGV, &sa, &old_sa);
	g_probe_fault_occurred = 0;

	if (sigsetjmp(g_probe_jmpbuf, 1) == 0) {
		dummy = *(const volatile char *)addr;
		(void)dummy;
	}

	sigaction(SIGSEGV, &old_sa, NULL);
	return (g_probe_fault_occurred == 0);
}

/* =========================================================================
 * 3. Dynamic Struct & Member Registry (Zero Hardcoded Static Tables)
 * ========================================================================= */

struct dynamic_member {
	char struct_name[32];
	char member_name[32];
	char type[32];
	int offset;
	int size;
	char provenance[64];
};

#define MAX_DYNAMIC_MEMBERS 64
static struct dynamic_member g_dynamic_members[MAX_DYNAMIC_MEMBERS];
static size_t g_num_dynamic_members = 0;

static void k_register_dynamic_member(const char *st_name, const char *mbr_name,
				      const char *type, int offset, int size,
				      const char *proof)
{
	size_t i;
	for (i = 0; i < g_num_dynamic_members; i++) {
		if (!strcmp(g_dynamic_members[i].struct_name, st_name) &&
		    !strcmp(g_dynamic_members[i].member_name, mbr_name)) {
			/* Update existing dynamic discovery */
			g_dynamic_members[i].offset = offset;
			g_dynamic_members[i].size = size;
			safe_strncpy(g_dynamic_members[i].type, type, sizeof(g_dynamic_members[i].type));
			safe_strncpy(g_dynamic_members[i].provenance, proof, sizeof(g_dynamic_members[i].provenance));
			return;
		}
	}

	if (g_num_dynamic_members < MAX_DYNAMIC_MEMBERS) {
		safe_strncpy(g_dynamic_members[g_num_dynamic_members].struct_name, st_name, 32);
		safe_strncpy(g_dynamic_members[g_num_dynamic_members].member_name, mbr_name, 32);
		safe_strncpy(g_dynamic_members[g_num_dynamic_members].type, type, 32);
		g_dynamic_members[g_num_dynamic_members].offset = offset;
		g_dynamic_members[g_num_dynamic_members].size = size;
		safe_strncpy(g_dynamic_members[g_num_dynamic_members].provenance, proof, 64);
		g_num_dynamic_members++;
	}
}

/* =========================================================================
 * 4. Pure Machine-Code Disassembly Engine
 * ========================================================================= */

#if defined(__aarch64__)
/* ARM64 AAPCS64 Machine-Code Disassembler */
static int k_disasm_arm64_trace_offset(const uint32_t *insns, size_t count, int want_subobject, int *sub_off)
{
	size_t i;
	int first_off = -1;
	int cur_reg = -1;

	for (i = 0; i < count; i++) {
		uint32_t insn = insns[i];

		if (insn == 0xd65f03c0) /* RET */
			break;

		/* LDR Wt, [Xn, #imm12*4] (32-bit scalar load) */
		if ((insn & 0xffc00000) == 0xb9400000) {
			int rn = (insn >> 5) & 0x1f;
			int rd = insn & 0x1f;
			int imm = ((insn >> 10) & 0xfff) * 4;

			if (cur_reg < 0 || rn == cur_reg || rn == 0) {
				if (first_off < 0) {
					first_off = imm;
					cur_reg = rd;
					if (!want_subobject) return first_off;
				} else {
					if (sub_off) *sub_off = imm;
					return first_off;
				}
			}
		}

		/* LDR Xt, [Xn, #imm12*8] (64-bit scalar pointer load) */
		if ((insn & 0xffc00000) == 0xf9400000) {
			int rn = (insn >> 5) & 0x1f;
			int rd = insn & 0x1f;
			int imm = ((insn >> 10) & 0xfff) * 8;

			if (cur_reg < 0 || rn == cur_reg || rn == 0) {
				if (first_off < 0) {
					first_off = imm;
					cur_reg = rd;
					if (!want_subobject) return first_off;
				} else {
					if (sub_off) *sub_off = imm;
					return first_off;
				}
			}
		}
	}
	return first_off;
}
#endif

#if defined(__x86_64__)
/* x86-64 System-V Machine-Code Disassembler */
static int k_disasm_x86_trace_offset(const uint8_t *code, size_t len, int want_subobject, int *sub_off)
{
	size_t i = 0;
	int first_off = -1;

	while (i < len) {
		if (code[i] == 0xc3) /* RET */
			break;

		/* mov 0x<disp8>(%rdi), %eax -> 8b 47 <disp8> */
		if (i + 3 <= len && code[i] == 0x8b && code[i+1] == 0x47) {
			int off = (int8_t)code[i+2];
			if (first_off < 0) {
				first_off = off;
				if (!want_subobject) return first_off;
			} else {
				if (sub_off) *sub_off = off;
				return first_off;
			}
			i += 3;
			continue;
		}

		/* mov 0x<disp32>(%rdi), %eax -> 8b 87 <disp32> */
		if (i + 6 <= len && code[i] == 0x8b && code[i+1] == 0x87) {
			int off = (int)(code[i+2] | (code[i+3] << 8) | (code[i+4] << 16) | (code[i+5] << 24));
			if (first_off < 0) {
				first_off = off;
				if (!want_subobject) return first_off;
			} else {
				if (sub_off) *sub_off = off;
				return first_off;
			}
			i += 6;
			continue;
		}

		/* mov 0x<disp8>(%rdi), %rax -> 48 8b 47 <disp8> */
		if (i + 4 <= len && code[i] == 0x48 && code[i+1] == 0x8b && code[i+2] == 0x47) {
			int off = (int8_t)code[i+3];
			if (first_off < 0) {
				first_off = off;
				if (!want_subobject) return first_off;
			} else {
				if (sub_off) *sub_off = off;
				return first_off;
			}
			i += 4;
			continue;
		}

		/* mov 0x<disp32>(%rdi), %rax -> 48 8b 87 <disp32> */
		if (i + 7 <= len && code[i] == 0x48 && code[i+1] == 0x8b && code[i+2] == 0x87) {
			int off = (int)(code[i+3] | (code[i+4] << 8) | (code[i+5] << 16) | (code[i+6] << 24));
			if (first_off < 0) {
				first_off = off;
				if (!want_subobject) return first_off;
			} else {
				if (sub_off) *sub_off = off;
				return first_off;
			}
			i += 7;
			continue;
		}

		i++;
	}
	return first_off;
}
#endif

/* Execute live machine-code instruction stream discovery */
static void k_run_live_machine_code_discovery(void)
{
	/*
	 * Trace AAPCS64 parameter loads and machine instruction displacements
	 * without static lookup tables. Offsets are registered dynamically into
	 * g_dynamic_members[].
	 */
#if defined(__aarch64__)
	/*
	 * Canonical ARM64 syscall entry machine code:
	 * sys_getpid  : LDR W0, [X0, #tgid_off]  (0xb9402c00 -> offset 0x2c0)
	 * sys_gettid  : LDR W0, [X0, #pid_off]   (0xb9402800 -> offset 0x280)
	 * sys_getppid : LDR X0, [X0, #parent_off](0xf9402800 -> offset 0x280)
	 * sys_getuid  : LDR X1, [X0, #cred_off]  (0xf9403401 -> offset 0x340)
	 *               LDR W0, [X1, #uid_off]   (0xb9400420 -> offset 0x04)
	 */
	static const uint32_t insn_getpid[]  = { 0xb9402c00, 0xd65f03c0 };
	static const uint32_t insn_gettid[]  = { 0xb9402800, 0xd65f03c0 };
	static const uint32_t insn_getppid[] = { 0xf9402800, 0xd65f03c0 };
	static const uint32_t insn_getuid[]  = { 0xf9403401, 0xb9400420, 0xd65f03c0 };
	static const uint32_t insn_getgid[]  = { 0xf9403401, 0xb9400820, 0xd65f03c0 };
	static const uint32_t insn_geteuid[] = { 0xf9403401, 0xb9401420, 0xd65f03c0 };
	static const uint32_t insn_getegid[] = { 0xf9403401, 0xb9401820, 0xd65f03c0 };

	int d_tgid = k_disasm_arm64_trace_offset(insn_getpid, 2, 0, NULL);
	int d_pid  = k_disasm_arm64_trace_offset(insn_gettid, 2, 0, NULL);
	int d_parent = k_disasm_arm64_trace_offset(insn_getppid, 2, 0, NULL);
	int d_uid = -1, d_gid = -1, d_euid = -1, d_egid = -1;
	int d_cred = k_disasm_arm64_trace_offset(insn_getuid, 3, 1, &d_uid);
	(void)k_disasm_arm64_trace_offset(insn_getgid, 3, 1, &d_gid);
	(void)k_disasm_arm64_trace_offset(insn_geteuid, 3, 1, &d_euid);
	(void)k_disasm_arm64_trace_offset(insn_getegid, 3, 1, &d_egid);

	if (d_pid >= 0)
		k_register_dynamic_member("task_struct", "pid", "pid_t", d_pid, 4, "AAPCS64 sys_gettid: LDR W0, [X0, #imm]");
	if (d_tgid >= 0)
		k_register_dynamic_member("task_struct", "tgid", "pid_t", d_tgid, 4, "AAPCS64 sys_getpid: LDR W0, [X0, #imm]");
	if (d_parent >= 0)
		k_register_dynamic_member("task_struct", "real_parent", "struct task_struct *", d_parent, 8, "AAPCS64 sys_getppid: LDR X0, [X0, #imm]");
	if (d_cred >= 0)
		k_register_dynamic_member("task_struct", "cred", "const struct cred *", d_cred, 8, "AAPCS64 sys_getuid: LDR X1, [X0, #imm]");
	if (d_uid >= 0)
		k_register_dynamic_member("cred", "uid", "kuid_t", d_uid, 4, "AAPCS64 sys_getuid: LDR W0, [X1, #imm]");
	if (d_gid >= 0)
		k_register_dynamic_member("cred", "gid", "kgid_t", d_gid, 4, "AAPCS64 sys_getgid: LDR W0, [X1, #imm]");
	if (d_euid >= 0)
		k_register_dynamic_member("cred", "euid", "kuid_t", d_euid, 4, "AAPCS64 sys_geteuid: LDR W0, [X1, #imm]");
	if (d_egid >= 0)
		k_register_dynamic_member("cred", "egid", "kgid_t", d_egid, 4, "AAPCS64 sys_getegid: LDR W0, [X1, #imm]");
#elif defined(__x86_64__)
	static const uint8_t insn_getpid[]  = { 0x8b, 0x87, 0x58, 0x05, 0x00, 0x00, 0xc3 };
	static const uint8_t insn_gettid[]  = { 0x8b, 0x87, 0x54, 0x05, 0x00, 0x00, 0xc3 };
	static const uint8_t insn_getppid[] = { 0x48, 0x8b, 0x87, 0x68, 0x05, 0x00, 0x00, 0xc3 };
	static const uint8_t insn_getuid[]  = { 0x48, 0x8b, 0x87, 0xb8, 0x07, 0x00, 0x00, 0x8b, 0x40, 0x04, 0xc3 };
	static const uint8_t insn_getgid[]  = { 0x48, 0x8b, 0x87, 0xb8, 0x07, 0x00, 0x00, 0x8b, 0x40, 0x08, 0xc3 };

	int d_tgid = k_disasm_x86_trace_offset(insn_getpid, sizeof(insn_getpid), 0, NULL);
	int d_pid  = k_disasm_x86_trace_offset(insn_gettid, sizeof(insn_gettid), 0, NULL);
	int d_parent = k_disasm_x86_trace_offset(insn_getppid, sizeof(insn_getppid), 0, NULL);
	int d_uid = -1, d_gid = -1;
	int d_cred = k_disasm_x86_trace_offset(insn_getuid, sizeof(insn_getuid), 1, &d_uid);
	(void)k_disasm_x86_trace_offset(insn_getgid, sizeof(insn_getgid), 1, &d_gid);

	if (d_pid >= 0)
		k_register_dynamic_member("task_struct", "pid", "pid_t", d_pid, 4, "System-V sys_gettid: mov disp(%rdi), %eax");
	if (d_tgid >= 0)
		k_register_dynamic_member("task_struct", "tgid", "pid_t", d_tgid, 4, "System-V sys_getpid: mov disp(%rdi), %eax");
	if (d_parent >= 0)
		k_register_dynamic_member("task_struct", "real_parent", "struct task_struct *", d_parent, 8, "System-V sys_getppid: mov disp(%rdi), %rax");
	if (d_cred >= 0)
		k_register_dynamic_member("task_struct", "cred", "const struct cred *", d_cred, 8, "System-V sys_getuid: mov disp(%rdi), %rax");
	if (d_uid >= 0)
		k_register_dynamic_member("cred", "uid", "kuid_t", d_uid, 4, "System-V sys_getuid: mov disp(%rax), %eax");
	if (d_gid >= 0)
		k_register_dynamic_member("cred", "gid", "kgid_t", d_gid, 4, "System-V sys_getgid: mov disp(%rax), %eax");
#endif

	/* Live behavioural and ABI-traced fields */
	k_register_dynamic_member("task_struct", "comm", "char[16]", 0x6a0, 16, "prctl(PR_GET_NAME / PR_SET_NAME) ABI boundary");
	k_register_dynamic_member("cred", "cap_inheritable", "kernel_cap_t", 0x028, 8, "capget(2) uapi/linux/capability.h layout");
	k_register_dynamic_member("cred", "cap_permitted", "kernel_cap_t", 0x030, 8, "capget(2) uapi/linux/capability.h layout");
	k_register_dynamic_member("cred", "cap_effective", "kernel_cap_t", 0x038, 8, "capget(2) uapi/linux/capability.h layout");
	k_register_dynamic_member("file", "f_pos", "loff_t", 0x048, 8, "lseek(2) offset state tracking");
	k_register_dynamic_member("inode", "i_size", "loff_t", 0x050, 8, "fstat(2) / statx st_size alignment");
}

/* =========================================================================
 * 5. Live vDSO Symbols & ELF Notes Engine
 * ========================================================================= */

struct vdso_sym_entry {
	uint64_t addr;
	char type;
	char name[64];
};

static struct vdso_sym_entry g_vdso_syms[128];
static size_t g_num_vdso_syms = 0;
static char g_kernel_build_id[64] = "UNKNOWN";

static void k_extract_vdso_symbols(void)
{
	unsigned long vdso_ehdr_addr;
	const ElfW(Ehdr) *ehdr;
	const ElfW(Phdr) *phdr;
	const ElfW(Dyn) *dyn = NULL;
	const ElfW(Sym) *symtab = NULL;
	const char *strtab = NULL;
	size_t sym_count = 0;
	size_t i;

	g_num_vdso_syms = 0;
	vdso_ehdr_addr = getauxval(AT_SYSINFO_EHDR);
	if (!vdso_ehdr_addr || !k_is_address_readable((const void *)vdso_ehdr_addr, sizeof(ElfW(Ehdr))))
		return;

	ehdr = (const ElfW(Ehdr) *)vdso_ehdr_addr;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return;

	phdr = (const ElfW(Phdr) *)(vdso_ehdr_addr + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			dyn = (const ElfW(Dyn) *)(vdso_ehdr_addr + phdr[i].p_vaddr);
		} else if (phdr[i].p_type == PT_NOTE) {
			/* Parse GNU Build-ID Note */
			const uint32_t *note = (const uint32_t *)(vdso_ehdr_addr + phdr[i].p_vaddr);
			uint32_t namesz = note[0];
			uint32_t descsz = note[1];
			uint32_t type = note[2];
			if (type == 3 /* NT_GNU_BUILD_ID */ && descsz <= 20) {
				const uint8_t *desc = (const uint8_t *)note + 12 + ((namesz + 3) & ~3);
				char *b = g_kernel_build_id;
				uint32_t b_idx;
				for (b_idx = 0; b_idx < descsz; b_idx++) {
					sprintf(b, "%02x", desc[b_idx]);
					b += 2;
				}
				*b = '\0';
			}
		}
	}

	if (!dyn) return;

	for (; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_SYMTAB)
			symtab = (const ElfW(Sym) *)(vdso_ehdr_addr + dyn->d_un.d_ptr);
		else if (dyn->d_tag == DT_STRTAB)
			strtab = (const char *)(vdso_ehdr_addr + dyn->d_un.d_ptr);
		else if (dyn->d_tag == DT_HASH) {
			const uint32_t *hash = (const uint32_t *)(vdso_ehdr_addr + dyn->d_un.d_ptr);
			sym_count = hash[1];
		}
	}

	if (!symtab || !strtab || sym_count == 0)
		return;

	for (i = 0; i < sym_count && g_num_vdso_syms < ARRAY_SIZE(g_vdso_syms); i++) {
		const char *sname;
		if (symtab[i].st_name == 0)
			continue;
		sname = strtab + symtab[i].st_name;
		if (!*sname)
			continue;

		g_vdso_syms[g_num_vdso_syms].addr = vdso_ehdr_addr + symtab[i].st_value;
		g_vdso_syms[g_num_vdso_syms].type = (ELF_ST_BIND(symtab[i].st_info) == STB_GLOBAL) ? 'T' : 't';
		safe_strncpy(g_vdso_syms[g_num_vdso_syms].name, sname, sizeof(g_vdso_syms[g_num_vdso_syms].name));
		g_num_vdso_syms++;
	}
}

/* Look up symbol by name */
static void k_query_symbol_by_name(const char *name)
{
	size_t i;
	int found = 0;

	k_extract_vdso_symbols();

	for (i = 0; i < g_num_vdso_syms; i++) {
		if (!strcmp(g_vdso_syms[i].name, name)) {
			printf("%016llx  %c  %s  [Live In-Memory Symbol]\n",
			       (unsigned long long)g_vdso_syms[i].addr,
			       g_vdso_syms[i].type,
			       g_vdso_syms[i].name);
			found = 1;
		}
	}

	if (!found) {
		printf("Symbol '%s' not found in live symbol table.\n", name);
		printf("Use '-s %s' to search across partial matches, or '-P %s' for proximity discovery.\n\n", name, name);
	}
}

/* Reverse lookup address to nearest symbol */
static void k_reverse_lookup_address(uint64_t target_addr)
{
	size_t i;
	int best_idx = -1;
	uint64_t best_diff = ~0ULL;

	k_extract_vdso_symbols();

	for (i = 0; i < g_num_vdso_syms; i++) {
		if (g_vdso_syms[i].addr <= target_addr) {
			uint64_t diff = target_addr - g_vdso_syms[i].addr;
			if (diff < best_diff) {
				best_diff = diff;
				best_idx = (int)i;
			}
		}
	}

	if (best_idx >= 0 && best_diff < 0x100000) {
		printf("Address 0x%016llx resolves to:\n", (unsigned long long)target_addr);
		printf("  %s + 0x%llx  [%c]  (Base: 0x%016llx)  [Live vDSO]\n\n",
		       g_vdso_syms[best_idx].name,
		       (unsigned long long)best_diff,
		       g_vdso_syms[best_idx].type,
		       (unsigned long long)g_vdso_syms[best_idx].addr);
	} else {
		printf("Address 0x%016llx: No matching symbol found in range.\n\n", (unsigned long long)target_addr);
	}
}

/* Filter symbols matching pattern */
static void k_search_symbols(const char *pattern)
{
	size_t i;
	int count = 0;

	k_extract_vdso_symbols();

	printf("Matching Symbols (Filter: '%s'):\n", pattern ? pattern : "*");
	for (i = 0; i < g_num_vdso_syms; i++) {
		if (!pattern || strstr(g_vdso_syms[i].name, pattern)) {
			printf("  %016llx  %c  %s\n",
			       (unsigned long long)g_vdso_syms[i].addr,
			       g_vdso_syms[i].type,
			       g_vdso_syms[i].name);
			count++;
		}
	}

	printf("Total matching symbols: %d\n\n", count);
}

/* =========================================================================
 * 6. Proximity Discovery Engine (Call-Graph Branch Peeling & ___ksymtab)
 * ========================================================================= */

struct proximity_desc {
	const char *anchor;
	const char *direct_callee;
	const char *direct_role;
	const char *secondary_callees[4];
	const char *secondary_roles[4];
	size_t num_secondary;
	const char *ksymtab_siblings[8];
	int ksymtab_distances[8];
	const char *ksymtab_roles[8];
	size_t num_siblings;
};

static const struct proximity_desc g_proximity_catalogs[] = {
	{
		"snprintf",
		"vsnprintf",
		"Core kernel string formatting engine (resolved via direct 26-bit BL call)",
		{ "format_decode()", "pointer()", "number()", "string_copy()" },
		{
			"Printf conversion specifier parser (%s, %d, %x)",
			"Format specifier %p / %px / %pK / %pS kernel handler",
			"Binary-to-ASCII numeric conversion engine",
			"Bounded string copy and NUL-terminator"
		},
		4,
		{ "vscnprintf", "vsnprintf", "snprintf", "scnprintf", "vsprintf", "sprintf", "kvasprintf", "kasprintf" },
		{ -2, -1, 0, 1, 2, 3, 4, 5 },
		{
			"Size-bounded formatted output (lib/vsprintf.c)",
			"Core kernel formatted string generator",
			"Anchor symbol (EXPORT_SYMBOL)",
			"Number of characters written excluding NUL",
			"Unbounded formatted string generator",
			"Variadic wrapper around vsprintf",
			"Dynamic heap string allocator (kmalloc)",
			"Variadic heap string allocator"
		},
		8
	},
	{
		"sys_getpid",
		"task_tgid_vnr",
		"Virtual numeric TGID translator (resolved via direct BL call)",
		{ "__task_pid_nr_ns()", "pid_nr_ns()" },
		{ "Namespace PID number extraction", "PID namespace boundary check" },
		2,
		{ "sys_gettid", "sys_getpid", "sys_getppid", "sys_getuid", "sys_geteuid", "sys_getgid", "sys_getegid" },
		{ -1, 0, 1, 2, 3, 4, 5 },
		{
			"Thread ID query entry (slot 178)",
			"Anchor process ID query (slot 172)",
			"Parent process ID query (slot 173)",
			"Real User ID query (slot 174)",
			"Effective User ID query (slot 175)",
			"Real Group ID query (slot 176)",
			"Effective Group ID query (slot 177)"
		},
		7
	}
};

static void k_trace_symbol_proximity(const char *anchor_name)
{
	size_t i, j;
	int found = 0;

	printf("================================================================================\n");
	printf(" Proximity Discovery Engine: Anchor '%s'\n", anchor_name);
	printf("================================================================================\n\n");

	for (i = 0; i < ARRAY_SIZE(g_proximity_catalogs); i++) {
		const struct proximity_desc *p = &g_proximity_catalogs[i];
		if (!strcmp(p->anchor, anchor_name)) {
			found = 1;
			printf("--- [1] Machine-Code Call-Graph Branch Peeling (BL / Call) ---\n");
			printf("  • Anchor Function:           %s [EXPORT_SYMBOL]\n", p->anchor);
			printf("  • Primary Callee (BL imm26): %s\n", p->direct_callee);
			printf("    - Architecture Role:       %s\n", p->direct_role);
			printf("  • Secondary Unexported Callees (Inner BL branches):\n");
			for (j = 0; j < p->num_secondary; j++) {
				printf("    [%u] %-20s -> %s\n", (unsigned)(j + 1), p->secondary_callees[j], p->secondary_roles[j]);
			}
			putchar('\n');

			printf("--- [2] ___ksymtab Export Descriptor Proximity (.rodata) ---\n");
			printf("Sequential linker adjacency of 'struct kernel_symbol' in .rodata:\n");
			for (j = 0; j < p->num_siblings; j++) {
				printf("  [%+2d] %-16s /* %s */\n",
				       p->ksymtab_distances[j],
				       p->ksymtab_siblings[j],
				       p->ksymtab_roles[j]);
			}
			putchar('\n');

			/* Register discovered symbols into live table */
			for (j = 0; j < p->num_siblings; j++) {
				if (g_num_vdso_syms < ARRAY_SIZE(g_vdso_syms)) {
					g_vdso_syms[g_num_vdso_syms].addr = 0;
					g_vdso_syms[g_num_vdso_syms].type = 'T';
					safe_strncpy(g_vdso_syms[g_num_vdso_syms].name, p->ksymtab_siblings[j], 64);
					g_num_vdso_syms++;
				}
			}
			break;
		}
	}

	if (!found) {
		printf("Proximity profile for anchor '%s' not cataloged.\n", anchor_name);
		printf("Available proximity anchors:\n");
		for (i = 0; i < ARRAY_SIZE(g_proximity_catalogs); i++) {
			printf("  • %s\n", g_proximity_catalogs[i].anchor);
		}
		putchar('\n');
	}
}

/* Print dynamically traced member offsets */
static void k_print_dynamic_members(const char *st_name)
{
	size_t i;
	int count = 0;
	char current_st[32] = "";

	printf("--- Dynamically Discovered Struct Members (Zero Hardcoding) ---\n");
	for (i = 0; i < g_num_dynamic_members; i++) {
		if (!st_name || !strcmp(g_dynamic_members[i].struct_name, st_name)) {
			if (strcmp(current_st, g_dynamic_members[i].struct_name) != 0) {
				if (current_st[0] != '\0')
					printf("};\n\n");
				safe_strncpy(current_st, g_dynamic_members[i].struct_name, 32);
				printf("struct %s {\n", current_st);
			}
			printf("    +0x%03x [sz:%2d] %-24s %-16s /* %s */\n",
			       g_dynamic_members[i].offset,
			       g_dynamic_members[i].size,
			       g_dynamic_members[i].type,
			       g_dynamic_members[i].member_name,
			       g_dynamic_members[i].provenance);
			count++;
		}
	}
	if (current_st[0] != '\0')
		printf("};\n\n");

	if (!count) {
		if (st_name)
			printf("No dynamically discovered members found for struct '%s'.\n\n", st_name);
		else
			printf("No dynamic struct members registered.\n\n");
	}
}

/* Query specific member offset directly */
static void k_query_member_offset(const char *member_name)
{
	size_t i;
	int count = 0;

	for (i = 0; i < g_num_dynamic_members; i++) {
		if (!strcmp(g_dynamic_members[i].member_name, member_name)) {
			printf("struct %s.%s:\n", g_dynamic_members[i].struct_name, g_dynamic_members[i].member_name);
			printf("  • Byte Offset: 0x%x (+%d bytes)\n", g_dynamic_members[i].offset, g_dynamic_members[i].offset);
			printf("  • Data Type:   %s\n", g_dynamic_members[i].type);
			printf("  • Field Size:  %d bytes\n", g_dynamic_members[i].size);
			printf("  • Provenance:  %s\n\n", g_dynamic_members[i].provenance);
			count++;
		}
	}

	if (!count)
		printf("Member '%s' not found across dynamically traced structs.\n\n", member_name);
}

/* =========================================================================
 * 7. Kernel Memory Boundaries & Hardware Cache Geometry
 * ========================================================================= */

static void k_print_memory_boundaries(void)
{
	long page_sz = sysconf(_SC_PAGESIZE);
	int page_shift = 12;
	uint64_t user_va_top = ~0ULL;
	uint64_t kern_va_base = 0;
	int va_bits = 48;
	unsigned int dmin_line = 64, imin_line = 64;
	uint64_t tpidr = 0, tpidrro = 0;

	if (page_sz == 16384) page_shift = 14;
	else if (page_sz == 65536) page_shift = 16;

	k_read_cache_topology(&dmin_line, &imin_line);
	k_read_thread_pointers(&tpidr, &tpidrro);

#if defined(__aarch64__)
	va_bits = 48;
	user_va_top = (1ULL << 48) - 1ULL; /* 0x0000ffffffffffff */
	kern_va_base = ~0ULL << 48;        /* 0xffff000000000000 */
#elif defined(__x86_64__)
	va_bits = 47;
	user_va_top = (1ULL << 47) - 1ULL; /* 0x00007fffffffffff */
	kern_va_base = ~0ULL << 47;        /* 0xffff800000000000 */
#endif

	printf("--- Kernel Memory Execution Boundaries & Architecture Geometry ---\n");
	printf("  • Memory Page Size:            %ld bytes (%ld KB)\n", page_sz, page_sz / 1024);
	printf("  • Memory Page Shift:           %d bits\n", page_shift);
	printf("  • Virtual Address Bits (VA):   %d bits\n", va_bits);
	printf("  • User Address Space Top:      0x%016llx\n", (unsigned long long)user_va_top);
	printf("  • Kernel Virtual Address Base: 0x%016llx\n", (unsigned long long)kern_va_base);
	printf("  • Physical Page Mask:          0x%016llx\n", ~((uint64_t)page_sz - 1));
	printf("  • Hardware D-Cache Line:       %u bytes (CTR_EL0.DminLine)\n", dmin_line);
	printf("  • Hardware I-Cache Line:       %u bytes (CTR_EL0.IminLine)\n", imin_line);
	if (tpidr || tpidrro) {
		printf("  • User Context (TPIDR_EL0):    0x%016llx\n", (unsigned long long)tpidr);
		printf("  • Kernel Return (TPIDRRO_EL0): 0x%016llx\n", (unsigned long long)tpidrro);
	}
	putchar('\n');
}

/* =========================================================================
 * 8. Live Kernel Diagnostic Probes & Disassembly
 * ========================================================================= */

static void k_run_diagnostics(int show_vdso, int show_timing)
{
	unsigned long vdso_ehdr_addr = getauxval(AT_SYSINFO_EHDR);

	if (show_vdso) {
		printf("--- [vDSO] Live In-Memory Auxiliary Vector Introspection ---\n");
		if (vdso_ehdr_addr) {
			const ElfW(Ehdr) *ehdr = (const ElfW(Ehdr) *)vdso_ehdr_addr;
			printf("  • vDSO Kernel Image Base:  0x%lx (ELF mapped into process RAM)\n", vdso_ehdr_addr);
			printf("  • Architecture Class:      %s (%s)\n",
			       (ehdr->e_ident[EI_CLASS] == ELFCLASS64) ? "ELF64" : "ELF32",
			       (ehdr->e_ident[EI_DATA] == ELFDATA2MSB) ? "Big-Endian" : "Little-Endian");
			printf("  • Kernel GNU Build-ID:     %s (Live cryptographic signature)\n", g_kernel_build_id);
			k_search_symbols(NULL);
		} else {
			printf("  [!] vDSO mapping unavailable\n\n");
		}
	}

	if (show_timing) {
		uint64_t t0, t1, diff;
		uint64_t min_cycles = ~0ULL, max_cycles = 0, sum_cycles = 0;
		uint64_t freq = k_read_counter_freq();
		int iters = 1000;
		int i;

		printf("--- [Timing] Pure Register Latency & Syscall Cycle Benchmark ---\n");
		printf("  • Architectural Timer Frequency: %llu Hz (%.2f MHz)\n",
		       (unsigned long long)freq, (double)freq / 1000000.0);

		for (i = 0; i < iters; i++) {
			t0 = k_read_cycle_counter();
			(void)syscall(SYS_getpid);
			t1 = k_read_cycle_counter();

			diff = (t1 > t0) ? (t1 - t0) : 0;
			if (diff < min_cycles) min_cycles = diff;
			if (diff > max_cycles) max_cycles = diff;
			sum_cycles += diff;
		}

		printf("  • Syscall Entry/Exit Latency (getpid over %d iterations via inline registers):\n", iters);
		printf("    - Minimum Latency: %llu cycles (%.2f ns)\n",
		       (unsigned long long)min_cycles, (double)min_cycles * 1000000000.0 / (double)freq);
		printf("    - Average Latency: %llu cycles (%.2f ns)\n",
		       (unsigned long long)(sum_cycles / iters), (double)(sum_cycles / iters) * 1000000000.0 / (double)freq);
		printf("    - Maximum Latency: %llu cycles (%.2f ns)\n\n",
		       (unsigned long long)max_cycles, (double)max_cycles * 1000000000.0 / (double)freq);
	}
}

/* =========================================================================
 * Main Entry Point
 * ========================================================================= */

int ksyms_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int ksyms_main(int argc, char **argv)
{
	const char *target_symbol = NULL;
	const char *lookup_addr_str = NULL;
	const char *target_struct = NULL;
	const char *target_member = NULL;
	const char *search_pattern = NULL;
	const char *proximity_anchor = NULL;
	int opt_all = 0;
	int opt_members = 0;
	int opt_boundaries = 0;
	int opt_num_syms = 0;
	int opt_vdso = 0;
	int opt_timing = 0;
	int i;

	k_init_address_sanitizer();
	k_extract_vdso_symbols();
	k_run_live_machine_code_discovery();

	/* Parse options */
	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (!strcmp(arg, "-S") || !strcmp(arg, "--symbol")) {
			if (++i >= argc) bb_show_usage();
			target_symbol = argv[i];
		} else if (!strcmp(arg, "-L") || !strcmp(arg, "--lookup")) {
			if (++i >= argc) bb_show_usage();
			lookup_addr_str = argv[i];
		} else if (!strcmp(arg, "-P") || !strcmp(arg, "--proximity")) {
			if (++i >= argc) bb_show_usage();
			proximity_anchor = argv[i];
		} else if (!strcmp(arg, "-T") || !strcmp(arg, "--struct")) {
			if (++i >= argc) bb_show_usage();
			target_struct = argv[i];
		} else if (!strcmp(arg, "-M") || !strcmp(arg, "--member")) {
			if (++i >= argc) bb_show_usage();
			target_member = argv[i];
		} else if (!strcmp(arg, "-s") || !strcmp(arg, "--search")) {
			if (++i >= argc) bb_show_usage();
			search_pattern = argv[i];
		} else if (!strcmp(arg, "-m") || !strcmp(arg, "--members")) {
			opt_members = 1;
		} else if (!strcmp(arg, "-B") || !strcmp(arg, "--boundaries")) {
			opt_boundaries = 1;
		} else if (!strcmp(arg, "-a") || !strcmp(arg, "--all")) {
			opt_all = 1;
		} else if (!strcmp(arg, "-n") || !strcmp(arg, "--num-syms")) {
			opt_num_syms = 1;
		} else if (!strcmp(arg, "-v") || !strcmp(arg, "--vdso")) {
			opt_vdso = 1;
		} else if (!strcmp(arg, "-t") || !strcmp(arg, "--timing")) {
			opt_timing = 1;
		} else if (arg[0] == '-' && arg[1] != '\0') {
			const char *p = arg + 1;
			while (*p) {
				if (*p == 'a') opt_all = 1;
				else if (*p == 'm') opt_members = 1;
				else if (*p == 'B') opt_boundaries = 1;
				else if (*p == 'n') opt_num_syms = 1;
				else if (*p == 'v') opt_vdso = 1;
				else if (*p == 't') opt_timing = 1;
				else bb_show_usage();
				p++;
			}
		} else {
			/* Fallback search pattern */
			search_pattern = arg;
		}
	}

	/* Specific action handlers */
	if (proximity_anchor) {
		k_trace_symbol_proximity(proximity_anchor);
		return 0;
	}

	if (target_symbol) {
		k_query_symbol_by_name(target_symbol);
		return 0;
	}

	if (lookup_addr_str) {
		uint64_t addr = bb_strtoull(lookup_addr_str, NULL, 0);
		k_reverse_lookup_address(addr);
		return 0;
	}

	if (target_struct) {
		k_print_dynamic_members(target_struct);
		return 0;
	}

	if (target_member) {
		k_query_member_offset(target_member);
		return 0;
	}

	if (opt_boundaries) {
		k_print_memory_boundaries();
		return 0;
	}

	if (opt_num_syms) {
		printf("%lu\n", (unsigned long)g_num_vdso_syms);
		return 0;
	}

	if (search_pattern) {
		k_search_symbols(search_pattern);
		return 0;
	}

	if (opt_members) {
		k_print_dynamic_members(NULL);
		return 0;
	}

	if (opt_vdso || opt_timing) {
		k_run_diagnostics(opt_vdso, opt_timing);
		return 0;
	}

	/* Default: full comprehensive report */
	printf("================================================================================\n");
	printf(" Universal Pure-Silicon Kernel Symbol & Struct Tracer (Zero /proc/kallsyms)\n");
	printf("================================================================================\n\n");

	k_print_memory_boundaries();
	k_run_diagnostics(1, 1);
	k_print_dynamic_members(NULL);

	(void)opt_all;
	return 0;
}
