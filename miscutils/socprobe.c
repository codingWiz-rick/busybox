/* vi: set sw=4 ts=4: */
/*
 * socprobe - Mobile SoC Hardware, MMIO, PLL, PMIC & CPU Machine-Code Engine
 *
 * Dedicated zero-dependency silicon hardware diagnostic suite for mobile SoCs.
 * Probes physical MMIO peripheral register windows, clock trees/PLLs, SPMI PMIC
 * buses, and executes direct architectural CPU system register audits via pure
 * inline assembly with built-in AArch64 machine-code instruction disassembly.
 *
 * Designed specifically for production Android environments where debugfs is
 * omitted/restricted (CONFIG_DEBUG_FS=n) and /dev/mem is blocked (CONFIG_DEVMEM=n).
 *
 * Licensed under GPLv2 or later.
 */

//config:config SOCPROBE
//config:	bool "socprobe (silicon hardware, MMIO, PLL, PMIC & CPU probe)"
//config:	default y
//config:	help
//config:	  Mobile SoC silicon hardware, MMIO, PLL, PMIC, and machine code
//config:	  probing suite. Discovers memory-mapped I/O peripherals, clock
//config:	  trees, SPMI PMIC buses, and executes inline assembly CPU
//config:	  register audits with built-in AArch64 machine code disassembler.

//applet:IF_SOCPROBE(APPLET_NOEXEC(socprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, socprobe))
//applet:IF_SOCPROBE(APPLET_NOEXEC(socreg, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, socreg))
//applet:IF_SOCPROBE(APPLET_NOEXEC(regprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, regprobe))
//applet:IF_SOCPROBE(APPLET_NOEXEC(pllprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, pllprobe))

//kbuild:lib-$(CONFIG_SOCPROBE) += socprobe.o

//usage:#define socprobe_trivial_usage
//usage:       "COMMAND [ARGS...]"
//usage:#define socprobe_full_usage "\n\n"
//usage:       "Mobile SoC silicon hardware, MMIO, PLL, PMIC, and CPU probe\n"
//usage:     "\nCommands:"
//usage:     "\n	status, info         Comprehensive SoC silicon telemetry overview"
//usage:     "\n	mmio [FILTER]        Exhaustive physical MMIO register map and drivers"
//usage:     "\n	pll, clocks          Clock controllers, CPU cluster OPPs, and devfreq"
//usage:     "\n	pmic                 SPMI PMIC buses, LDO/SMPS rails, and battery telemetry"
//usage:     "\n	cpu                  Architectural CPU system registers via inline assembly"
//usage:     "\n	disasm <HEX...>      Disassemble 32-bit AArch64 machine instructions"
//usage:
//usage:#define socreg_trivial_usage socprobe_trivial_usage
//usage:#define socreg_full_usage socprobe_full_usage
//usage:#define regprobe_trivial_usage socprobe_trivial_usage
//usage:#define regprobe_full_usage socprobe_full_usage
//usage:#define pllprobe_trivial_usage socprobe_trivial_usage
//usage:#define pllprobe_full_usage socprobe_full_usage

#include "libbb.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <setjmp.h>
#include <signal.h>
#include <ctype.h>

/* ==============================================================================
 * Section 1: AArch64 Architectural System Registers & Inline Assembly
 * ============================================================================== */

#if defined(__aarch64__) || defined(__arm64__)
static sigjmp_buf g_sigill_jmp;

static void sigill_handler(int sig)
{
	(void)sig;
	siglongjmp(g_sigill_jmp, 1);
}

/* Safely read AArch64 architectural system registers with SIGILL trap recovery */
static uint64_t read_arm64_sysreg(int reg_id, bool *ok)
{
	struct sigaction sa, old_sa;
	uint64_t val = 0;
	bool success = false;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigill_handler;
	sigaction(SIGILL, &sa, &old_sa);

	if (sigsetjmp(g_sigill_jmp, 1) == 0) {
		switch (reg_id) {
		case 0: asm volatile("mrs %0, midr_el1" : "=r"(val)); break;
		case 1: asm volatile("mrs %0, mpidr_el1" : "=r"(val)); break;
		case 2: asm volatile("mrs %0, ctr_el0" : "=r"(val)); break;
		case 3: asm volatile("mrs %0, dczid_el0" : "=r"(val)); break;
		case 4: asm volatile("mrs %0, id_aa64isar0_el1" : "=r"(val)); break;
		case 5: asm volatile("mrs %0, id_aa64isar1_el1" : "=r"(val)); break;
		case 6: asm volatile("mrs %0, id_aa64pfr0_el1" : "=r"(val)); break;
		case 7: asm volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(val)); break;
		case 8: asm volatile("mrs %0, cntfrq_el0" : "=r"(val)); break;
		case 9: asm volatile("mrs %0, cntvct_el0" : "=r"(val)); break;
		default: break;
		}
		success = true;
	} else {
		success = false;
	}

	sigaction(SIGILL, &old_sa, NULL);
	if (ok)
		*ok = success;
	return val;
}

/*
 * Implementer and part-name look-up tables.
 * Only used from code that is itself inside #if defined(__aarch64__), so
 * guard them with the same macro to avoid -Wunused-function on x86 host
 * builds where the inline-assembly block is compiled out.
 */
static const char *get_arm_implementer_name(uint8_t impl)
{
	switch (impl) {
	case 0x41: return "ARM Limited";
	case 0x42: return "Broadcom";
	case 0x43: return "Cavium";
	case 0x4e: return "NVIDIA";
	case 0x50: return "AppliedMicro";
	case 0x51: return "Qualcomm Inc.";
	case 0x53: return "Samsung";
	case 0x69: return "Intel";
	default:   return "Unknown Implementer";
	}
}

static const char *get_arm_part_name(uint8_t impl, uint16_t part)
{
	if (impl == 0x51) {
		/* Qualcomm Parts */
		switch (part) {
		case 0x800: return "Kryo 260 / 280 (Cortex-A73 derivative)";
		case 0x801: return "Kryo 260 / 280 (Cortex-A53 derivative)";
		case 0x802: return "Kryo 385 Gold (Cortex-A75 derivative)";
		case 0x803: return "Kryo 385 Silver (Cortex-A55 derivative)";
		case 0x804: return "Kryo 485 Gold (Cortex-A76 derivative)";
		case 0x805: return "Kryo 485 Silver (Cortex-A55 derivative)";
		case 0xc00: return "Falkor";
		default:    return "Qualcomm Custom Core";
		}
	} else if (impl == 0x41) {
		/* ARM Standard Parts */
		switch (part) {
		case 0xd03: return "Cortex-A53";
		case 0xd05: return "Cortex-A55";
		case 0xd07: return "Cortex-A57";
		case 0xd08: return "Cortex-A72";
		case 0xd09: return "Cortex-A73";
		case 0xd0a: return "Cortex-A75";
		case 0xd0b: return "Cortex-A76";
		case 0xd0d: return "Cortex-A77";
		case 0xd41: return "Cortex-A78";
		case 0xd44: return "Cortex-X1";
		case 0xd46: return "Cortex-A510";
		case 0xd47: return "Cortex-A710";
		case 0xd48: return "Cortex-X2";
		default:    return "ARM Cortex Standard Core";
		}
	}
	return "ARM64 Processor Core";
}
#endif /* __aarch64__ */

/* ==============================================================================
 * Section 2: Pure AArch64 Machine-Code Instruction Disassembler
 * ============================================================================== */

/* Decodes raw 32-bit little-endian AArch64 instruction opcodes */
static void disassemble_aarch64_insn(uint32_t insn, uint64_t addr, char *out_buf, size_t out_sz)
{
	/* 1. MRS / MSR (System Register Move) */
	if ((insn & 0xfff00000) == 0xd5300000) {
		/* MRS Xt, <system_reg> */
		uint32_t rt = insn & 0x1f;
		uint32_t op0 = (insn >> 19) & 0x3;
		uint32_t op1 = (insn >> 16) & 0x7;
		uint32_t crn = (insn >> 12) & 0xf;
		uint32_t crm = (insn >> 8) & 0xf;
		uint32_t op2 = (insn >> 5) & 0x7;
		const char *reg_name = "sreg";

		if (op0 == 3 && op1 == 0 && crn == 0 && crm == 0 && op2 == 0) reg_name = "midr_el1";
		else if (op0 == 3 && op1 == 0 && crn == 0 && crm == 0 && op2 == 5) reg_name = "mpidr_el1";
		else if (op0 == 3 && op1 == 3 && crn == 0 && crm == 0 && op2 == 1) reg_name = "ctr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 0 && crm == 0 && op2 == 7) reg_name = "dczid_el0";
		else if (op0 == 3 && op1 == 0 && crn == 6 && crm == 0 && op2 == 0) reg_name = "id_aa64isar0_el1";
		else if (op0 == 3 && op1 == 0 && crn == 6 && crm == 0 && op2 == 1) reg_name = "id_aa64isar1_el1";
		else if (op0 == 3 && op1 == 0 && crn == 4 && crm == 0 && op2 == 0) reg_name = "id_aa64pfr0_el1";
		else if (op0 == 3 && op1 == 0 && crn == 7 && crm == 0 && op2 == 0) reg_name = "id_aa64mmfr0_el1";
		else if (op0 == 3 && op1 == 3 && crn == 14 && crm == 0 && op2 == 0) reg_name = "cntfrq_el0";
		else if (op0 == 3 && op1 == 3 && crn == 14 && crm == 0 && op2 == 2) reg_name = "cntvct_el0";
		else if (op0 == 3 && op1 == 0 && crn == 1 && crm == 0 && op2 == 0) reg_name = "sctlr_el1";
		else if (op0 == 3 && op1 == 0 && crn == 2 && crm == 0 && op2 == 0) reg_name = "ttbr0_el1";
		else if (op0 == 3 && op1 == 0 && crn == 2 && crm == 0 && op2 == 1) reg_name = "ttbr1_el1";
		else if (op0 == 3 && op1 == 0 && crn == 2 && crm == 0 && op2 == 2) reg_name = "tcr_el1";
		else if (op0 == 3 && op1 == 0 && crn == 10 && crm == 2 && op2 == 0) reg_name = "mair_el1";
		else if (op0 == 3 && op1 == 0 && crn == 12 && crm == 0 && op2 == 0) reg_name = "vbar_el1";
		else if (op0 == 3 && op1 == 0 && crn == 4 && crm == 1 && op2 == 0) reg_name = "sp_el0";

		snprintf(out_buf, out_sz, "mrs     x%u, %s", rt, reg_name);
		return;
	} else if ((insn & 0xfff00000) == 0xd5100000) {
		/* MSR <system_reg>, Xt */
		uint32_t rt = insn & 0x1f;
		snprintf(out_buf, out_sz, "msr     sreg, x%u", rt);
		return;
	}

	/* 2. ADRP / ADR (PC-Relative Addressing) */
	if ((insn & 0x9f000000) == 0x90000000) {
		/* ADRP Xd, #imm */
		uint32_t rd = insn & 0x1f;
		uint32_t immlo = (insn >> 29) & 0x3;
		uint32_t immhi = (insn >> 5) & 0x7ffff;
		int64_t imm = (int64_t)((immhi << 2) | immlo);
		uint64_t target;
		if (imm & (1 << 20))
			imm |= ~((int64_t)0x1fffff);
		imm <<= 12;
		target = (addr & ~0xfffULL) + imm;
		snprintf(out_buf, out_sz, "adrp    x%u, 0x%"PRIx64, rd, target);
		return;
	} else if ((insn & 0x9f000000) == 0x10000000) {
		/* ADR Xd, #imm */
		uint32_t rd = insn & 0x1f;
		uint32_t immlo = (insn >> 29) & 0x3;
		uint32_t immhi = (insn >> 5) & 0x7ffff;
		int64_t imm = (int64_t)((immhi << 2) | immlo);
		uint64_t target;
		if (imm & (1 << 20))
			imm |= ~((int64_t)0x1fffff);
		target = addr + imm;
		snprintf(out_buf, out_sz, "adr     x%u, 0x%"PRIx64, rd, target);
		return;
	}

	/* 3. ADD / SUB Immediate */
	if ((insn & 0x1f000000) == 0x11000000) {
		uint32_t sf = (insn >> 31) & 0x1;
		uint32_t op = (insn >> 30) & 0x1;
		uint32_t sh = (insn >> 22) & 0x1;
		uint32_t imm12 = (insn >> 10) & 0xfff;
		uint32_t rn = (insn >> 5) & 0x1f;
		uint32_t rd = insn & 0x1f;
		char reg_type = sf ? 'x' : 'w';
		if (sh) imm12 <<= 12;

		if (op == 0 && imm12 == 0 && rn == 31) {
			snprintf(out_buf, out_sz, "mov     %c%u, xzr", reg_type, rd);
		} else {
			snprintf(out_buf, out_sz, "%s     %c%u, %c%u, #0x%x",
			         op ? "sub" : "add", reg_type, rd, reg_type, rn, imm12);
		}
		return;
	}

	/* 4. LDR / STR (Unsigned Immediate Offset) */
	if ((insn & 0x3b000000) == 0x39000000) {
		uint32_t size = (insn >> 30) & 0x3;
		uint32_t opc = (insn >> 22) & 0x3;
		uint32_t imm12 = (insn >> 10) & 0xfff;
		uint32_t rn = (insn >> 5) & 0x1f;
		uint32_t rt = insn & 0x1f;
		uint32_t offset = imm12 << size;
		char reg_prefix = (size == 3) ? 'x' : 'w';
		const char *op_str = (opc == 0) ? "str" : "ldr";

		if (size == 0) op_str = (opc == 0) ? "strb" : "ldrb";
		else if (size == 1) op_str = (opc == 0) ? "strh" : "ldrh";

		if (offset == 0)
			snprintf(out_buf, out_sz, "%s    %c%u, [x%u]", op_str, reg_prefix, rt, rn);
		else
			snprintf(out_buf, out_sz, "%s    %c%u, [x%u, #0x%x]", op_str, reg_prefix, rt, rn, offset);
		return;
	}

	/* 5. Branch Instructions */
	if ((insn & 0x7c000000) == 0x14000000) {
		/* B / BL */
		uint32_t is_bl = (insn >> 31) & 0x1;
		int32_t imm26 = (int32_t)(insn & 0x03ffffff);
		uint64_t target;
		if (imm26 & (1 << 25))
			imm26 |= ~0x03ffffff;
		target = addr + ((int64_t)imm26 << 2);
		snprintf(out_buf, out_sz, "%s      0x%"PRIx64, is_bl ? "bl" : "b", target);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd65f0000) {
		/* RET */
		uint32_t rn = (insn >> 5) & 0x1f;
		if (rn == 30)
			snprintf(out_buf, out_sz, "ret");
		else
			snprintf(out_buf, out_sz, "ret     x%u", rn);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd63f0000) {
		/* BLR Xn */
		uint32_t rn = (insn >> 5) & 0x1f;
		snprintf(out_buf, out_sz, "blr     x%u", rn);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd61f0000) {
		/* BR Xn */
		uint32_t rn = (insn >> 5) & 0x1f;
		snprintf(out_buf, out_sz, "br      x%u", rn);
		return;
	}

	/* 6. System Traps & Barriers */
	if ((insn & 0xffe0001f) == 0xd4000001) {
		uint32_t imm16 = (insn >> 5) & 0xffff;
		snprintf(out_buf, out_sz, "svc     #0x%x", imm16);
		return;
	} else if ((insn & 0xffe0001f) == 0xd4000002) {
		uint32_t imm16 = (insn >> 5) & 0xffff;
		snprintf(out_buf, out_sz, "hvc     #0x%x", imm16);
		return;
	} else if ((insn & 0xffe0001f) == 0xd4000003) {
		uint32_t imm16 = (insn >> 5) & 0xffff;
		snprintf(out_buf, out_sz, "smc     #0x%x", imm16);
		return;
	} else if (insn == 0xd503201f) {
		snprintf(out_buf, out_sz, "nop");
		return;
	} else if (insn == 0xd5033fdf) {
		snprintf(out_buf, out_sz, "isb");
		return;
	} else if ((insn & 0xfffff0ff) == 0xd503309f) {
		snprintf(out_buf, out_sz, "dsb     sy");
		return;
	}

	/* Default fallback */
	snprintf(out_buf, out_sz, ".word   0x%08x", insn);
}

/* ==============================================================================
 * Section 3: Hardware Peripheral & MMIO Discovery Engine
 * ============================================================================== */

struct mmio_entry {
	uint64_t start;
	uint64_t end;
	char name[64];
	char driver[64];
	char compatible[128];
};

/* Resolve driver and device-tree compatible string from sysfs for a given MMIO base */
static void resolve_driver_for_mmio(uint64_t base, char *out_drv, size_t drv_sz, char *out_compat, size_t compat_sz)
{
	DIR *d;
	struct dirent *de;
	char hex_prefix[32];

	out_drv[0] = '\0';
	out_compat[0] = '\0';
	snprintf(hex_prefix, sizeof(hex_prefix), "%llx.", (unsigned long long)base);

	d = opendir("/sys/bus/platform/devices");
	if (!d)
		return;

	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, hex_prefix, strlen(hex_prefix)) == 0) {
			char dev_path[PATH_MAX];
			char drv_link[PATH_MAX];
			char compat_path[PATH_MAX];
			ssize_t len;
			FILE *cf;

			/* 1. Resolve Driver */
			snprintf(drv_link, sizeof(drv_link), "/sys/bus/platform/devices/%s/driver", de->d_name);
			len = readlink(drv_link, dev_path, sizeof(dev_path) - 1);
			if (len > 0) {
				char *slash;
				dev_path[len] = '\0';
				slash = strrchr(dev_path, '/');
				if (slash)
					safe_strncpy(out_drv, slash + 1, drv_sz);
			}

			/* 2. Resolve Compatible String from of_node */
			snprintf(compat_path, sizeof(compat_path), "/sys/bus/platform/devices/%s/of_node/compatible", de->d_name);
			cf = fopen(compat_path, "r");
			if (cf) {
				if (fgets(out_compat, compat_sz, cf)) {
					char *nl = strchr(out_compat, '\n');
					if (nl)
						*nl = '\0';
				}
				fclose(cf);
			}
			break;
		}
	}
	closedir(d);
}

/* Format size in bytes to human-readable string */
static void format_size(uint64_t bytes, char *out, size_t out_sz)
{
	if (bytes >= (1024ULL * 1024 * 1024))
		snprintf(out, out_sz, "%.1f GB", (double)bytes / (1024.0 * 1024 * 1024));
	else if (bytes >= (1024ULL * 1024))
		snprintf(out, out_sz, "%.1f MB", (double)bytes / (1024.0 * 1024));
	else if (bytes >= 1024ULL)
		snprintf(out, out_sz, "%.1f KB", (double)bytes / 1024.0);
	else
		snprintf(out, out_sz, "%llu B", (unsigned long long)bytes);
}

/* Subcommand: mmio */
static int do_mmio(const char *filter)
{
	FILE *f = fopen("/proc/iomem", "r");
	char line[256];
	int count = 0;

	if (!f)
		bb_error_msg_and_die("can't open /proc/iomem");

	puts("\n=== SoC Physical Memory-Mapped I/O (MMIO) Registers ===");
	printf("%-23s  %-9s  %-26s  %-16s  %s\n",
	       "PHYSICAL RANGE", "SIZE", "PERIPHERAL NAME", "DRIVER", "COMPATIBLE / TYPE");
	puts("---------------------------------------------------------------------------------------------------------");

	while (fgets(line, sizeof(line), f)) {
		uint64_t start, end;
		char name[128];
		char drv[64], compat[128], sz_str[16];
		uint64_t sz;

		/* Skip nested indented regions to display top-level controllers */
		if (line[0] == ' ')
			continue;

		if (sscanf(line, "%"SCNx64"-%"SCNx64" : %127[^\n]", &start, &end, name) != 3)
			continue;

		/* Skip system RAM nodes to focus strictly on hardware silicon peripherals */
		if (strstr(name, "System RAM") != NULL)
			continue;

		/* Apply optional keyword filter */
		if (filter && filter[0]) {
			if (strcasestr(name, filter) == NULL &&
			    strcasestr(line, filter) == NULL)
				continue;
		}

		sz = (end >= start) ? (end - start + 1) : 0;
		format_size(sz, sz_str, sizeof(sz_str));

		resolve_driver_for_mmio(start, drv, sizeof(drv), compat, sizeof(compat));

		printf("0x%08llx-0x%08llx  %-9s  %-26s  %-16s  %s\n",
		       (unsigned long long)start, (unsigned long long)end,
		       sz_str, name, drv[0] ? drv : "-", compat[0] ? compat : "-");
		count++;
	}

	fclose(f);
	printf("---------------------------------------------------------------------------------------------------------\n");
	printf("[+] Total Discovered Hardware MMIO Peripherals: %d\n\n", count);
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 4: PLL, Clocks & Devfreq Subsystem Prober
 * ============================================================================== */

static int do_pll(void)
{
	DIR *d;
	struct dirent *de;
	int cpu_policies = 0;
	int devfreq_nodes = 0;

	puts("\n=== SoC Clocks, PLLs & Frequency Scaling Domains ===");

	/* 1. Hardware Crystal Counter Frequency */
#if defined(__aarch64__) || defined(__arm64__)
	{
		bool ok = false;
		uint64_t cntfrq = read_arm64_sysreg(8, &ok);
		if (ok && cntfrq > 0) {
			printf("  Hardware TCXO Base:  %.3f MHz (%llu Hz, CNTFRQ_EL0)\n",
			       (double)cntfrq / 1000000.0, (unsigned long long)cntfrq);
		}
	}
#endif

	/* 2. CPU Cluster Clocks & Frequency Policies */
	puts("\n--- CPU Cluster Clock Scaling Policies ---");
	d = opendir("/sys/devices/system/cpu/cpufreq");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (strncmp(de->d_name, "policy", 6) == 0) {
				char path[PATH_MAX];
				char cpus[64], gov[32];
				long cur_khz = 0, min_khz = 0, max_khz = 0;
				FILE *f;

				/* Related CPUs */
				cpus[0] = '\0';
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpufreq/%s/affected_cpus", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fgets(cpus, sizeof(cpus), f)) {
						char *nl = strchr(cpus, '\n');
						if (nl) *nl = '\0';
					}
					fclose(f);
				}

				/* Current Frequency */
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpufreq/%s/scaling_cur_freq", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fscanf(f, "%ld", &cur_khz) != 1) cur_khz = 0;
					fclose(f);
				}

				/* Min Frequency */
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpufreq/%s/scaling_min_freq", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fscanf(f, "%ld", &min_khz) != 1) min_khz = 0;
					fclose(f);
				}

				/* Max Frequency */
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpufreq/%s/scaling_max_freq", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fscanf(f, "%ld", &max_khz) != 1) max_khz = 0;
					fclose(f);
				}

				/* Governor */
				gov[0] = '\0';
				snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpufreq/%s/scaling_governor", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fgets(gov, sizeof(gov), f)) {
						char *nl = strchr(gov, '\n');
						if (nl) *nl = '\0';
					}
					fclose(f);
				}

				printf("  %-9s (CPUs %-7s): Cur: %6.1f MHz | Range: [%.1f - %.1f MHz] | Gov: %s\n",
				       de->d_name, cpus[0] ? cpus : "-",
				       (double)cur_khz / 1000.0,
				       (double)min_khz / 1000.0,
				       (double)max_khz / 1000.0,
				       gov[0] ? gov : "unknown");
				cpu_policies++;
			}
		}
		closedir(d);
	}

	/* 3. Devfreq Peripherals (GPU, DDR Bandwidth, Storage) */
	puts("\n--- GPU & System Bus Dynamic Frequency Domains (Devfreq) ---");
	d = opendir("/sys/class/devfreq");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] != '.') {
				char path[PATH_MAX];
				char gov[32];
				uint64_t cur_freq = 0;
				FILE *f;

				snprintf(path, sizeof(path), "/sys/class/devfreq/%s/cur_freq", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fscanf(f, "%"SCNu64, &cur_freq) != 1) cur_freq = 0;
					fclose(f);
				}

				gov[0] = '\0';
				snprintf(path, sizeof(path), "/sys/class/devfreq/%s/governor", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fgets(gov, sizeof(gov), f)) {
						char *nl = strchr(gov, '\n');
						if (nl) *nl = '\0';
					}
					fclose(f);
				}

				if (cur_freq >= 1000000ULL) {
					printf("  %-32s Cur: %6.1f MHz  Gov: %s\n",
					       de->d_name, (double)cur_freq / 1000000.0, gov[0] ? gov : "-");
				} else if (cur_freq > 0) {
					printf("  %-32s Cur: %6llu Hz   Gov: %s\n",
					       de->d_name, (unsigned long long)cur_freq, gov[0] ? gov : "-");
				} else {
					printf("  %-32s Status: Active       Gov: %s\n",
					       de->d_name, gov[0] ? gov : "-");
				}
				devfreq_nodes++;
			}
		}
		closedir(d);
	}

	printf("[+] Discovered %d CPU frequency scaling policies and %d devfreq domains.\n\n",
	       cpu_policies, devfreq_nodes);
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 5: SPMI Arbiter & PMIC Prober
 * ============================================================================== */

static int do_pmic(void)
{
	DIR *d;
	struct dirent *de;
	int spmi_count = 0;
	int reg_count = 0;

	puts("\n=== Qualcomm SPMI Bus & PMIC Hardware Probing ===");

	/* 1. SPMI Controllers & Slaves */
	puts("--- SPMI Arbiter Bus Slaves ---");
	d = opendir("/sys/bus/spmi/devices");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] != '.') {
				char path[PATH_MAX];
				char modalias[64];
				FILE *f;

				modalias[0] = '\0';
				snprintf(path, sizeof(path), "/sys/bus/spmi/devices/%s/modalias", de->d_name);
				f = fopen(path, "r");
				if (f) {
					if (fgets(modalias, sizeof(modalias), f)) {
						char *nl = strchr(modalias, '\n');
						if (nl) *nl = '\0';
					}
					fclose(f);
				}

				printf("  SPMI Slave: %-12s [Type: %s]\n", de->d_name, modalias[0] ? modalias : "Qualcomm PMIC");
				spmi_count++;
			}
		}
		closedir(d);
	}
	if (!spmi_count)
		puts("  [!] Direct SPMI bus node not exposed in sysfs (handled via driver registers)");

	/* 2. PMIC Battery & Charger Power Supply Telemetry */
	puts("\n--- PMIC Fuel Gauge, Charger & Battery Registers ---");
	d = opendir("/sys/class/power_supply");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] != '.') {
				char path[PATH_MAX];
				char type[32], status[32], health[32], tech[32];
				long v_now = 0, i_now = 0, cap = 0, temp = 0;
				FILE *f;

				type[0] = status[0] = health[0] = tech[0] = '\0';

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/type", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fgets(type, sizeof(type), f)) { char *nl = strchr(type, '\n'); if (nl) *nl = '\0'; } fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/status", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fgets(status, sizeof(status), f)) { char *nl = strchr(status, '\n'); if (nl) *nl = '\0'; } fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/health", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fgets(health, sizeof(health), f)) { char *nl = strchr(health, '\n'); if (nl) *nl = '\0'; } fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/technology", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fgets(tech, sizeof(tech), f)) { char *nl = strchr(tech, '\n'); if (nl) *nl = '\0'; } fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/voltage_now", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fscanf(f, "%ld", &v_now) != 1) v_now = 0; fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/current_now", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fscanf(f, "%ld", &i_now) != 1) i_now = 0; fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/capacity", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fscanf(f, "%ld", &cap) != 1) cap = 0; fclose(f); }

				snprintf(path, sizeof(path), "/sys/class/power_supply/%s/temp", de->d_name);
				f = fopen(path, "r");
				if (f) { if (fscanf(f, "%ld", &temp) != 1) temp = 0; fclose(f); }

				printf("  Supply [%s]: Type: %s | Status: %s%s\n",
				       de->d_name, type[0] ? type : "-", status[0] ? status : "-",
				       health[0] ? " | Health: " : "");
				if (health[0]) printf("%s", health);
				if (v_now > 0)
					printf("    Voltage: %.3f V (%ld uV)", (double)v_now / 1000000.0, v_now);
				if (i_now != 0)
					printf(" | Current: %.1f mA (%ld uA)", (double)i_now / 1000.0, i_now);
				if (cap > 0)
					printf(" | Capacity: %ld%%", cap);
				if (temp > 0)
					printf(" | Temp: %.1f C", (double)temp / 10.0);
				putchar('\n');
			}
		}
		closedir(d);
	}

	/* 3. PMIC Voltage Regulators (LDOs & SMPS) */
	d = opendir("/sys/class/regulator");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			if (strncmp(de->d_name, "regulator.", 10) == 0)
				reg_count++;
		}
		closedir(d);
	}
	printf("\n  Total Registered PMIC Power Rails (LDO/SMPS): %d active regulators\n\n", reg_count);

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 6: Architectural CPU Machine-Code Registers
 * ============================================================================== */

static int do_cpu(void)
{
	puts("\n=== Pure Architectural ARM64 Silicon Register Audit ===");

#if defined(__aarch64__) || defined(__arm64__)
	{
		bool ok;
		uint64_t midr = read_arm64_sysreg(0, &ok);
		if (ok) {
			uint8_t impl = (uint8_t)((midr >> 24) & 0xff);
			uint8_t var  = (uint8_t)((midr >> 20) & 0xf);
			uint8_t arch = (uint8_t)((midr >> 16) & 0xf);
			uint16_t part = (uint16_t)((midr >> 4) & 0xfff);
			uint8_t rev  = (uint8_t)(midr & 0xf);

			printf("  MIDR_EL1:       0x%016llx\n", (unsigned long long)midr);
			printf("    Implementer:  0x%02x (%s)\n", impl, get_arm_implementer_name(impl));
			printf("    Architecture: ARMv8-A (code 0x%x)\n", arch);
			printf("    Part Number:  0x%03x (%s)\n", part, get_arm_part_name(impl, part));
			printf("    Variant:      r%up%u (Variant %u, Revision %u)\n", var, rev, var, rev);
		} else {
			printf("  MIDR_EL1:       [Trapped by Hypervisor / OS]\n");
		}

		{
			uint64_t mpidr = read_arm64_sysreg(1, &ok);
			if (ok) {
				uint32_t aff0 = mpidr & 0xff;
				uint32_t aff1 = (mpidr >> 8) & 0xff;
				uint32_t aff2 = (mpidr >> 16) & 0xff;
				printf("  MPIDR_EL1:      0x%016llx (Cluster %u, Core %u, Aff2 %u)\n",
				       (unsigned long long)mpidr, aff1, aff0, aff2);
			}
		}

		{
			uint64_t ctr = read_arm64_sysreg(2, &ok);
			if (ok) {
				uint32_t dmin_words = 1 << ((ctr >> 16) & 0xf);
				uint32_t imin_words = 1 << (ctr & 0xf);
				printf("  CTR_EL0:        0x%016llx\n", (unsigned long long)ctr);
				printf("    D-Cache Line: %u bytes (%u words)\n", dmin_words * 4, dmin_words);
				printf("    I-Cache Line: %u bytes (%u words)\n", imin_words * 4, imin_words);
			}
		}

		{
			uint64_t dczid = read_arm64_sysreg(3, &ok);
			if (ok) {
				bool dzp = (dczid >> 4) & 1;
				uint32_t block_bytes = 4 << (dczid & 0xf);
				printf("  DCZID_EL0:      0x%016llx (dc zva: %s, Block: %u bytes)\n",
				       (unsigned long long)dczid, dzp ? "Prohibited" : "Permitted", block_bytes);
			}
		}

		{
			uint64_t isar0 = read_arm64_sysreg(4, &ok);
			if (ok) {
				printf("  ID_AA64ISAR0:   0x%016llx [AES:%u SHA1:%u SHA2:%u CRC32:%u ATOMIC:%u]\n",
				       (unsigned long long)isar0,
				       (unsigned)((isar0 >> 4) & 0xf),
				       (unsigned)((isar0 >> 8) & 0xf),
				       (unsigned)((isar0 >> 12) & 0xf),
				       (unsigned)((isar0 >> 16) & 0xf),
				       (unsigned)((isar0 >> 20) & 0xf));
			}
		}

		{
			uint64_t pfr0 = read_arm64_sysreg(6, &ok);
			if (ok) {
				printf("  ID_AA64PFR0:    0x%016llx [AdvSIMD:%u FP:%u GIC:%u CSV2:%u]\n",
				       (unsigned long long)pfr0,
				       (unsigned)((pfr0 >> 20) & 0xf),
				       (unsigned)((pfr0 >> 16) & 0xf),
				       (unsigned)((pfr0 >> 24) & 0xf),
				       (unsigned)((pfr0 >> 56) & 0xf));
			}
		}

		{
			uint64_t mmfr0 = read_arm64_sysreg(7, &ok);
			if (ok) {
				static const unsigned pa_bits[] = { 32, 36, 40, 42, 44, 48, 52, 0 };
				unsigned pa_idx = mmfr0 & 0xf;
				unsigned pa = (pa_idx < 7) ? pa_bits[pa_idx] : 0;
				printf("  ID_AA64MMFR0:   0x%016llx [PA Range: %u-bit Physical Addressing]\n",
				       (unsigned long long)mmfr0, pa);
			}
		}

		{
			uint64_t cntfrq = read_arm64_sysreg(8, &ok);
			uint64_t cntvct = read_arm64_sysreg(9, &ok);
			if (ok && cntfrq > 0) {
				printf("  System Counter: %.3f MHz (%llu Hz) | Live VCT: %llu cycles\n",
				       (double)cntfrq / 1000000.0,
				       (unsigned long long)cntfrq,
				       (unsigned long long)cntvct);
			}
		}
	}
#else
	puts("  [!] Host platform is not ARM64. Architectural CPU registers require AArch64 target.");
#endif

	putchar('\n');
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 7: Machine Code Disassembler Subcommand
 * ============================================================================== */

static int do_disasm(int argc, char **argv)
{
	int i;
	uint64_t fake_pc = 0x1000;

	if (argc < 3) {
		puts("Usage: socprobe disasm <HEX_INSN_1> [HEX_INSN_2...]");
		puts("Example: socprobe disasm d5380000 90000800 91000000 b9400000 d4000001");
		return EXIT_FAILURE;
	}

	puts("\n=== Pure AArch64 Machine-Code Disassembly ===");
	printf("%-16s  %-10s  %s\n", "ADDRESS", "OPCODE", "DISASSEMBLY");
	puts("-------------------------------------------------------");

	for (i = 2; i < argc; i++) {
		const char *hex_str = argv[i];
		uint32_t insn;
		char dis_buf[128];

		if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
			hex_str += 2;

		insn = (uint32_t)strtoul(hex_str, NULL, 16);
		disassemble_aarch64_insn(insn, fake_pc, dis_buf, sizeof(dis_buf));

		printf("0x%012llx    %08x    %s\n", (unsigned long long)fake_pc, insn, dis_buf);
		fake_pc += 4;
	}

	puts("-------------------------------------------------------\n");
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 8: Status & Main Dispatcher
 * ============================================================================== */

static int do_status(void)
{
	puts("\n==================================================================");
	puts("       Mobile SoC Silicon Hardware, MMIO & Clock Engine");
	puts("==================================================================");

	/* 1. SoC Identity from Device Tree */
	{
		FILE *f = fopen("/proc/device-tree/model", "r");
		char model[128];
		model[0] = '\0';
		if (f) {
			if (fgets(model, sizeof(model), f)) {
				char *nl = strchr(model, '\n');
				if (nl) *nl = '\0';
			}
			fclose(f);
		}
		if (model[0])
			printf("  Hardware Model:   %s\n", model);
	}

	{
		FILE *f = fopen("/proc/device-tree/compatible", "r");
		char compat[128];
		compat[0] = '\0';
		if (f) {
			if (fgets(compat, sizeof(compat), f)) {
				char *nl = strchr(compat, '\n');
				if (nl) *nl = '\0';
			}
			fclose(f);
		}
		if (compat[0])
			printf("  SoC Family:       %s\n", compat);
	}

	/* 2. CPU Silicon Architecture */
#if defined(__aarch64__) || defined(__arm64__)
	{
		bool ok;
		uint64_t midr = read_arm64_sysreg(0, &ok);
		if (ok) {
			uint8_t impl = (uint8_t)((midr >> 24) & 0xff);
			uint16_t part = (uint16_t)((midr >> 4) & 0xfff);
			uint8_t var  = (uint8_t)((midr >> 20) & 0xf);
			uint8_t rev  = (uint8_t)(midr & 0xf);
			printf("  Silicon Core:     %s (%s r%up%u)\n",
			       get_arm_part_name(impl, part), get_arm_implementer_name(impl), var, rev);
		}
	}
#endif

	/* 3. MMIO Count */
	{
		FILE *f = fopen("/proc/iomem", "r");
		int count = 0;
		if (f) {
			char line[256];
			while (fgets(line, sizeof(line), f)) {
				if (line[0] != ' ' && strstr(line, "System RAM") == NULL)
					count++;
			}
			fclose(f);
			printf("  MMIO Registers:   %d mapped hardware peripheral windows in /proc/iomem\n", count);
		}
	}

	/* 4. PMIC Summary */
	{
		DIR *d = opendir("/sys/bus/spmi/devices");
		int spmi_count = 0;
		if (d) {
			struct dirent *de;
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] != '.')
					spmi_count++;
			}
			closedir(d);
			printf("  SPMI Arbiter:     %d PMIC hardware slaves active\n", spmi_count);
		}
	}

	puts("\nAvailable Diagnostic Subcommands:");
	puts("  socprobe mmio      List all physical MMIO register maps, drivers, and sizes");
	puts("  socprobe pll       Probe clock controllers, CPU cluster OPPs, and devfreq");
	puts("  socprobe pmic      Probe SPMI PMIC slaves, power rails, and battery registers");
	puts("  socprobe cpu       Audit architectural ARM64 CPU registers via inline assembly");
	puts("  socprobe disasm    Disassemble raw 32-bit AArch64 machine instructions\n");

	return EXIT_SUCCESS;
}

int socprobe_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int socprobe_main(int argc, char **argv)
{
	const char *cmd;

	if (argc < 2)
		return do_status();

	cmd = argv[1];

	if (strcmp(cmd, "status") == 0 || strcmp(cmd, "info") == 0)
		return do_status();
	if (strcmp(cmd, "mmio") == 0)
		return do_mmio(argc > 2 ? argv[2] : NULL);
	if (strcmp(cmd, "pll") == 0 || strcmp(cmd, "clocks") == 0)
		return do_pll();
	if (strcmp(cmd, "pmic") == 0)
		return do_pmic();
	if (strcmp(cmd, "cpu") == 0)
		return do_cpu();
	if (strcmp(cmd, "disasm") == 0)
		return do_disasm(argc, argv);

	bb_show_usage();
	return EXIT_FAILURE;
}
