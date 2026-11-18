/* vi: set sw=4 ts=4: */
/*
 * socprobe - Pure In-Memory Mobile SoC Silicon Hardware & Machine-Code Engine
 *
 * Dedicated zero-dependency silicon hardware diagnostic suite for mobile SoCs.
 * Operates with ZERO filesystem dependencies (zero /proc, zero /sys, zero /dev,
 * zero disk access). Probes architectural CPU registers via pure AArch64 inline
 * assembly, measures live CPU clock frequencies via hardware cycle-counter loops,
 * models Qualcomm SPMI PMIC voltage/current/power registers, provides in-memory
 * physical MMIO memory maps, and features an integrated AArch64 machine-code
 * instruction disassembler.
 *
 * Comprehensive Hardware Subsystems Covered (100% In-RAM Operation):
 *   - PSCI & Qualcomm TrustZone / QSEE SMC Call Calling Conventions & Function IDs
 *   - Spectra ISP Camera Hardware, CSID/CSIPHY & 3D/Gamma/LSC Look-Up Tables (LUTs)
 *   - Hexagon QDSP6 (aDSP, cDSP HVX/HMX Tensor AI, mDSP) & IPA Network Offloader
 *   - Audio Routing DSP (ARDP), LPASS, Soundwire & SLIMbus Digital Audio
 *   - PMIC VADC / ADC5 Analog-to-Digital Converter Channel Architectures
 *   - Network-on-Chip (NoC: SNOC, CNOC, MMNOC) Interconnects, QoS & BWMON Monitors
 *   - Global Clock Controller (GCC) & RPM Clock Branches, RCGR & CBCR Registers
 *   - Silicon Ring Oscillators (ROSC), Core Power Reduction (CPR) & TSENS Sensors
 *   - Qualcomm Crypto Engine (CE v5), BAM DMA, HWKM & Inline Crypto Engine (ICE)
 *   - AI Accelerators: Hexagon Tensor Processor (HTP / HMX) & Adreno ML Units
 *   - ARMv8 Architectural Performance Monitor Unit (PMU) Hardware Counters
 *   - System Management Interface (SMI), SPMI Arbiter & APCS IPC Mailboxes
 *   - Pure AArch64 Machine-Code Disassembler with PSCI/TrustZone SMC & PMU Decoding
 *
 * Designed specifically for hardened/jailed environments, recovery, and early-boot
 * where debugfs is omitted, /dev/mem is blocked, and procfs/sysfs are unmounted.
 *
 * Licensed under GPLv2 or later.
 */

//config:config SOCPROBE
//config:	bool "socprobe (pure silicon hardware, MMIO, PLL, PMIC & CPU probe)"
//config:	default y
//config:	help
//config:	  Pure in-memory mobile SoC silicon hardware, MMIO, PLL, PMIC, and
//config:	  machine code probing suite. Operates with zero filesystem
//config:	  endpoints (no /proc, no /sys, no /dev) using inline assembly CPU
//config:	  register audits, cycle-timing loops, and AArch64 disassembly.

//applet:IF_SOCPROBE(APPLET_NOEXEC(socprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, socprobe))
//applet:IF_SOCPROBE(APPLET_NOEXEC(socreg, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, socreg))
//applet:IF_SOCPROBE(APPLET_NOEXEC(regprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, regprobe))
//applet:IF_SOCPROBE(APPLET_NOEXEC(pllprobe, socprobe, BB_DIR_USR_BIN, BB_SUID_DROP, pllprobe))

//kbuild:lib-$(CONFIG_SOCPROBE) += socprobe.o

//usage:#define socprobe_trivial_usage
//usage:       "COMMAND [ARGS...]"
//usage:#define socprobe_full_usage "\n\n"
//usage:       "Pure in-memory mobile SoC silicon hardware, MMIO, PLL, and CPU probe\n"
//usage:     "\nCommands:"
//usage:     "\n	status, info         SoC silicon telemetry overview (zero filesystem)"
//usage:     "\n	cpu                  Architectural CPU system registers via inline assembly"
//usage:     "\n	pll                  Hardware TCXO and live CPU core clock assembly timing"
//usage:     "\n	clock, clk           GCC/RPM clock tree, RCGR dividers & CBCR branch registers"
//usage:     "\n	pmic                 Qualcomm SPMI PMIC register map (LDO, Buck, PON, FG)"
//usage:     "\n	volt, power          PMIC voltage DAC steps, current, and power formulas"
//usage:     "\n	psci, tz             PSCI & TrustZone/QSEE SMC call registers & function IDs"
//usage:     "\n	isp, camera          Spectra ISP hardware, CSID/CSIPHY, and LUT registers"
//usage:     "\n	dsp                  Hexagon DSPs (aDSP, cDSP HVX/HMX), IPA network offloader"
//usage:     "\n	ardp                 Audio Routing DSP (ARDP), Soundwire & SLIMbus registers"
//usage:     "\n	adc, a2d             PMIC VADC/ADC5 analog-to-digital converter channels"
//usage:     "\n	noc, traffic         System NoC interconnects, QoS arbiters & BWMON monitors"
//usage:     "\n	smi                  System Management Interface, SPMI & IPC mailbox registers"
//usage:     "\n	rosc, ring, cpr      Silicon Ring Oscillators, Aging & CPR/TSENS sensors"
//usage:     "\n	crypto, ce           Qualcomm Crypto Engine v5, HWKM & ICE registers"
//usage:     "\n	ai, npu, htp         Hexagon Tensor Processor, HMX matrix & AI accelerators"
//usage:     "\n	pmu, perf            ARMv8 PMU hardware performance counter registers"
//usage:     "\n	mmio [FILTER]        In-memory physical MMIO peripheral register memory map"
//usage:     "\n	disasm <HEX...>      Disassemble 32-bit AArch64 machine instructions"
//usage:
//usage:#define socreg_trivial_usage socprobe_trivial_usage
//usage:#define socreg_full_usage socprobe_full_usage
//usage:#define regprobe_trivial_usage socprobe_trivial_usage
//usage:#define regprobe_full_usage socprobe_full_usage
//usage:#define pllprobe_trivial_usage socprobe_trivial_usage
//usage:#define pllprobe_full_usage socprobe_full_usage

#include "libbb.h"
#include <setjmp.h>
#include <signal.h>
#include <ctype.h>

/* ==============================================================================
 * Section 1: Pure Inline Assembly Architectural Registers & Cycle Calibration
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
		case 0:  asm volatile("mrs %0, midr_el1" : "=r"(val)); break;
		case 1:  asm volatile("mrs %0, mpidr_el1" : "=r"(val)); break;
		case 2:  asm volatile("mrs %0, revidr_el1" : "=r"(val)); break;
		case 3:  asm volatile("mrs %0, ctr_el0" : "=r"(val)); break;
		case 4:  asm volatile("mrs %0, dczid_el0" : "=r"(val)); break;
		case 5:  asm volatile("mrs %0, id_aa64isar0_el1" : "=r"(val)); break;
		case 6:  asm volatile("mrs %0, id_aa64isar1_el1" : "=r"(val)); break;
		case 7:  asm volatile("mrs %0, id_aa64pfr0_el1" : "=r"(val)); break;
		case 8:  asm volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(val)); break;
		case 9:  asm volatile("mrs %0, cntfrq_el0" : "=r"(val)); break;
		case 10: asm volatile("mrs %0, cntvct_el0" : "=r"(val)); break;
		case 11: asm volatile("mrs %0, CurrentEL" : "=r"(val)); break;
		case 12: asm volatile("mrs %0, daif" : "=r"(val)); break;
		case 13: asm volatile("mrs %0, nzcv" : "=r"(val)); break;
		case 14: asm volatile("mrs %0, fpcr" : "=r"(val)); break;
		case 15: asm volatile("mrs %0, fpsr" : "=r"(val)); break;
		/* ARMv8 PMU Performance Counter Registers */
		case 16: asm volatile("mrs %0, pmcr_el0" : "=r"(val)); break;
		case 17: asm volatile("mrs %0, pmccntr_el0" : "=r"(val)); break;
		case 18: asm volatile("mrs %0, pmuserenr_el0" : "=r"(val)); break;
		case 19: asm volatile("mrs %0, pmcntenset_el0" : "=r"(val)); break;
		case 20: asm volatile("mrs %0, pmccfiltr_el0" : "=r"(val)); break;
		case 21: asm volatile("mrs %0, pmovsset_el0" : "=r"(val)); break;
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

/* Measure live CPU core clock frequency via pure assembly timing calibration loop */
static double measure_cpu_clock_mhz(void)
{
	uint64_t cntfrq;
	uint64_t t_start, t_end;
	uint64_t target_ticks;
	volatile uint64_t count = 0;
	bool ok = false;

	cntfrq = read_arm64_sysreg(9, &ok);
	if (!ok || cntfrq == 0)
		return 0.0;

	/* Run loop for 50 milliseconds of hardware crystal time */
	target_ticks = cntfrq / 20;

	asm volatile(
		"mrs %0, cntvct_el0\n"
		"1:\n"
		"add %2, %2, #1\n"
		"add %2, %2, #1\n"
		"add %2, %2, #1\n"
		"add %2, %2, #1\n"
		"mrs %1, cntvct_el0\n"
		"sub %1, %1, %0\n"
		"cmp %1, %3\n"
		"blt 1b\n"
		"mrs %1, cntvct_el0\n"
		: "=&r"(t_start), "=&r"(t_end), "+r"(count)
		: "r"(target_ticks)
		: "cc"
	);

	if (t_end > t_start) {
		double elapsed_sec = (double)(t_end - t_start) / (double)cntfrq;
		double total_instructions = (double)count * 2.0;
		if (elapsed_sec > 0.0)
			return (total_instructions / elapsed_sec) / 1000000.0;
	}

	return 0.0;
}

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

static const char *lookup_psci_tz_name(uint32_t fid)
{
	switch (fid) {
	/* Standard ARM PSCI Function IDs */
	case 0x84000000: return "PSCI_VERSION";
	case 0x84000001: case 0xc4000001: return "PSCI_CPU_SUSPEND";
	case 0x84000002: return "PSCI_CPU_OFF";
	case 0x84000003: case 0xc4000003: return "PSCI_CPU_ON";
	case 0x84000004: case 0xc4000004: return "PSCI_AFFINITY_INFO";
	case 0x84000005: case 0xc4000005: return "PSCI_MIGRATE";
	case 0x84000006: return "PSCI_MIGRATE_INFO_TYPE";
	case 0x84000008: return "PSCI_SYSTEM_OFF";
	case 0x84000009: return "PSCI_SYSTEM_RESET";
	case 0x8400000a: return "PSCI_FEATURES";
	case 0x8400000b: return "PSCI_CPU_FREEZE";
	case 0x8400000c: return "PSCI_CPU_DEFAULT_SUSPEND";
	case 0x84000012: case 0xc4000012: return "PSCI_SYSTEM_RESET2";
	case 0x84000013: return "PSCI_MEM_PROTECT";
	/* Qualcomm QSEE / SCM SIP Service IDs */
	case 0x02000101: return "TZ_SCM_CMD_SIP (QSEE App Dispatch)";
	case 0x02000200: return "TZ_QFPROM_READ_FUSE";
	case 0x02000300: return "TZ_QFPROM_WRITE_FUSE";
	case 0x02000400: return "TZ_PIL_PAS_AUTH_AND_RESET (Subsystem Loader)";
	case 0x02000800: return "TZ_MEM_PROTECT_XPU (Peripheral Isolation)";
	case 0x02000900: return "TZ_SMMU_SECURE_CFG (Stage-2 Context Bank)";
	default:         return NULL;
	}
}

static void disassemble_aarch64_insn(uint32_t insn, uint64_t addr, char *out_buf, size_t out_sz)
{
	/* 1. MRS / MSR (System Register Move) */
	if ((insn & 0xfff00000) == 0xd5300000) {
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
		/* PMU Performance Monitor Registers */
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 12 && op2 == 0) reg_name = "pmcr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 12 && op2 == 1) reg_name = "pmcntenset_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 12 && op2 == 2) reg_name = "pmcntenclr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 12 && op2 == 3) reg_name = "pmovsset_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 12 && op2 == 5) reg_name = "pmselr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 13 && op2 == 0) reg_name = "pmccntr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 14 && op2 == 0) reg_name = "pmuserenr_el0";
		else if (op0 == 3 && op1 == 3 && crn == 9 && crm == 14 && op2 == 1) reg_name = "pmccfiltr_el0";

		snprintf(out_buf, out_sz, "mrs     x%u, %s", rt, reg_name);
		return;
	} else if ((insn & 0xfff00000) == 0xd5100000) {
		uint32_t rt = insn & 0x1f;
		snprintf(out_buf, out_sz, "msr     sreg, x%u", rt);
		return;
	}

	/* 2. ADRP / ADR (PC-Relative Addressing) */
	if ((insn & 0x9f000000) == 0x90000000) {
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
		uint32_t is_bl = (insn >> 31) & 0x1;
		int32_t imm26 = (int32_t)(insn & 0x03ffffff);
		uint64_t target;
		if (imm26 & (1 << 25))
			imm26 |= ~0x03ffffff;
		target = addr + ((int64_t)imm26 << 2);
		snprintf(out_buf, out_sz, "%s      0x%"PRIx64, is_bl ? "bl" : "b", target);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd65f0000) {
		uint32_t rn = (insn >> 5) & 0x1f;
		if (rn == 30)
			snprintf(out_buf, out_sz, "ret");
		else
			snprintf(out_buf, out_sz, "ret     x%u", rn);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd63f0000) {
		uint32_t rn = (insn >> 5) & 0x1f;
		snprintf(out_buf, out_sz, "blr     x%u", rn);
		return;
	} else if ((insn & 0xfffffc1f) == 0xd61f0000) {
		uint32_t rn = (insn >> 5) & 0x1f;
		snprintf(out_buf, out_sz, "br      x%u", rn);
		return;
	}

	/* 6. System Traps & TrustZone/PSCI Power Management Calls */
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
		snprintf(out_buf, out_sz, "smc     #0x%x (PSCI / TrustZone Call)", imm16);
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

	snprintf(out_buf, out_sz, ".word   0x%08x", insn);
}

/* ==============================================================================
 * Section 3: Pure Silicon MMIO Peripheral Memory Map (In-Memory Table)
 * ============================================================================== */

struct silicon_mmio {
	uint64_t start;
	uint64_t end;
	const char *name;
	const char *category;
	const char *description;
};

static const struct silicon_mmio g_silicon_mmio[] = {
	{ 0x003ED000, 0x003FB007, "cx_ipeak",   "POWER",   "Dynamic Core Voltage & Peak Current Arbitrator" },
	{ 0x00400000, 0x00FFFFFF, "tlmm",       "GPIO",    "Top-Level Mode Multiplexer / Pin Control (113 GPIOs)" },
	{ 0x00406000, 0x00407FFF, "ipcc",       "IPC",     "Inter-Processor Communication Controller Mailbox" },
	{ 0x00700000, 0x00703FFF, "crypto_ce5", "SECURITY","Qualcomm Crypto Engine v5 Hardware Core" },
	{ 0x00704000, 0x00707FFF, "crypto_bam", "SECURITY","BAM Crypto DMA Bus Access Manager Controller" },
	{ 0x00730000, 0x00731FFF, "hwkm",       "SECURITY","Hardware Key Manager / OTP Key Derivation Engine" },
	{ 0x01400000, 0x015EFFFF, "gcc",        "CLOCK",   "Global Clock Controller / Core PLLs / RCG dividers" },
	{ 0x01500000, 0x0151FFFF, "cnoc",       "NOC",     "Config NoC Low-Speed Peripheral Interconnect" },
	{ 0x01600000, 0x01600083, "refgen",     "POWER",   "Voltage Reference Generator / Silicon Bandgap" },
	{ 0x01610000, 0x01611FFF, "eud",        "DEBUG",   "Embedded USB Debugger Controller" },
	{ 0x01613000, 0x0161310F, "hsusb_phy",  "USB",     "High-Speed USB 2.0 PHY Analog Interface" },
	{ 0x01620000, 0x01621FFF, "cpu_bwmon",  "NOC",     "CPU Core Interconnect Bandwidth Monitor" },
	{ 0x01626000, 0x0163FFFF, "snoc",       "NOC",     "System NoC High-Speed Interconnect Fabric" },
	{ 0x0163C000, 0x0163DFFF, "smp2p",      "IPC",     "Shared Memory Point-to-Point Cross-Core Register" },
	{ 0x01668000, 0x01669FFF, "sys_cpr",    "POWER",   "System Core Power Reduction & Ring Oscillator" },
	{ 0x01678000, 0x01679FFF, "tsens_rosc", "THERMAL", "TSENS Ring Oscillator Temperature Monitor" },
	{ 0x01B40000, 0x01B46FFF, "qfprom",     "SECURITY","Qualcomm Fuse PROM / Silicon Security Key Bank" },
	{ 0x01C0A000, 0x01C2FFFF, "spmi_cnfg",  "SPMI",    "SPMI Arbiter Configuration Window" },
	{ 0x01C40000, 0x01C410FF, "spmi_core",  "SPMI",    "SPMI Arbiter Core Control & Channel Mapping" },
	{ 0x01D88000, 0x01D89FFF, "ufs_ice",    "STORAGE", "UFS Inline Crypto Engine (Hardware Sector Crypt)" },
	{ 0x01E00000, 0x03DFFFFF, "spmi_chnls", "SPMI",    "SPMI PMIC Channels (32 MB Per-Peripheral Window)" },
	{ 0x01E40000, 0x01EBFFFF, "ipa",        "NETWORK", "IP Accelerator (Network Packet Offload & Router)" },
	{ 0x03E00000, 0x03EFFFFF, "spmi_obsrvr","SPMI",    "SPMI PMIC Observer Window (1 MB Read-Only Window)" },
	{ 0x03F00000, 0x03F9FFFF, "spmi_intr",  "SPMI",    "SPMI Interrupt Arbitration Manager" },
	{ 0x04080000, 0x040FFFFF, "mdsp",       "DSP",     "Hexagon Modem Baseband Subsystem (mDSP)" },
	{ 0x0440B000, 0x0440B003, "pshold",     "POWER",   "Power Hold & Hard Silicon Reset Trigger" },
	{ 0x04410000, 0x04410007, "tsens_srot", "THERMAL", "Thermal Sensor Secure Read-Only Table" },
	{ 0x04411000, 0x044111FE, "tsens_tm",   "THERMAL", "Thermal Sensor Temperature Monitor (11 on-die ADCs)" },
	{ 0x044A0000, 0x044BFFFF, "bimc",       "NOC",     "Bus Interface & LPDDR4x Memory Controller Arbiter" },
	{ 0x04784000, 0x04784FFF, "sdhc",       "STORAGE", "SD / eMMC Storage Controller (SDCC)" },
	{ 0x04804000, 0x04806FFF, "ufshc",      "STORAGE", "Universal Flash Storage Host Controller" },
	{ 0x04807000, 0x04807DFF, "ufs_phy",    "STORAGE", "UFS M-PHY Interface" },
	{ 0x04A00000, 0x04A03FFF, "qup_0",      "BUS",     "Qualcomm Universal Peripheral v3 Core 0 (I2C/SPI)" },
	{ 0x04A80000, 0x04A83FFF, "qup_1",      "BUS",     "Qualcomm Universal Peripheral v3 Core 1 (UART)" },
	{ 0x04C00000, 0x04CFFFFF, "usb3",       "USB",     "Synopsys DesignWare SuperSpeed USB 3.0 Controller" },
	{ 0x05040000, 0x0505FFFF, "mmnoc",      "NOC",     "Multimedia NoC High-Bandwidth Display/Camera Interconnect" },
	{ 0x05900000, 0x0597FFFF, "gpu_core",   "GPU",     "Adreno GPU Graphics Core / Shaders / Texture Pipes" },
	{ 0x05990000, 0x05991FFF, "gpu_bwmon",  "NOC",     "Adreno GPU Memory Bus Traffic Bandwidth Monitor" },
	{ 0x05D00000, 0x05DFFFFF, "mdss",       "DISPLAY", "Mobile Display Subsystem / DPU Display Processing Unit" },
	{ 0x05E94000, 0x05E942FF, "dsi_phy",    "DISPLAY", "MIPI DSI 4-Lane High-Speed Display PHY" },
	{ 0x06280000, 0x06283FFF, "soundwire",  "AUDIO",   "Soundwire Master Digital Audio Bus Controller" },
	{ 0x062D0000, 0x062DFFFF, "adsp",       "DSP",     "Hexagon Audio DSP (LPASS / ARDP Routing Core)" },
	{ 0x062DC000, 0x062DFFFF, "slimbus",    "AUDIO",   "SLIMbus Audio Serial Interconnect Controller" },
	{ 0x08300000, 0x0837FFFF, "cdsp",       "DSP",     "Hexagon Compute DSP (cDSP HVX 1024-bit SIMD)" },
	{ 0x08380000, 0x0839FFFF, "htp_npu",    "AI",      "Hexagon Tensor Processor / Matrix AI Acceleration Unit" },
	{ 0x090B0000, 0x090B1FFF, "apcs_clk",   "CLOCK",   "APCS CPU Core Clock Distribution & PLL Generator" },
	{ 0x090B5000, 0x090B5FFF, "apcs_ipc",   "IPC",     "APCS Inter-Processor Hardware Mailbox Doorbells" },
	{ 0x090D8000, 0x090D9FFF, "apcs_cpr",   "POWER",   "APCS CPU Core Power Reduction & Ring Oscillators" },
	{ 0x0AC00000, 0x0AC1FFFF, "ife_0",      "CAMERA",  "Spectra Image Front End 0 (Primary Dual ISP)" },
	{ 0x0AC10000, 0x0AC17FFF, "icp",        "CAMERA",  "Image Control Processor (Camera Subsystem MCU)" },
	{ 0x0AC20000, 0x0AC27FFF, "bps",        "CAMERA",  "Bayer Processing Segment (Raw Sensor Demosaic Engine)" },
	{ 0x0AC30000, 0x0AC37FFF, "csid_0",     "CAMERA",  "Camera Serial Interface Decoder Core 0" },
	{ 0x0AC40000, 0x0AC47FFF, "ipe",        "CAMERA",  "Image Processing Engine (3D-LUT Color / Post-Filter)" },
	{ 0x0AC65000, 0x0AC65FFF, "csiphy_0",   "CAMERA",  "MIPI CSI-2 4-Lane Camera PHY 0" },
	{ 0x0AC66000, 0x0AC66FFF, "csiphy_1",   "CAMERA",  "MIPI CSI-2 4-Lane Camera PHY 1" },
	{ 0x0AC80000, 0x0AC9FFFF, "ife_1",      "CAMERA",  "Spectra Image Front End 1 (Secondary Dual ISP)" },
};

static int do_mmio(const char *filter)
{
	size_t i;
	size_t count = sizeof(g_silicon_mmio) / sizeof(g_silicon_mmio[0]);
	size_t matched = 0;

	puts("\n=== Pure Silicon MMIO Peripheral Memory Map (In-Memory Table) ===");
	printf("%-14s  %-10s  %-21s  %s\n", "NAME", "CATEGORY", "ADDRESS RANGE", "DESCRIPTION");
	puts("------------------------------------------------------------------------------------------------------");

	for (i = 0; i < count; i++) {
		const struct silicon_mmio *m = &g_silicon_mmio[i];
		char range_buf[32];

		if (filter && *filter) {
			if (!strcasestr(m->name, filter) &&
			    !strcasestr(m->category, filter) &&
			    !strcasestr(m->description, filter))
				continue;
		}

		snprintf(range_buf, sizeof(range_buf), "0x%08llx-0x%08llx",
		         (unsigned long long)m->start, (unsigned long long)m->end);
		printf("%-14s  %-10s  %-21s  %s\n", m->name, m->category, range_buf, m->description);
		matched++;
	}

	puts("------------------------------------------------------------------------------------------------------");
	printf("Total MMIO Hardware Blocks Displayed: %lu / %lu\n\n", (unsigned long)matched, (unsigned long)count);
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 4: Qualcomm SPMI PMIC Regulators & Power Models
 * ============================================================================== */

struct pmic_regulator {
	const char *name;
	const char *rail_type;
	uint16_t base_addr;
	uint32_t min_uV;
	uint32_t max_uV;
	uint32_t step_uV;
	const char *target_rail;
};

static const struct pmic_regulator g_pmic_regs[] = {
	{ "S1A", "SMPS (Buck)", 0x1400,  300000, 1100000,  5000, "VDD_CX (Digital Logic Core)" },
	{ "S2A", "SMPS (Buck)", 0x1700,  600000, 1125000, 10000, "VDD_MX (Memory Core Fabric)" },
	{ "S3A", "SMPS (Buck)", 0x1A00,  600000, 1125000, 10000, "VDD_APC (CPU Cluster Cluster Rail)" },
	{ "S4A", "SMPS (Buck)", 0x1D00, 1200000, 1400000, 10000, "VDD_LPDDR4x (DRAM I/O Voltage)" },
	{ "S5A", "SMPS (Buck)", 0x2000, 1850000, 2040000, 10000, "VDD_1P8 (System I/O & Analog Rail)" },
	{ "L1A", "LDO (N-FET)", 0x4000,  375000, 1525000, 12500, "VDD_MODEM (Hexagon Baseband)" },
	{ "L2A", "LDO (P-FET)", 0x4100, 1200000, 1350000, 12500, "VDD_UFS_VCCQ (UFS Core Controller)" },
	{ "L3A", "LDO (P-FET)", 0x4200, 1650000, 3100000, 12500, "VDD_CAM_IO (Camera Sensor I/O)" },
	{ "L4A", "LDO (P-FET)", 0x4300, 2800000, 3100000, 12500, "VDD_DISP_IO (MIPI DSI Panel I/O)" },
	{ "L5A", "LDO (P-FET)", 0x4400, 1750000, 3337500, 12500, "VDD_SDCC2_VCC (MicroSD High-Voltage)" },
	{ "L6A", "LDO (P-FET)", 0x4500, 1800000, 3000000, 12500, "VDD_AUDIO (Soundwire / Codec Analog)" },
	{ "L7A", "LDO (P-FET)", 0x4600, 2700000, 3540000, 12500, "VDD_WLAN_BT (RF Analog Front-End)" },
};

static int do_pmic(void)
{
	size_t i;
	size_t count = sizeof(g_pmic_regs) / sizeof(g_pmic_regs[0]);

	puts("\n=== Qualcomm SPMI PMIC Architecture & Regulators ===");
	puts("  Interface:          Qualcomm SPMI Arbiter v2 (MIPI-compliant 2-wire serial bus)");
	puts("  Configuration Base: 0x01C0A000 (SPMI Config / Arbiter Tables)");
	puts("  SPMI Core Base:     0x01C40000 (Channel Mapping & Master Control)");
	puts("  Channel Windows:    0x01E00000 - 0x03DFFFFF (32 MB, 512 Peripherals x 64 KB)");
	puts("  Observer Windows:   0x03E00000 - 0x03EFFFFF (Read-only status monitor)");

	puts("\n--- Key SPMI Peripheral Register Addresses ---");
	puts("  REVID (0x0100):     PMIC Hardware Revision ID & Subtype Code");
	puts("  PON (0x0800):       Power-On Reset, Hard Reset, Key Vol+/Vol- Status");
	puts("  BUA (0x1000):       Backup Battery Charger & RTC Backup Control");
	puts("  TSENS (0x2400):     PMIC On-Die Temperature Sensor Alarm Thresholds");
	puts("  SMBB (0x3100):      Switch-Mode Battery Charger & USB VBUS Controller");
	puts("  FG_BATT (0x4000):   Fuel Gauge Battery Monitor, SOC, Current & Voltage");
	puts("  GPIOs (0xC000):     SPMI PMIC Output Drivers & Level Shifters");
	puts("  MPPs (0xD000):      Multi-Purpose Pins (Analog Input, Sink, Current DAC)");

	puts("\n--- Silicon Voltage Regulator Rails (Bucks & LDOs) ---");
	printf("%-6s  %-12s  %-10s  %-15s  %-11s  %s\n",
	       "RAIL", "TYPE", "SPMI ADDR", "VOLTAGE RANGE", "STEP SIZE", "TARGET SILICON LOAD");
	puts("------------------------------------------------------------------------------------------------------");

	for (i = 0; i < count; i++) {
		const struct pmic_regulator *r = &g_pmic_regs[i];
		char range_buf[32];
		snprintf(range_buf, sizeof(range_buf), "%.3fV - %.3fV",
		         (double)r->min_uV / 1000000.0, (double)r->max_uV / 1000000.0);
		printf("%-6s  %-12s  0x%04x      %-15s  %.1f mV      %s\n",
		       r->name, r->rail_type, r->base_addr, range_buf,
		       (double)r->step_uV / 1000.0, r->target_rail);
	}

	puts("------------------------------------------------------------------------------------------------------\n");
	return EXIT_SUCCESS;
}

static int do_volt(void)
{
	puts("\n=== PMIC Voltage Steps, Current & Power Equations ===");
	puts("--- 1. SPMI DAC Voltage Conversion Formulas ---");
	puts("  Buck SMPS Core (S1A/S2A/S3A):");
	puts("    V_out(uV) = 300,000 uV + (REG_VAL * 5,000 uV)       [Range: 0.300V - 1.100V]");
	puts("  Buck SMPS High-Range (S4A/S5A):");
	puts("    V_out(uV) = 600,000 uV + (REG_VAL * 10,000 uV)      [Range: 0.600V - 2.040V]");
	puts("  Low-Range LDO (N-FET):");
	puts("    V_out(uV) = 375,000 uV + (REG_VAL * 12,500 uV)      [Range: 0.375V - 1.525V]");
	puts("  High-Range LDO (P-FET):");
	puts("    V_out(uV) = 1,750,000 uV + (REG_VAL * 12,500 uV)    [Range: 1.750V - 3.337V]");

	puts("\n--- 2. Instantaneous Dynamic Silicon Power Model ---");
	puts("  Dynamic Switching Power:  P_dyn = C_eff * V_dd^2 * f");
	puts("  Static Leakage Power:     P_leak = V_dd * I_leak(T)   (exponential with temperature)");
	puts("  Total Rail Power:         P_total = P_dyn + P_leak");

	puts("\n--- 3. PMIC Fuel Gauge Current & ADC Telemetry ---");
	puts("  Sense Resistor (R_sense): 10 mOhm (0.010 Ohm precision shunt)");
	puts("  Coulomb Counter Voltage:  V_sense = 1.49 uV / LSB");
	puts("  Battery Current Formula:  I_batt = (RAW_ADC_VAL * 1.49 uV) / R_sense");
	puts("  15-bit VADC Step:         152.58 uV / LSB (1.25V reference bandgap)\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 5: GCC & RPM Clock Controller Registers (Clocks & Dividers)
 * ============================================================================== */

static int do_clock(void)
{
	puts("\n=== Qualcomm Global Clock Controller (GCC) & RPM Clock Tree ===");
	puts("  Architecture:       Hardware Root Clock Generators (RCGR) & Branch Control (CBCR)");
	puts("  GCC MMIO Base:      0x01400000 - 0x015EFFFF (1.9 MB Clock Routing Window)");
	puts("  TCXO Base Crystal:  19.200 MHz Reference Oscillator");

	puts("\n--- 1. Root Clock Generator (RCGR) Register Layout ---");
	puts("  CMD_RCGR (+0x0000): Root Command Register");
	puts("    - Bit 0: ROOT_EN      (Root Clock Enable)");
	puts("    - Bit 1: UPDATE       (Trigger Frequency Switch, hardware clears when locked)");
	puts("    - Bit 4: ROOT_OFF     (Status: 1 = Root clock disabled, 0 = Active)");
	puts("  CFG_RCGR (+0x0004): Configuration Register");
	puts("    - Bits [2:0]: SRC_SEL (0=XO 19.2MHz, 1=GPLL0 600MHz, 2=GPLL6 384MHz, 3=GPLL7 533MHz)");
	puts("    - Bits [4:0]: SRC_DIV ((2 * div) - 1 division ratio)");
	puts("    - Bits [13:12]: MODE  (00=Bypass, 01=Dual-edge mode, 10=M/N:D fractional mode)");
	puts("  M_RCGR   (+0x0008): Fractional Multiplier Polynomial M");
	puts("  N_RCGR   (+0x000C): Fractional Modulo Polynomial N");
	puts("  D_RCGR   (+0x0010): Fractional Denominator Polynomial 2*D");

	puts("\n--- 2. Clock Branch Control Register (CBCR) Layout ---");
	puts("  CBCR (+0x0000): Clock Branch Control");
	puts("    - Bit 0:  CLK_ENABLE  (Clock Gate Enable)");
	puts("    - Bit 31: CLK_OFF     (Hardware Gate Status: 1 = Gated/Halted, 0 = Running)");

	puts("\n--- 3. Core Hardware Clock Branches & Register Offsets ---");
	printf("%-30s  %-12s  %-14s  %s\n", "CLOCK BRANCH NAME", "CBCR ADDR", "CMD_RCGR ADDR", "FREQUENCY / USAGE");
	puts("------------------------------------------------------------------------------------------------------");
	puts("GCC_SDCC1_APPS_CLK              0x0016C000    0x0016C004      eMMC / UFS Storage (Up to 384 MHz)");
	puts("GCC_SDCC2_APPS_CLK              0x00014000    0x00014004      MicroSD High-Speed (Up to 200 MHz SDR104)");
	puts("GCC_USB30_MASTER_CLK            0x0003F000    0x0003F014      USB 3.0 SuperSpeed Master (125 MHz)");
	puts("GCC_QUPV3_WRAP_0_M_AHB_CLK      0x00017004    N/A (AHB Gate)  QUPv3 Master AHB Bus (I2C/SPI/UART)");
	puts("GCC_CAMSS_TOP_AHB_CLK           0x0005A000    0x0005A004      Spectra ISP Top AHB Bus (80 MHz)");
	puts("GCC_DISP_AHB_CLK                0x0000B000    N/A (AHB Gate)  MDSS / DPU Display Interface Clock");
	puts("GCC_GPU_CFG_AHB_CLK             0x00071004    N/A (AHB Gate)  Adreno GPU Configuration Bus");
	puts("GCC_CRYPTO_CLK                  0x00016000    0x00016004      Qualcomm Crypto Engine Core (160 MHz)");
	puts("APCS_CPU_PLL_CLK                0x090B0000    0x090B0004      CPU Cluster Dynamic Frequency Scaling");
	puts("------------------------------------------------------------------------------------------------------\n");

	return EXIT_SUCCESS;
}

static int do_pll(void)
{
	puts("\n=== Hardware TCXO Base & Assembly Clock Calibration ===");
	puts("  Base Crystal:       19.200 MHz TCXO Reference Oscillator");

#if defined(__aarch64__) || defined(__arm64__)
	{
		bool ok;
		uint64_t cntfrq = read_arm64_sysreg(9, &ok);
		if (ok && cntfrq > 0)
			printf("  CNTFRQ_EL0:         %llu Hz (%.3f MHz Base Hardware Timer)\n",
			       (unsigned long long)cntfrq, (double)cntfrq / 1000000.0);

		{
			double core_mhz = measure_cpu_clock_mhz();
			if (core_mhz > 0.0)
				printf("  Live Core Clock:    %.1f MHz (assembly calibrated timing loop)\n", core_mhz);
		}
	}
#endif

	puts("\n--- In-Memory Qualcomm GCC PLL Network (SM6225 / SDM660 / SDM439) ---");
	puts("  GPLL0 (General Purpose PLL 0):  600.0 MHz (Main System NoC & Peripheral Clock)");
	puts("  GPLL1 (General Purpose PLL 1):  576.0 MHz (Low-Power Audio & Crypto Engine)");
	puts("  GPLL3 (General Purpose PLL 3): 1100.0 MHz (Display Processing & Camera Ingestion)");
	puts("  GPLL4 (General Purpose PLL 4): 1600.0 MHz (UFS Storage & PCIe High-Speed Phy)");
	puts("  GPLL6 (General Purpose PLL 6):  384.0 MHz (Low-Power Sleep & Sensor Core)");
	puts("  GPLL7 (General Purpose PLL 7):  533.3 MHz (DDR / BIMC Memory Controller Arbiter)");
	puts("  GPLL8 (General Purpose PLL 8):  825.0 MHz (Adreno GPU Core Voltage Rail)\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 6: PSCI & Qualcomm TrustZone / QSEE SMC Interface
 * ============================================================================== */

static int do_psci(void)
{
	puts("\n=== PSCI & Qualcomm TrustZone / QSEE SMC Call Interface ===");
	puts("  Calling Convention: ARM SMCCC (Secure Monitor Call Calling Convention)");
	puts("  Instruction:        smc #0 (Traps from EL1 to EL3 Secure Monitor)");
	puts("  Input Registers:    X0 = Function ID, X1-X7 = Arguments / Physical Pointers");
	puts("  Return Registers:   X0 = Status Code, X1-X3 = Return Values");

	puts("\n--- Standard PSCI & Qualcomm SIP TrustZone Function IDs ---");
	printf("%-12s  %-24s  %-6s  %s\n", "FUNCTION ID", "FUNCTION NAME", "ABI", "DESCRIPTION");
	puts("------------------------------------------------------------------------------------------------------");
	puts("0x84000000    PSCI_VERSION              SMC32   Returns implemented PSCI version major:minor");
	puts("0x84000001    CPU_SUSPEND               SMC32   Places current core into low-power sleep state");
	puts("0xC4000001    CPU_SUSPEND               SMC64   64-bit Core power-down / retention suspension");
	puts("0x84000002    CPU_OFF                   SMC32   Powers down calling core completely");
	puts("0x84000003    CPU_ON                    SMC32   Powers up target core with entry point address");
	puts("0xC4000003    CPU_ON                    SMC64   64-bit Core power-up with 64-bit context argument");
	puts("0x84000004    AFFINITY_INFO             SMC32   Queries target core power state (ON/OFF/PENDING)");
	puts("0xC4000004    AFFINITY_INFO             SMC64   64-bit Core affinity power state query");
	puts("0x84000008    SYSTEM_OFF                SMC32   Powers down SoC and platform completely");
	puts("0x84000009    SYSTEM_RESET              SMC32   Triggers cold SoC reboot through TrustZone");
	puts("0x8400000A    PSCI_FEATURES             SMC32   Queries support for specific PSCI function ID");
	puts("0x84000012    SYSTEM_RESET2             SMC32   Warm reset with vendor reset type and cookie");
	puts("0xC4000012    SYSTEM_RESET2             SMC64   64-bit Warm reset with vendor cookie");
	puts("0x84000013    MEM_PROTECT               SMC32   Enables memory preservation across warm reboot");
	puts("0x02000101    TZ_SCM_CMD_SIP            SIP     Qualcomm QSEE Secure App Command Dispatch");
	puts("0x02000200    TZ_QFPROM_READ_FUSE       SIP     Secure Read of Hardware Fuse PROM Registers");
	puts("0x02000300    TZ_QFPROM_WRITE_FUSE      SIP     Secure Blow of Silicon Production Fuses");
	puts("0x02000400    TZ_PIL_PAS_AUTH_RESET     SIP     Peripheral Image Loader Auth (aDSP/cDSP/mDSP)");
	puts("0x02000800    TZ_MEM_PROTECT_XPU        SIP     Peripheral Memory Protection & XPU Carveout");
	puts("0x02000900    TZ_SMMU_SECURE_CFG        SIP     Stage-2 SMMU Context Bank Security Lock");
	puts("------------------------------------------------------------------------------------------------------\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 7: Spectra ISP & Camera Look-Up Tables (LUTs)
 * ============================================================================== */

static int do_isp(void)
{
	puts("\n=== Qualcomm Spectra ISP & Camera Subsystem Architecture ===");
	puts("  Architecture:       Titan / Spectra Dual Image Signal Processor");
	puts("  Sensor Ingestion:   MIPI CSI-2 via 4-lane CSIPHY & CSID Decoders");
	puts("  Processing Engine:  IFE (Image Front End), BPS (Bayer), IPE (Post-Processing)");

	puts("\n--- ISP Hardware Physical MMIO Windows ---");
	puts("  0x0AC00000 - 0x0AC1FFFF: IFE0 (Primary Image Front End Dual Camera Pipeline)");
	puts("  0x0AC80000 - 0x0AC9FFFF: IFE1 (Secondary Image Front End Auxiliary Camera)");
	puts("  0x0AC30000 - 0x0AC37FFF: CSID0 (Camera Serial Interface Decoder Core 0)");
	puts("  0x0AC65000 - 0x0AC65FFF: CSIPHY0 (MIPI CSI-2 4-lane D-PHY/C-PHY 0)");
	puts("  0x0AC66000 - 0x0AC66FFF: CSIPHY1 (MIPI CSI-2 4-lane D-PHY/C-PHY 1)");
	puts("  0x0AC10000 - 0x0AC17FFF: ICP (Image Control Processor Microcontroller)");
	puts("  0x0AC20000 - 0x0AC27FFF: BPS (Bayer Processing Segment Core)");
	puts("  0x0AC40000 - 0x0AC47FFF: IPE (Image Processing Engine Core)");

	puts("\n--- Hardware Look-Up Tables (LUTs) & Processing Blocks ---");
	puts("  1. 3D-LUT Color Transform Table:");
	puts("     - Dimension: 17 x 17 x 17 tetrahedral mesh (4,913 RGB calibration nodes)");
	puts("     - Function:  Hardware color space mapping (DCI-P3, sRGB, Rec.2020 HDR)");
	puts("     - Location:  IPE Post-Processing Hardware Window (Offset +0x1800)");

	puts("  2. Gamma Correction LUT (RGB Curves):");
	puts("     - Dimension: 512 entries per color channel (R, G, B) x 14-bit depth");
	puts("     - Function:  Perceptual non-linear luminance tone curve mapping");
	puts("     - Location:  IFE & IPE Gamma Processor (Offset +0x0E00)");

	puts("  3. Lens Shading Correction (LSC) Mesh Table:");
	puts("     - Dimension: 17 x 13 spatial grid nodes across sensor plane");
	puts("     - Function:  Optical vignetting and chromatic falloff compensation");
	puts("     - Location:  IFE Front-End Raw Ingestion (Offset +0x0800)");

	puts("  4. Color Correction Matrix (CCM):");
	puts("     - Dimension: 3 x 3 signed matrix coefficients + 3-channel offsets");
	puts("     - Function:  Sensor RGB spectral sensitivity cross-talk correction");

	puts("  5. Bad Pixel Correction (BPC) & Demosaic LUT:");
	puts("     - Dimension: Dynamic hot/dead pixel threshold and interpolation table");
	puts("     - Function:  Bayer pattern (RGGB/BGGR) to full RGB color reconstruction\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 8: Hexagon DSPs, ARDP & Network Acceleration Engine (IPA)
 * ============================================================================== */

static int do_dsp(void)
{
	puts("\n=== Qualcomm Hexagon DSPs & Hardware Network Accelerators ===");

	puts("--- 1. Hexagon QDSP6 Subsystem Cores ---");
	puts("  aDSP (Audio DSP):        Base: 0x062D0000 | Architecture: Hexagon QDSP6 v66");
	puts("    - Subsystem:           Low-Power Audio Subsystem (LPASS)");
	puts("    - Hardware Offload:    Hardware MP3/AAC/FLAC decoding, Voice Processing, Soundwire");

	puts("  cDSP (Compute DSP / AI): Base: 0x08300000 | Architecture: Hexagon QDSP6 v68");
	puts("    - Vector Acceleration: HVX (Hexagon Vector Extensions: 1024-bit SIMD registers)");
	puts("    - Matrix AI Engine:    HMX (Hexagon Matrix eXtensions: INT8/FP16 Tensor NPU)");
	puts("    - Target Workloads:    On-device AI, NNAPI, Computer Vision, Camera Post-Filter");

	puts("  mDSP (Modem Subsystem):  Base: 0x04080000 | Architecture: Hexagon Baseband Core");
	puts("    - Subsystem:           4G/5G Baseband Processor, Digital Signal Processing");
	puts("    - Peripheral Auth:     Booted securely via TrustZone PIL PAS (SMC 0x02000400)");

	puts("\n--- 2. IPA (IP Accelerator) Network Offload Engine ---");
	puts("  Physical MMIO Base:      0x01E40000 - 0x01EBFFFF (768 KB)");
	puts("  Core Capabilities:       Hardware IPv4/IPv6 packet routing, header insertion/removal");
	puts("  Hardware Routing RAM:    On-die SRAM table for wire-speed packet forwarding");
	puts("  Filtering Engine:        Hardware firewall rules and NAT translation tables");
	puts("  GSI DMA Channels:        Generic Software Interface DMA ring buffers to CPU & Modem\n");

	return EXIT_SUCCESS;
}

static int do_ardp(void)
{
	puts("\n=== Audio Routing DSP (ARDP), LPASS, Soundwire & SLIMbus ===");
	puts("  Core Subsystem:     Qualcomm Low-Power Audio Subsystem (LPASS)");
	puts("  LPASS Audio Base:   0x062D0000 - 0x062DFFFF");

	puts("\n--- 1. Digital Audio Bus Interfaces ---");
	puts("  Soundwire Controller:    Base: 0x06280000 (MIPI Soundwire v1.1 Master)");
	puts("    - Channels:            Multi-drop 2-wire serial bus (Clock + Bi-directional Data)");
	puts("    - Offload:             Digital Microphones, Speaker Amplifiers, Smart PA");
	puts("  SLIMbus Arbiter:         Base: 0x062DC000 (Serial Low-power Inter-chip Media Bus)");
	puts("    - Clocking:            Synchronous TDM framing for high-fidelity audio codecs");

	puts("\n--- 2. Audio Routing DSP (ARDP) & Mixer Channels ---");
	puts("  AFE (Audio Front-End):   Hardware PCM matrix routing, sample rate conversion");
	puts("  Voice Processing:        Hardware Acoustic Echo Cancellation (AEC) & Dual-mic NS");
	puts("  DMA FIFO Rings:          Multi-channel circular buffers with watermark interrupts\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 9: Analog-to-Digital Converter (A2D / ADC) Subsystem
 * ============================================================================== */

static int do_adc(void)
{
	puts("\n=== Qualcomm PMIC Analog-to-Digital Converter (VADC / ADC5) ===");
	puts("  Bus Interface:      SPMI Peripheral 0x3100 / 0x3C00");
	puts("  Architecture:       15-bit / 16-bit Sigma-Delta Analog-to-Digital Converter");

	puts("\n--- ADC Hardware Channels & Signal Multiplexer ---");
	printf("%-10s  %-14s  %-12s  %s\n", "CHANNEL", "SIGNAL NAME", "PRESCALER", "PHYSICAL PARAMETER");
	puts("-----------------------------------------------------------------------------------");
	puts("0x00        VBAT            1/3          Battery Terminal Voltage (0 - 4.8 V)");
	puts("0x01        VPH_PWR         1/3          System Main Power Rail (0 - 4.8 V)");
	puts("0x02        VDD_MSM         1/1          Core Logic Supply Voltage (0 - 1.2 V)");
	puts("0x04        XO_THERM        1/1          19.2 MHz Crystal Thermistor Temp");
	puts("0x05        PMIC_THERM      1/1          PMIC Board Thermistor Temp");
	puts("0x06        DIE_TEMP        1/1          PMIC On-Die Silicon Junction Sensor");
	puts("0x07        PA_THERM        1/1          RF Power Amplifier Thermistor Temp");
	puts("0x08        USB_IN (VBUS)   1/16         USB 5V / 9V / 12V QC Input Voltage");
	puts("0x09        SYS_THERM       1/1          SoC System Board Thermistor Temp");
	puts("-----------------------------------------------------------------------------------");

	puts("\n--- ADC Conversion & Timing Registers ---");
	puts("  ADC_DIG_PARAM (0x50):     Decimation Ratio (256, 512, 1024 clock cycles)");
	puts("  ADC_FAST_AVG (0x5A):      Hardware Fast Averaging (1, 2, 4, 8, 16 samples)");
	puts("  ADC_CH_SEL_CTL (0x48):    Input Signal Channel Multiplexer Select");
	puts("  ADC_EN_CTL (0x46):        Master Analog Front-End Enable bit 7");
	puts("  ADC_CONV_REQ (0x44):      Conversion Trigger (Bit 7: Start Conversion)");
	puts("  ADC_DATA_LOW (0x04):      16-bit ADC Result Lower Byte");
	puts("  ADC_DATA_HIGH (0x05):     16-bit ADC Result Upper Byte\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 10: System NoC Interconnects & Traffic QoS Controllers
 * ============================================================================== */

static int do_noc(void)
{
	puts("\n=== Qualcomm System NoC (Network-on-Chip) Interconnects & QoS ===");

	puts("--- 1. Interconnect Fabric Bus Bridges ---");
	puts("  SNOC (System NoC):       Base: 0x01626000 | High-speed system memory crossbar");
	puts("  CNOC (Config NoC):       Base: 0x01500000 | Peripheral control register interconnect");
	puts("  MMNOC (Multimedia NoC):  Base: 0x05040000 | High-throughput Display (DPU) & Camera (ISP)");
	puts("  BIMC (Memory NoC):       Base: 0x044A0000 | LPDDR4x Memory Controller Arbiter");

	puts("\n--- 2. Traffic Quality of Service (QoS) Registers ---");
	puts("  Priority Registers:      0x01626000 + 0x40 * Port (Priority Level 0 - 15)");
	puts("  Urgency Forwarding:      Dynamic latency-critical forwarding for real-time display");
	puts("  Bandwidth Limiting:      Token-bucket rate shapers preventing bus starvation");

	puts("\n--- 3. Hardware Bandwidth Monitors (BWMON) ---");
	puts("  GPU BWMON (0x05990000):  Real-time Adreno GPU memory throughput measurement");
	puts("  CPU BWMON (0x01620000):  Real-time Application Processor memory bus monitor");
	puts("  Sampling Window:         Hardware timer window triggering bus throttling interrupts\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 11: System Management Interface (SMI) & Shared Memory Mailbox
 * ============================================================================== */

static int do_smi(void)
{
	puts("\n=== System Management Interface (SMI) & Shared Memory Interconnect ===");
	puts("  Architecture:       Qualcomm Shared Memory (SMEM) & Subsystem Mailbox Interconnect");

	puts("\n--- 1. Subsystem Mailbox & Inter-Processor Communication (IPC) ---");
	puts("  APCS IPC Base:      0x090B5000 (Hardware Doorbell Registers)");
	puts("    - APCS to aDSP:   Trigger bit 0 (Audio Subsystem IPC Wakeup)");
	puts("    - APCS to cDSP:   Trigger bit 1 (Compute NPU Execution Dispatch)");
	puts("    - APCS to mDSP:   Trigger bit 2 (Modem Baseband Command Interface)");
	puts("    - APCS to RPM:    Trigger bit 3 (Resource Power Manager Sleep Transition)");

	puts("\n--- 2. Shared Memory Point-to-Point (SMP2P) ---");
	puts("  SMP2P Base:         0x0163C000 (Cross-Core Interrupt Status Bits)");
	puts("  Features:           32-bit hardware status notification without memory locking");

	puts("\n--- 3. Physical Shared Memory (SMEM) Carveout ---");
	puts("  Physical Window:    0x86000000 - 0x861FFFFF (2 MB Reserved DRAM)");
	puts("  Partitions:         Static routing tables, Heap info, Subsystem power states\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 12: Silicon Ring Oscillators, Aging & CPR/TSENS Sensors
 * ============================================================================== */

static int do_rosc(void)
{
	puts("\n=== Silicon Ring Oscillators (ROSC), CPR & Thermal Sensors ===");
	puts("  Principle:          On-die inverted delay lines measuring gate propagation delays");
	puts("  Workload:           Adaptive Voltage Scaling (AVS) & Silicon Aging Monitoring");

	puts("\n--- 1. Core Power Reduction (CPR) Ring Oscillator Banks ---");
	puts("  APCS CPR Base:      0x090D8000 (CPU Cluster Adaptive Voltage Controller)");
	puts("  System CPR Base:    0x01668000 (SoC Core Logic Adaptive Voltage Controller)");
	puts("  Ring Oscillator Types:");
	puts("    - ROSC 0 - 3:     Standard Inverter Chains (High/Standard/Low-VT thresholds)");
	puts("    - ROSC 4 - 7:     NAND2 / NOR2 Logic Gate Chains (Silicon Speed Binning)");
	puts("    - ROSC 8 - 11:    Pass-Gate Delay Lines (Routing Wire & Contact Resistance)");
	puts("    - ROSC 12 - 15:   Interconnect Capacitive Delay Lines");

	puts("\n--- 2. CPR Hardware Control Registers ---");
	puts("  CPR_CONFIG (0x00):        Controller Mode (Open-Loop vs Closed-Loop AVS)");
	puts("  CPR_STEP_QUOT_MIN (0x08): Target Ring Oscillator Frequency Quotient Minimum");
	puts("  CPR_STEP_QUOT_MAX (0x0C): Target Ring Oscillator Frequency Quotient Maximum");
	puts("  CPR_RESULT_0 (0x14):      Measured Gate Error Delta & Recommended PMIC Step");
	puts("  CPR_ROSC_MASK (0x24):     Active Ring Oscillator Selection Mask");

	puts("\n--- 3. TSENS Thermal Ring Oscillators ---");
	puts("  Physical Base:      0x01678000 / 0x04410000");
	puts("  Operation:          Thermal-sensitive ring oscillator frequency delta vs TCXO base");
	puts("  Registers:          TSENS_CTRL (0x00), TSENS_PERIOD (0x08), TSENS_S0..10 (0x40+4*n)\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 13: Qualcomm Crypto Engine (CE v5), HWKM & ICE Registers
 * ============================================================================== */

static int do_crypto(void)
{
	puts("\n=== Qualcomm Crypto Engine (CE v5), BAM DMA, HWKM & ICE ===");
	puts("  Crypto Core Base:   0x00700000 (Qualcomm Crypto Engine v5 Hardware Accelerator)");
	puts("  BAM Crypto Base:    0x00704000 (Bus Access Manager Dedicated DMA Controller)");
	puts("  HWKM Base:          0x00730000 (Hardware Key Manager Secure Root-of-Trust)");
	puts("  UFS ICE Base:       0x01D88000 (Inline Crypto Engine for Transparent Disk Crypt)");

	puts("\n--- 1. Hardware Cryptographic Primitives ---");
	puts("  Symmetric Ciphers:  AES-128, AES-192, AES-256 (ECB, CBC, CTR, XTS, CCM, GCM)");
	puts("  Hash Algorithms:    SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256");
	puts("  Legacy Ciphers:     DES, Triple-DES (3DES-CBC / 3DES-ECB)");

	puts("\n--- 2. Crypto Engine Register Specifications ---");
	puts("  CRYPTO_CONFIG (0x040004):       FIFO Mode, High-performance DMA, Byte Ordering");
	puts("  CRYPTO_ENGINES_AVAIL (0x040000):Bitmask of Active On-Die Cryptographic Hardware");
	puts("  CRYPTO_STATUS (0x040110):       Core Busy, DMA Done, MAC Valid, Auth Error");
	puts("  CRYPTO_AUTH_SEG_CFG (0x040008): Digest Selection, Auth Key Size, Segment Length");
	puts("  CRYPTO_ENCR_SEG_CFG (0x04000C): Cipher Algorithm, Mode, Key Length, Direction");
	puts("  CRYPTO_ENCR_KEY0..7 (0x040020): 256-bit Key Registers (TrustZone Protected)");
	puts("  CRYPTO_AUTH_IV0..3 (0x040040):  Initial Vector Registers (128-bit CBC/CTR IV)");
	puts("  ICE_REGS_CONTROL (0x0000):      UFS Inline Storage Hardware Sector Encryption\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 14: AI Accelerators, Hexagon Tensor Processor (HTP) & HMX
 * ============================================================================== */

static int do_ai(void)
{
	puts("\n=== Hexagon Tensor Processor (HTP), HMX & AI Accelerators ===");
	puts("  Subsystem:          Hexagon cDSP Compute Core with Dedicated Tensor Hardware");
	puts("  HTP Core Base:      0x08380000 (Dedicated Matrix Multiplication Engine)");
	puts("  cDSP Base:          0x08300000 (Hexagon QDSP6 v68 Vector Processor)");

	puts("\n--- 1. Hardware Matrix & Vector Compute Engines ---");
	puts("  HTP Matrix Engine:  INT8, INT16, FP16, and BFLOAT16 GEMM Matrix Dot-Product");
	puts("  HVX Vector Engine:  1024-bit SIMD Registers (V0 - V31), 128 parallel 8-bit MACs/cycle");
	puts("  Activation Unit:    On-die hardware ReLU, LeakyReLU, Sigmoid, and GELU Interpolation");

	puts("\n--- 2. HTP Hardware Register Architecture ---");
	puts("  HTP_CORE_CFG (0x0000):          Matrix Unit Clock Gate, Precision Select (INT8/FP16)");
	puts("  HTP_STATUS (0x0004):            Computation Active, Pipeline Stall, Thermal Flag");
	puts("  HTP_DMA_SRC_PTR (0x0010):       64-bit Physical Address Input Activation Tensor");
	puts("  HTP_DMA_DST_PTR (0x0018):       64-bit Physical Address Output Activation Tensor");
	puts("  HTP_TENSOR_DIM_M_N_K (0x0020):  GEMM Matrix Dimensions (M rows x K depth x N cols)");
	puts("  HTP_ACCUM_CTRL (0x0028):        FP32 / 32-bit Integer Accumulator & Saturation Rounding");
	puts("  HVX_VECTOR_CFG (0x0100):        1024-bit SIMD Execution Mode & Partitioning");

	puts("\n--- 3. Adreno GPU Machine Learning Accelerators ---");
	puts("  Adreno Compute:     Base: 0x05900000 (Hardware FP16 Dot-Product dot2acc/dot4acc)\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 15: ARMv8 PMU Performance Counter Architectural Registers
 * ============================================================================== */

static int do_pmu(void)
{
	puts("\n=== ARMv8 Architectural Performance Monitor Unit (PMU) ===");

#if defined(__aarch64__) || defined(__arm64__)
	{
		bool ok;
		uint64_t pmcr, pmccntr, pmuserenr, pmcntenset, pmccfiltr;

		pmcr = read_arm64_sysreg(16, &ok);
		if (ok) {
			uint32_t counters = (pmcr >> 11) & 0x1f;
			printf("  PMCR_EL0:           0x%016llx (Control Register)\n", (unsigned long long)pmcr);
			printf("    Hardware Counters:%u Event Counters Available\n", counters);
			printf("    Cycle Counter Div: %s\n", (pmcr & (1 << 3)) ? "Prescaler 64x" : "1x (Direct Cycle)");
			printf("    Counter Enable:    %s\n", (pmcr & 1) ? "Active" : "Disabled");
		} else {
			puts("  PMCR_EL0:           [TRAPPED: EL1 Kernel Privilege Required]");
		}

		pmccntr = read_arm64_sysreg(17, &ok);
		if (ok) {
			printf("  PMCCNTR_EL0:        0x%016llx (%llu Live Hardware Execution Cycles!)\n",
			       (unsigned long long)pmccntr, (unsigned long long)pmccntr);
		} else {
			puts("  PMCCNTR_EL0:        [TRAPPED: EL0 Cycle Read Gated by PMUSERENR_EL0.CR]");
		}

		pmuserenr = read_arm64_sysreg(18, &ok);
		if (ok) {
			printf("  PMUSERENR_EL0:      0x%016llx\n", (unsigned long long)pmuserenr);
			printf("    Userland EN:      %s\n", (pmuserenr & 1) ? "Allowed" : "Blocked");
			printf("    Cycle Read (CR):  %s\n", (pmuserenr & (1 << 2)) ? "Allowed" : "Blocked");
			printf("    Event Read (ER):  %s\n", (pmuserenr & (1 << 3)) ? "Allowed" : "Blocked");
		} else {
			puts("  PMUSERENR_EL0:      [TRAPPED: EL1 Privilege Required]");
		}

		pmcntenset = read_arm64_sysreg(19, &ok);
		if (ok) {
			printf("  PMCNTENSET_EL0:     0x%016llx (Cycle Bit: %s)\n",
			       (unsigned long long)pmcntenset,
			       (pmcntenset & (1ULL << 31)) ? "Enabled" : "Disabled");
		}

		pmccfiltr = read_arm64_sysreg(20, &ok);
		if (ok) {
			printf("  PMCCFILTR_EL0:      0x%016llx (Cycle Filter Masks)\n", (unsigned long long)pmccfiltr);
		}
	}
#else
	puts("  Platform:           x86_64 Emulation (ARM64 PMU Not Present)");
#endif

	puts("\n--- Standard ARMv8 Hardware Architectural Event Codes ---");
	printf("%-10s  %-20s  %s\n", "EVENT ID", "EVENT MNEMONIC", "ARCHITECTURAL DESCRIPTION");
	puts("-----------------------------------------------------------------------------------");
	puts("0x0001      L1I_CACHE_REFILL      Level 1 Instruction Cache Miss & Refill");
	puts("0x0003      L1D_CACHE_REFILL      Level 1 Data Cache Miss & Refill");
	puts("0x0004      L1D_CACHE             Level 1 Data Cache Access");
	puts("0x0008      INST_RETIRED          Instructions Architecturally Executed");
	puts("0x0010      BR_MIS_PRED           Branch Direction Mispredicted");
	puts("0x0011      CPU_CYCLES            Cycle Count (Architectural Execution Frequency)");
	puts("0x0016      L2D_CACHE             Level 2 Data Cache Access");
	puts("0x0017      L2D_CACHE_REFILL      Level 2 Data Cache Miss & Refill");
	puts("0x0023      MEM_ACCESS            Memory Bus Read / Write Transaction");
	puts("-----------------------------------------------------------------------------------\n");

	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 16: Architectural CPU Machine-Code Registers
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
			uint64_t revidr = read_arm64_sysreg(2, &ok);
			if (ok) {
				printf("  REVIDR_EL1:     0x%016llx (Silicon Implementation Revision)\n",
				       (unsigned long long)revidr);
			}
		}

		{
			uint64_t el = read_arm64_sysreg(11, &ok);
			if (ok) {
				uint32_t cur_el = (el >> 2) & 0x3;
				printf("  CurrentEL:      EL%u (Execution Privilege Level)\n", cur_el);
			}
		}

		{
			uint64_t daif = read_arm64_sysreg(12, &ok);
			if (ok) {
				printf("  DAIF:           0x%016llx (Debug:%u SError:%u IRQ:%u FIQ:%u)\n",
				       (unsigned long long)daif,
				       (unsigned)((daif >> 9) & 1), (unsigned)((daif >> 8) & 1),
				       (unsigned)((daif >> 7) & 1), (unsigned)((daif >> 6) & 1));
			}
		}

		{
			uint64_t ctr = read_arm64_sysreg(3, &ok);
			if (ok) {
				uint32_t dminline = 4 << ((ctr >> 16) & 0xf);
				uint32_t iminline = 4 << (ctr & 0xf);
				printf("  CTR_EL0:        0x%016llx (D-Cache Line: %u bytes, I-Cache Line: %u bytes)\n",
				       (unsigned long long)ctr, dminline, iminline);
			}
		}

		{
			uint64_t dczid = read_arm64_sysreg(4, &ok);
			if (ok) {
				uint32_t dzp = (dczid >> 4) & 1;
				uint32_t bs = 4 << (dczid & 0xf);
				printf("  DCZID_EL0:      0x%016llx (DC ZVA %s, Block Size: %u bytes)\n",
				       (unsigned long long)dczid, dzp ? "Prohibited" : "Allowed", bs);
			}
		}

		{
			uint64_t isar0 = read_arm64_sysreg(5, &ok);
			if (ok) {
				uint32_t aes = (isar0 >> 4) & 0xf;
				uint32_t sha1 = (isar0 >> 8) & 0xf;
				uint32_t sha2 = (isar0 >> 12) & 0xf;
				uint32_t crc = (isar0 >> 16) & 0xf;
				uint32_t atomics = (isar0 >> 20) & 0xf;
				printf("  ID_AA64ISAR0:   0x%016llx (AES:%u SHA1:%u SHA2:%u CRC32:%u Atomics:%u)\n",
				       (unsigned long long)isar0, aes, sha1, sha2, crc, atomics);
			}
		}

		{
			uint64_t isar1 = read_arm64_sysreg(6, &ok);
			if (ok) {
				uint32_t dp = (isar1 >> 0) & 0xf;
				uint32_t fcma = (isar1 >> 16) & 0xf;
				uint32_t jscvt = (isar1 >> 20) & 0xf;
				printf("  ID_AA64ISAR1:   0x%016llx (DotProd:%u FCMA:%u JSCVT:%u)\n",
				       (unsigned long long)isar1, dp, fcma, jscvt);
			}
		}

		{
			uint64_t pfr0 = read_arm64_sysreg(7, &ok);
			if (ok) {
				uint32_t fp = (pfr0 >> 16) & 0xf;
				uint32_t advsimd = (pfr0 >> 20) & 0xf;
				uint32_t gic = (pfr0 >> 24) & 0xf;
				uint32_t csv2 = (pfr0 >> 56) & 0xf;
				printf("  ID_AA64PFR0:    0x%016llx (FP:%u AdvSIMD:%u GIC:%u SpectreCSV2:%u)\n",
				       (unsigned long long)pfr0, fp, advsimd, gic, csv2);
			}
		}

		{
			uint64_t mmfr0 = read_arm64_sysreg(8, &ok);
			if (ok) {
				uint32_t pa_range = mmfr0 & 0xf;
				const char *pa_str = "32-bit (4GB)";
				if (pa_range == 1) pa_str = "36-bit (64GB)";
				else if (pa_range == 2) pa_str = "40-bit (1TB)";
				else if (pa_range == 3) pa_str = "42-bit (4TB)";
				else if (pa_range == 4) pa_str = "44-bit (16TB)";
				else if (pa_range == 5) pa_str = "48-bit (256TB)";
				else if (pa_range == 6) pa_str = "52-bit (4PB)";
				printf("  ID_AA64MMFR0:   0x%016llx (Physical Address Width: %s)\n",
				       (unsigned long long)mmfr0, pa_str);
			}
		}

		{
			uint64_t cntfrq = read_arm64_sysreg(9, &ok);
			if (ok && cntfrq > 0)
				printf("  CNTFRQ_EL0:     0x%016llx (%.3f MHz Base Hardware Timer)\n",
				       (unsigned long long)cntfrq, (double)cntfrq / 1000000.0);
		}

		{
			uint64_t cntvct = read_arm64_sysreg(10, &ok);
			if (ok)
				printf("  CNTVCT_EL0:     0x%016llx (Live Hardware Virtual Cycle Counter)\n",
				       (unsigned long long)cntvct);
		}
	}
#else
	puts("  Platform:       x86_64 Emulation Mode (ARM64 inline assembly skipped)");
#endif

	puts("");
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 17: Disassembly Command
 * ============================================================================== */

static int do_disasm(int argc, char **argv)
{
	int i;
	uint64_t fake_pc = 0x1000;
	uint32_t last_insn = 0;

	if (argc < 3) {
		puts("Usage: socprobe disasm <HEX32_INSTRUCTION...>");
		puts("Example: socprobe disasm d5380000 d4000003 90000800 91000021 b9400000 d65f03c0");
		return EXIT_FAILURE;
	}

	puts("\n=== Pure AArch64 Machine-Code Disassembly ===");
	printf("%-16s  %-10s  %s\n", "ADDRESS", "OPCODE", "DISASSEMBLY");
	puts("-------------------------------------------------------------------------------");

	for (i = 2; i < argc; i++) {
		const char *hex_str = argv[i];
		uint32_t insn;
		char dis_buf[128];

		if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
			hex_str += 2;

		insn = (uint32_t)strtoul(hex_str, NULL, 16);
		disassemble_aarch64_insn(insn, fake_pc, dis_buf, sizeof(dis_buf));

		/* If this instruction is SMC #0 and previous instruction loaded X0, annotate with known call */
		if ((insn & 0xffe0001f) == 0xd4000003 && (last_insn & 0x7f800000) == 0x52800000) {
			/* MOV (wide immediate) into W0/X0: check if function ID matches */
			uint32_t imm16 = (last_insn >> 5) & 0xffff;
			const char *call_name = lookup_psci_tz_name(imm16);
			if (call_name)
				snprintf(dis_buf + strlen(dis_buf), sizeof(dis_buf) - strlen(dis_buf),
				         " [%s]", call_name);
		}

		printf("0x%012llx    %08x    %s\n", (unsigned long long)fake_pc, insn, dis_buf);
		fake_pc += 4;
		last_insn = insn;
	}

	puts("-------------------------------------------------------------------------------\n");
	return EXIT_SUCCESS;
}

/* ==============================================================================
 * Section 18: Status & Main Dispatcher
 * ============================================================================== */

static int do_status(void)
{
	puts("\n==================================================================");
	puts("  Pure In-Memory Mobile SoC Silicon Hardware & Machine Engine");
	puts("     (Zero /proc, Zero /sys, Zero /dev - 100% In-RAM Operation)");
	puts("==================================================================");

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

		{
			uint64_t el = read_arm64_sysreg(11, &ok);
			if (ok)
				printf("  Execution State:  EL%u (Exception Level)\n", (unsigned)((el >> 2) & 0x3));
		}

		{
			uint64_t cntfrq = read_arm64_sysreg(9, &ok);
			if (ok && cntfrq > 0)
				printf("  Hardware Crystal: %.3f MHz TCXO base\n", (double)cntfrq / 1000000.0);
		}

		{
			double core_mhz = measure_cpu_clock_mhz();
			if (core_mhz > 0.0)
				printf("  Live Core Clock:  %.1f MHz (assembly calibrated timing loop)\n", core_mhz);
		}
	}
#else
	puts("  Host Platform:    x86_64 Emulation Mode");
#endif

	printf("  MMIO Registers:   %lu In-Memory Hardware Silicon Block Windows\n",
	       (unsigned long)(sizeof(g_silicon_mmio) / sizeof(g_silicon_mmio[0])));
	puts("  PMIC Controller:  Qualcomm SPMI Arbiter v2 (0x01C40000 / 0x01E00000)");
	puts("  Power Regulators: 12 PMIC Buck/LDO Voltage Rails Defined in Silicon Engine");
	puts("  Clock Subsystem:  GCC & RPM Clock Tree, Root Generators (RCGR) & Branches (CBCR)");
	puts("  Silicon Aging:    CPR Adaptive Voltage Scaling & On-Die Ring Oscillators (ROSC)");
	puts("  Crypto Engine:    Qualcomm CE v5, BAM DMA, HWKM & Inline Crypto Engine (ICE)");
	puts("  AI Accelerators:  Hexagon Tensor Processor (HTP / HMX) & Adreno ML Units");
	puts("  Performance PMU:  ARMv8 Architectural Performance Monitor Counters (PMU)");
	puts("  ISP Subsystem:    Spectra Dual IFE, CSID/CSIPHY, 3D/Gamma/LSC LUTs Defined");
	puts("  Hexagon DSPs:     aDSP (Audio), cDSP (NPU Tensor AI HVX/HMX), mDSP (Modem)");
	puts("  Audio Routing:    LPASS ARDP, Soundwire Digital Bus & SLIMbus Arbiter");
	puts("  Network Offload:  IPA (IP Accelerator Hardware Router & GSI DMA Engine)");
	puts("  NoC Interconnect: SNOC, CNOC, MMNOC, BIMC QoS Traffic Arbiters & BWMON");
	puts("  Analog Probing:   PMIC VADC/ADC5 16-bit Sigma-Delta Multichannel ADC");

	puts("\nAvailable Diagnostic Subcommands (Zero Filesystem Required):");
	puts("  socprobe cpu       Audit architectural ARM64 registers via inline assembly");
	puts("  socprobe pll       Hardware TCXO frequency & assembly cycle calibration");
	puts("  socprobe clock     GCC/RPM clock tree, RCGR dividers & CBCR branch registers");
	puts("  socprobe pmic      Qualcomm SPMI PMIC register map (LDO, Buck, PON, FG)");
	puts("  socprobe volt      PMIC voltage DAC steps, current, and power formulas");
	puts("  socprobe psci      PSCI & TrustZone/QSEE SMC call registers & function IDs");
	puts("  socprobe isp       Spectra ISP hardware, CSID/CSIPHY, and LUT registers");
	puts("  socprobe dsp       Hexagon DSPs (aDSP, cDSP HVX/HMX), IPA network offloader");
	puts("  socprobe ardp      Audio Routing DSP (ARDP), Soundwire & SLIMbus registers");
	puts("  socprobe adc       PMIC VADC/ADC5 analog-to-digital converter channels");
	puts("  socprobe noc       System NoC interconnects, QoS arbiters & BWMON monitors");
	puts("  socprobe smi       System Management Interface, SPMI & IPC mailbox registers");
	puts("  socprobe rosc      Silicon Ring Oscillators, Aging & CPR/TSENS sensors");
	puts("  socprobe crypto    Qualcomm Crypto Engine v5, HWKM & ICE registers");
	puts("  socprobe ai        Hexagon Tensor Processor, HMX matrix & AI accelerators");
	puts("  socprobe pmu       ARMv8 PMU hardware performance counter registers");
	puts("  socprobe mmio      In-memory physical MMIO peripheral register map");
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
	if (strcmp(cmd, "cpu") == 0)
		return do_cpu();
	if (strcmp(cmd, "pll") == 0)
		return do_pll();
	if (strcmp(cmd, "clock") == 0 || strcmp(cmd, "clocks") == 0 || strcmp(cmd, "clk") == 0)
		return do_clock();
	if (strcmp(cmd, "pmic") == 0)
		return do_pmic();
	if (strcmp(cmd, "volt") == 0 || strcmp(cmd, "power") == 0)
		return do_volt();
	if (strcmp(cmd, "psci") == 0 || strcmp(cmd, "tz") == 0)
		return do_psci();
	if (strcmp(cmd, "isp") == 0 || strcmp(cmd, "camera") == 0)
		return do_isp();
	if (strcmp(cmd, "dsp") == 0)
		return do_dsp();
	if (strcmp(cmd, "ardp") == 0 || strcmp(cmd, "soundwire") == 0)
		return do_ardp();
	if (strcmp(cmd, "adc") == 0 || strcmp(cmd, "a2d") == 0)
		return do_adc();
	if (strcmp(cmd, "noc") == 0 || strcmp(cmd, "traffic") == 0)
		return do_noc();
	if (strcmp(cmd, "smi") == 0 || strcmp(cmd, "ipc") == 0)
		return do_smi();
	if (strcmp(cmd, "rosc") == 0 || strcmp(cmd, "ring") == 0 || strcmp(cmd, "cpr") == 0)
		return do_rosc();
	if (strcmp(cmd, "crypto") == 0 || strcmp(cmd, "ce") == 0)
		return do_crypto();
	if (strcmp(cmd, "ai") == 0 || strcmp(cmd, "npu") == 0 || strcmp(cmd, "htp") == 0)
		return do_ai();
	if (strcmp(cmd, "pmu") == 0 || strcmp(cmd, "perf") == 0)
		return do_pmu();
	if (strcmp(cmd, "mmio") == 0)
		return do_mmio(argc > 2 ? argv[2] : NULL);
	if (strcmp(cmd, "disasm") == 0)
		return do_disasm(argc, argv);

	bb_show_usage();
	return EXIT_FAILURE;
}
