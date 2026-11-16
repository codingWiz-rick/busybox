/* vi: set sw=4 ts=4: */
/*
 * magiskboot_patch.c — Direct Kernel Security & Module Vermagic Patching Engine
 *
 * Implements direct kernel security neutralization (CONFIG_MODULE_SIG_FORCE,
 * KCFI, Forward-Edge CFI, SELinux permissive, Samsung RKP) and module vermagic /
 * ELF relocation patchers for magiskboot.
 *
 * Included directly into archival/magiskboot.c translation unit.
 * Conforms to Linux Kernel Coding Style & ISO C99/C11 standards.
 */

/* =========================================================================
 * 10. Direct Kernel Security & Manipulation Engine
 * ========================================================================= */

static inline uint32_t arm64_read_u32(const uint8_t *buf, size_t off) {
	return (uint32_t)buf[off] |
	       ((uint32_t)buf[off + 1] << 8) |
	       ((uint32_t)buf[off + 2] << 16) |
	       ((uint32_t)buf[off + 3] << 24);
}

static inline void arm64_write_u32(uint8_t *buf, size_t off, uint32_t val) {
	buf[off]     = (uint8_t)(val & 0xff);
	buf[off + 1] = (uint8_t)((val >> 8) & 0xff);
	buf[off + 2] = (uint8_t)((val >> 16) & 0xff);
	buf[off + 3] = (uint8_t)((val >> 24) & 0xff);
}

static inline int64_t arm64_decode_adrp_imm(uint32_t adrp_insn) {
	int64_t immlo = (int64_t)((adrp_insn >> 29) & 0x3U);
	int64_t immhi = (int64_t)((adrp_insn >> 5) & 0x7ffffU);
	int64_t imm = (immhi << 2) | immlo;
	if (imm & (1LL << 20))
		imm -= (1LL << 21);
	return imm;
}

static inline bool arm64_decode_adrp(uint32_t insn, uint64_t pc, int *rd, uint64_t *page_addr) {
	if ((insn & ARM64_ADRP_MASK) != ARM64_ADRP_VAL)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);

	if (page_addr) {
		int64_t imm = arm64_decode_adrp_imm(insn);
		*page_addr = (pc & ~0xfffULL) + (uint64_t)(imm << 12);
	}
	return true;
}

static inline bool arm64_decode_ldr_imm(uint32_t insn, int *rt, int *rn,
                                        int32_t *offset, int *size, bool *is_signed) {
	uint32_t u_cls = insn & 0x3fc00000U;
	uint32_t s_cls;

	if (u_cls == 0x39400000U || u_cls == 0x39800000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = (int32_t)(((insn >> 10) & 0xfffU) * sz);
		if (size) *size = sz;
		if (is_signed) *is_signed = (u_cls == 0x39800000U);
		return true;
	}

	s_cls = insn & 0x3fe00c00U;
	if (s_cls == 0x38400000U || s_cls == 0x38800000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		int32_t simm9 = (int32_t)((insn >> 12) & 0x1ffU);
		if (simm9 & 0x100U)
			simm9 |= ~0x1ff;
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = simm9;
		if (size) *size = sz;
		if (is_signed) *is_signed = (s_cls == 0x38800000U);
		return true;
	}

	return false;
}

static inline bool arm64_decode_str_imm(uint32_t insn, int *rt, int *rn,
                                        int32_t *offset, int *size) {
	if ((insn & 0x3fc00000U) == 0x39000000U) {
		int sz = 1 << ((insn >> 30) & 0x3);
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = (int32_t)(((insn >> 10) & 0xfffU) * sz);
		if (size) *size = sz;
		return true;
	}
	return false;
}

static inline bool arm64_decode_cbz(uint32_t insn, uint64_t pc, int *rt,
                                    bool *is_cbnz, bool *is_64bit, uint64_t *target) {
	if ((insn & 0x7e000000U) != 0x34000000U)
		return false;

	if (rt) *rt = (int)(insn & 0x1fU);
	if (is_cbnz) *is_cbnz = ((insn & (1U << 24)) != 0);
	if (is_64bit) *is_64bit = ((insn & (1U << 31)) != 0);

	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18))
			imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool arm64_decode_b_bl(uint32_t insn, uint64_t pc, bool *is_bl, uint64_t *target) {
	if ((insn & 0x7c000000U) != 0x14000000U)
		return false;

	if (is_bl) *is_bl = ((insn & 0x80000000U) != 0);

	if (target) {
		int64_t imm26 = (int64_t)(insn & 0x03ffffffU);
		if (imm26 & (1LL << 25))
			imm26 -= (1LL << 26);
		*target = pc + (uint64_t)(imm26 << 2);
	}
	return true;
}

static inline bool arm64_decode_blr(uint32_t insn, int *rn) {
	if ((insn & 0xfffffc1fU) == 0xd63f0000U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		return true;
	}
	return false;
}

static inline bool arm64_decode_blr_auth(uint32_t insn, int *rn, bool *use_b_key, bool *use_zero) {
	if ((insn & 0xffff0800U) == 0xd73f0800U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (use_b_key) *use_b_key = ((insn >> 10) & 1) != 0;
		if (use_zero) *use_zero = (insn & 0x1fU) == 31;
		return true;
	}
	return false;
}

static inline bool arm64_decode_mov_wide(uint32_t insn, int *rd, uint16_t *imm16,
                                         int *shift, int *opcode) {
	if ((insn & 0x1f800000U) != 0x12800000U)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);
	if (imm16) *imm16 = (uint16_t)((insn >> 5) & 0xffffU);
	if (shift) *shift = (int)(((insn >> 21) & 0x3U) * 16);
	if (opcode) *opcode = (int)((insn >> 29) & 0x3U);
	return true;
}

static inline bool arm64_decode_add_sub_imm(uint32_t insn, int *rd, int *rn,
                                            uint32_t *imm, bool *is_sub, bool *is_64bit) {
	if ((insn & 0x1f000000U) != 0x11000000U)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);
	if (rn) *rn = (int)((insn >> 5) & 0x1fU);
	if (is_sub) *is_sub = ((insn & (1U << 30)) != 0);
	if (is_64bit) *is_64bit = ((insn & (1U << 31)) != 0);

	if (imm) {
		uint32_t val = (insn >> 10) & 0xfffU;
		if (insn & (1U << 22))
			val <<= 12;
		*imm = val;
	}
	return true;
}

static inline bool arm64_decode_tbz(uint32_t insn, uint64_t pc, int *rt,
                                    int *bit_pos, bool *is_tbnz, uint64_t *target) {
	if ((insn & 0x7e000000U) != 0x36000000U)
		return false;

	if (rt) *rt = (int)(insn & 0x1fU);
	if (is_tbnz) *is_tbnz = ((insn & (1U << 24)) != 0);

	if (bit_pos) {
		uint32_t b5 = (insn >> 31) & 0x1U;
		uint32_t b40 = (insn >> 19) & 0x1fU;
		*bit_pos = (int)((b5 << 5) | b40);
	}

	if (target) {
		int64_t imm14 = (int64_t)((insn >> 5) & 0x3fffU);
		if (imm14 & (1LL << 13))
			imm14 -= (1LL << 14);
		*target = pc + (uint64_t)(imm14 << 2);
	}
	return true;
}

static inline bool arm64_decode_ldp_stp(uint32_t insn, int *rt, int *rt2, int *rn,
                                        int32_t *offset, bool *is_load, bool *is_64bit) {
	bool sf;

	if ((insn & 0x3a000000U) != 0x28000000U)
		return false;

	if (rt) *rt = (int)(insn & 0x1fU);
	if (rn) *rn = (int)((insn >> 5) & 0x1fU);
	if (rt2) *rt2 = (int)((insn >> 10) & 0x1fU);
	if (is_load) *is_load = ((insn & (1U << 22)) != 0);

	sf = ((insn & (1U << 31)) != 0);
	if (is_64bit) *is_64bit = sf;

	if (offset) {
		int scale = sf ? 8 : 4;
		int32_t imm7 = (int32_t)((insn >> 15) & 0x7fU);
		if (imm7 & 0x40)
			imm7 |= ~0x7f;
		*offset = imm7 * scale;
	}
	return true;
}

static inline bool arm64_decode_ret(uint32_t insn, int *rn, bool *is_auth) {
	if ((insn & 0xfffffc1fU) == 0xd65f0000U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (is_auth) *is_auth = false;
		return true;
	}
	if ((insn & 0xfffffbffU) == 0xd65f0bffU) {
		if (rn) *rn = 30; /* LR */
		if (is_auth) *is_auth = true;
		return true;
	}
	return false;
}

static inline bool arm64_decode_pac_bti(uint32_t insn, bool *is_pac, bool *is_bti) {
	if ((insn & 0xfffff01fU) == 0xd503201fU) {
		uint32_t crm_op2 = (insn >> 5) & 0x7fU;
		if (crm_op2 == 0x19 || crm_op2 == 0x1b || crm_op2 == 0x07) {
			if (is_pac) *is_pac = true;
			if (is_bti) *is_bti = false;
			return true;
		}
		if (crm_op2 == 0x22 || crm_op2 == 0x24 || crm_op2 == 0x26) {
			if (is_pac) *is_pac = false;
			if (is_bti) *is_bti = true;
			return true;
		}
	}
	return false;
}

static inline bool arm64_decode_mrs_sp_el0(uint32_t insn, int *rt) {
	if ((insn & 0xffffffe0U) == 0xd5384100U) {
		if (rt) *rt = (int)(insn & 0x1fU);
		return true;
	}
	return false;
}

static inline uint64_t arm64_peel_branch(const uint8_t *data, size_t size, uint64_t pc, int max_depth) {
	uint64_t cur = pc;
	int d;
	bool is_bl;
	uint64_t branch_target;

	for (d = 0; d < max_depth && cur + 4 <= size; d++) {
		uint32_t insn = *(const uint32_t *)(data + cur);
		bool is_pac = false, is_bti = false;
		if (arm64_decode_pac_bti(insn, &is_pac, &is_bti)) {
			cur += 4;
			continue;
		}
		is_bl = false;
		branch_target = 0;
		if (arm64_decode_b_bl(insn, cur, &is_bl, &branch_target) && !is_bl) {
			if (branch_target + 4 <= size && branch_target != cur) {
				cur = branch_target;
				continue;
			}
		}
		break;
	}
	return cur;
}

static inline bool arm64_decode_adr(uint32_t insn, uint64_t pc, int *rd, uint64_t *target_addr) {
	if ((insn & 0x9f000000U) != 0x10000000U)
		return false;

	if (rd) *rd = (int)(insn & 0x1fU);

	if (target_addr) {
		int64_t immlo = (int64_t)((insn >> 29) & 0x3U);
		int64_t immhi = (int64_t)((insn >> 5) & 0x7ffffU);
		int64_t imm = (immhi << 2) | immlo;
		if (imm & (1LL << 20))
			imm -= (1LL << 21);
		*target_addr = pc + (uint64_t)imm;
	}
	return true;
}

static inline bool arm64_decode_brk(uint32_t insn, uint16_t *imm16) {
	if ((insn & 0xffe0001fU) == 0xd4200000U) {
		if (imm16) *imm16 = (uint16_t)((insn >> 5) & 0xffffU);
		return true;
	}
	return false;
}

static inline bool arm64_decode_sysreg_mrs_msr(uint32_t insn, bool *is_mrs, int *rt, uint16_t *sysreg_id) {
	if ((insn & 0xffd00000U) != 0xd5100000U)
		return false;

	if (is_mrs) *is_mrs = ((insn & 0x00200000U) != 0);
	if (rt) *rt = (int)(insn & 0x1fU);
	if (sysreg_id) *sysreg_id = (uint16_t)((insn >> 5) & 0xffffU);
	return true;
}

static inline bool arm64_decode_uaccess(uint32_t insn, bool *is_load, int *rt, int *rn,
                                        int32_t *offset, int *size) {
	uint32_t cls = insn & 0x3fc00c00U;
	int sz;

	if (cls != 0x38400800U && cls != 0x38000800U)
		return false;

	if (is_load) *is_load = (cls == 0x38400800U);
	if (rt) *rt = (int)(insn & 0x1fU);
	if (rn) *rn = (int)((insn >> 5) & 0x1fU);

	sz = 1 << ((insn >> 30) & 0x3);
	if (size) *size = sz;

	if (offset) {
		int32_t simm9 = (int32_t)((insn >> 12) & 0x1ffU);
		if (simm9 & 0x100)
			simm9 |= ~0x1ff;
		*offset = simm9;
	}
	return true;
}

static inline bool arm64_decode_b_cond(uint32_t insn, uint64_t pc, int *cond, uint64_t *target) {
	if ((insn & 0xff000010U) != 0x54000000U)
		return false;

	if (cond) *cond = (int)(insn & 0x0fU);

	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18))
			imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool arm64_decode_cmp_imm(uint32_t insn, int *rn, uint32_t *imm, bool *is_64bit) {
	if ((insn & 0x3f80001fU) != 0x3100001fU)
		return false;

	if (is_64bit) *is_64bit = ((insn & (1U << 31)) != 0);
	if (rn) *rn = (int)((insn >> 5) & 0x1fU);

	if (imm) {
		uint32_t shift = (insn >> 22) & 1U;
		uint32_t imm12 = (insn >> 10) & 0xfffU;
		*imm = imm12 << (shift ? 12 : 0);
	}
	return true;
}

/**
 * kroot_elf_locate_kernel_payload - Dynamically locate uncompressed ARM64 kernel within a buffer
 */
static int kroot_elf_locate_kernel_payload(const uint8_t *buf, size_t buf_size,
                                           const uint8_t **out_payload, size_t *out_payload_size) {
	const arm64_image_header_t *arm64_hdr;
	size_t scan_limit;
	size_t off;

	if (!buf || buf_size < sizeof(arm64_image_header_t) || !out_payload || !out_payload_size)
		return -EINVAL;

	/* 1. Direct ARM64 kernel Image detection */
	arm64_hdr = (const arm64_image_header_t *)buf;
	if (arm64_hdr->magic == ARM64_IMAGE_MAGIC) {
		*out_payload = buf;
		*out_payload_size = (arm64_hdr->image_size > 0 && arm64_hdr->image_size <= buf_size) ?
			(size_t)arm64_hdr->image_size : buf_size;
		return 0;
	}

	/* 2. Android boot.img header detection (v0 - v4) */
	if (buf_size >= sizeof(struct boot_img_hdr_v0) && memcmp(buf, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
		const struct boot_img_hdr_v0 *v0 = (const struct boot_img_hdr_v0 *)buf;
		size_t k_off = 0;
		size_t k_sz = 0;

		if (v0->header_version >= 3) {
			const struct boot_img_hdr_v3 *v3 = (const struct boot_img_hdr_v3 *)buf;
			k_off = 4096;
			k_sz = v3->kernel_size;
		} else {
			size_t page_sz = (v0->page_size >= 2048 && (v0->page_size & (v0->page_size - 1)) == 0) ?
				v0->page_size : 2048;
			k_off = page_sz;
			k_sz = v0->kernel_size;
		}

		if (k_off < buf_size) {
			const uint8_t *k_start = buf + k_off;
			size_t max_avail = buf_size - k_off;
			size_t actual_sz = (k_sz > 0 && k_sz <= max_avail) ? k_sz : max_avail;

			if (actual_sz >= sizeof(arm64_image_header_t)) {
				const arm64_image_header_t *inner_hdr = (const arm64_image_header_t *)k_start;
				if (inner_hdr->magic == ARM64_IMAGE_MAGIC) {
					*out_payload = k_start;
					*out_payload_size = (inner_hdr->image_size > 0 && inner_hdr->image_size <= actual_sz) ?
						(size_t)inner_hdr->image_size : actual_sz;
					return 0;
				}
			}

			*out_payload = k_start;
			*out_payload_size = actual_sz;
			return 0;
		}
	}

	/* 3. Dynamic scan: search for canonical ARM64 Image magic on 64-byte aligned boundaries */
	scan_limit = (buf_size > 64 * 1024 * 1024) ? (64 * 1024 * 1024) : buf_size;
	for (off = 0; off + sizeof(arm64_image_header_t) <= scan_limit; off += 64) {
		const arm64_image_header_t *cand = (const arm64_image_header_t *)(buf + off);
		if (cand->magic == ARM64_IMAGE_MAGIC && cand->image_size > 0 && off + cand->image_size <= buf_size) {
			*out_payload = buf + off;
			*out_payload_size = (size_t)cand->image_size;
			return 0;
		}
	}

	*out_payload = buf;
	*out_payload_size = buf_size;
	return 0;
}

static bool patch_sigenforce_buf(uint8_t *buf, size_t size, int *out_checks, int *out_setters) {
	size_t sig_enforce_offset = (size_t)-1;
	int patched_checks = 0;
	int neutralized_setters = 0;
	size_t limit;
	size_t i, j, k;
	uint8_t old_val;
	uint64_t target_page;
	uint32_t target_off;
	const uint8_t *k_payload = NULL;
	size_t k_payload_sz = 0;
	size_t k_off = 0;
	size_t k_sz = size;
	uint32_t inst0, inst1, inst2, inst3;
	int mov_rd, mov_shift, mov_opc;
	uint16_t mov_imm;
	bool is_errno_mov;
	int cbz_reg;
	bool is_cbnz, is_64bit;
	int ldr_rt, ldr_rn, ldr_sz;
	int32_t ldr_off;
	bool is_signed;
	int adrp_rd;
	uint64_t page_addr;
	size_t target_addr;
	int str_rt, str_rn, str_sz;
	int32_t str_off;
	int add_rd, add_rn;
	uint32_t add_imm;
	bool is_sub;
	int s2_rt, s2_rn, s2_sz;
	int32_t s2_off;

	if (!buf || size < 64) return false;

	if (kroot_elf_locate_kernel_payload(buf, size, &k_payload, &k_payload_sz) == 0 && k_payload) {
		k_off = (size_t)(k_payload - buf);
		k_sz = k_payload_sz;
	}

	limit = (k_sz >= 16) ? (k_sz - 16) : 0;
	for (i = 0; i < limit; i += 4) {
		inst3 = arm64_read_u32(buf, k_off + i + 12);
		is_errno_mov = false;

		if (arm64_decode_mov_wide(inst3, &mov_rd, &mov_imm, &mov_shift, &mov_opc) &&
		    mov_opc == 0 && mov_shift == 0) {
			if (mov_imm == 125 || mov_imm == 128) is_errno_mov = true;
		}
		if (!is_errno_mov && (inst3 & 0x7fffffe0U) == 0x12800fa0U) {
			is_errno_mov = true;
		}
		if (!is_errno_mov) continue;

		inst2 = arm64_read_u32(buf, k_off + i + 8);
		if (!arm64_decode_cbz(inst2, (uint64_t)(i + 8), &cbz_reg, &is_cbnz, &is_64bit, NULL) || is_cbnz)
			continue;

		inst1 = arm64_read_u32(buf, k_off + i + 4);
		if (!arm64_decode_ldr_imm(inst1, &ldr_rt, &ldr_rn, &ldr_off, &ldr_sz, &is_signed) ||
		    ldr_rt != cbz_reg || ldr_sz != 1)
			continue;

		inst0 = arm64_read_u32(buf, k_off + i);
		if (!arm64_decode_adrp(inst0, (uint64_t)i, &adrp_rd, &page_addr) || adrp_rd != ldr_rn)
			continue;

		target_addr = (size_t)(page_addr + (uint32_t)ldr_off);
		if (target_addr < k_sz) {
			uint32_t mov_wzr = ARM64_MOV_W0_WZR_OPCODE | (uint32_t)cbz_reg;
			sig_enforce_offset = target_addr;
			arm64_write_u32(buf, k_off + i + 4, mov_wzr);
			fprintf(stderr, "[+] Found inlined module_sig_check @ image 0x%08zX (file 0x%08zX)\n", i, k_off + i);
			fprintf(stderr, "[+] Patched check @ image 0x%08zX to MOV w%d, wzr (0x%08X)\n", i + 4, cbz_reg, mov_wzr);
			patched_checks++;
			break;
		}
	}

	if (sig_enforce_offset == (size_t)-1) {
		for (i = 0; i + 20 <= size; i++) {
			if (memcmp(buf + i, "module.sig_enforce=1", 20) == 0) {
				buf[i + 19] = '0';
				fprintf(stderr, "[+] Patched 'module.sig_enforce=1' -> '0' @ 0x%08zX\n", i);
				patched_checks++;
			}
		}
		if (out_checks) *out_checks = patched_checks;
		if (out_setters) *out_setters = 0;
		return (patched_checks > 0);
	}

	old_val = buf[k_off + sig_enforce_offset];
	buf[k_off + sig_enforce_offset] = 0x00;
	fprintf(stderr, "[+] Cleared sig_enforce variable in .data: 0x%02X -> 0x00\n", old_val);

	target_page = (uint64_t)(sig_enforce_offset & ~0xfffULL);
	target_off = (uint32_t)(sig_enforce_offset & 0xfffULL);

	for (i = 0; i < limit; i += 4) {
		inst0 = arm64_read_u32(buf, k_off + i);

		if (!arm64_decode_adrp(inst0, (uint64_t)i, &adrp_rd, &page_addr) || page_addr != target_page)
			continue;

		for (j = 1; j <= 4; j++) {
			if (i + j * 4 >= k_sz) break;
			inst1 = arm64_read_u32(buf, k_off + i + j * 4);

			/* Case 1: Direct single-instruction store: STRB wT, [xN, #target_off] */
			if (arm64_decode_str_imm(inst1, &str_rt, &str_rn, &str_off, &str_sz) &&
			    str_rn == adrp_rd && str_sz == 1 && (uint32_t)str_off == target_off) {
				arm64_write_u32(buf, k_off + i + j * 4, ARM64_NOP_OPCODE);
				fprintf(stderr, "[+] Neutralized runtime setter (STRB) @ image 0x%08zX (file 0x%08zX) -> NOP\n",
				        i + j * 4, k_off + i + j * 4);
				neutralized_setters++;
			}

			/* Case 2: Two-instruction store: ADD xM, xN, #target_off ... STRB wT, [xM, #0] */
			if (arm64_decode_add_sub_imm(inst1, &add_rd, &add_rn, &add_imm, &is_sub, &is_64bit) &&
			    !is_sub && add_rn == adrp_rd && add_imm == target_off) {
				for (k = j + 1; k <= j + 3; k++) {
					if (i + k * 4 >= k_sz) break;
					inst2 = arm64_read_u32(buf, k_off + i + k * 4);
					if (arm64_decode_str_imm(inst2, &s2_rt, &s2_rn, &s2_off, &s2_sz) &&
					    s2_rn == add_rd && s2_sz == 1 && s2_off == 0) {
						arm64_write_u32(buf, k_off + i + k * 4, ARM64_NOP_OPCODE);
						fprintf(stderr, "[+] Neutralized runtime setter (ADD+STRB) @ image 0x%08zX (file 0x%08zX) -> NOP\n",
						        i + k * 4, k_off + i + k * 4);
						neutralized_setters++;
					}
				}
			}
		}
	}

	for (i = 0; i + 20 <= size; i++) {
		if (memcmp(buf + i, "module.sig_enforce=1", 20) == 0) {
			buf[i + 19] = '0';
			fprintf(stderr, "[+] Patched 'module.sig_enforce=1' -> '0' @ 0x%08zX\n", i);
		}
	}

	if (out_checks) *out_checks = patched_checks;
	if (out_setters) *out_setters = neutralized_setters;
	return true;
}

static bool patch_cfi_buf(uint8_t *buf, size_t size, int *out_kcfi, int *out_legacy) {
	int kcfi_count = 0;
	int legacy_count = 0;
	size_t limit;
	size_t i, j, p;

	if (!buf || size < 32) return false;

	/* Phase 1: KCFI Detection & Neutralization (Linux 6.1, 6.6, Mainline) */
	limit = size - 16;
	for (i = 0; i < limit; i += 4) {
		uint32_t inst0 = arm64_read_u32(buf, i);
		if (inst0 == ARM64_CMP_W0_1) {
			uint32_t inst1 = arm64_read_u32(buf, i + 4);
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			uint32_t inst3 = arm64_read_u32(buf, i + 12);

			if (inst1 == ARM64_B_EQ_40 && inst2 == ARM64_CMP_W0_2) {
				if (inst3 == ARM64_B_TO_SKIP) {
					fprintf(stderr, "[*] KCFI cfi_handler @ 0x%08zX already neutralized\n", i);
					kcfi_count++;
				} else if (inst3 == ARM64_B_EQ_12) {
					arm64_write_u32(buf, i + 12, ARM64_B_TO_SKIP);
					fprintf(stderr, "[+] Neutralized KCFI die branch @ 0x%08zX: B.EQ -> B +32 (skip faulting instruction)\n", i + 12);
					kcfi_count++;
				}
			}
		}
	}

	/* Phase 2: Legacy Forward-Edge CFI Detection & Neutralization (Linux 4.19, 5.10) */
	for (j = 0; j < limit; j += 4) {
		uint32_t inst_brk = arm64_read_u32(buf, j + 12);
		if (inst_brk == ARM64_BRK_800 || inst_brk == ARM64_NOP_OPCODE) {
			uint32_t inst_bl = arm64_read_u32(buf, j + 8);
			uint32_t inst_mov = arm64_read_u32(buf, j + 4);

			if ((inst_bl & ARM64_BL_MASK) == ARM64_BL_VAL && inst_mov == ARM64_MOV_X1_X19) {
				bool is_cfi_context = false;
				for (p = 1; p <= 8; p++) {
					size_t pc_off = p * 4;
					if (j >= pc_off) {
						uint32_t prev = arm64_read_u32(buf, j - pc_off);
						int rd;
						uint64_t target_page;
						if (arm64_decode_adrp(prev, (uint64_t)(j - pc_off), &rd, &target_page)) {
							if (target_page < size) {
								size_t chk_end = (target_page + 4096 < size) ? (target_page + 4096) : size;
								size_t s;
								for (s = target_page; s + 11 <= chk_end; s++) {
									if (memcmp(buf + s, "CFI failure", 11) == 0 ||
									    memcmp(buf + s, "cfi_failure", 11) == 0) {
										is_cfi_context = true;
										break;
									}
								}
								if (is_cfi_context) break;
							}
						}
					}
				}

				if (is_cfi_context) {
					if (inst_brk == ARM64_NOP_OPCODE) {
						fprintf(stderr, "[*] Legacy CFI BUG trap @ 0x%08zX already neutralized\n", j + 12);
						legacy_count++;
					} else {
						arm64_write_u32(buf, j + 12, ARM64_NOP_OPCODE);
						fprintf(stderr, "[+] Neutralized Legacy Forward-Edge CFI BUG trap @ 0x%08zX: BRK #0x800 -> NOP\n", j + 12);
						legacy_count++;
					}
				}
			}
		}
	}

	if (out_kcfi) *out_kcfi = kcfi_count;
	if (out_legacy) *out_legacy = legacy_count;
	return (kcfi_count + legacy_count > 0);
}

static bool patch_selinux_permissive(uint8_t *buf, size_t size) {
	bool modified = false;
	size_t i;
	static const char p1_from[] = "androidboot.selinux=enforcing";
	static const char p1_to[]   = "androidboot.selinux=permissive";
	static const char p2_from[] = "selinux_enforcing=1";
	static const char p2_to[]   = "selinux_enforcing=0";

	for (i = 0; i + sizeof(p1_from) - 1 <= size; i++) {
		if (memcmp(buf + i, p1_from, sizeof(p1_from) - 1) == 0) {
			memcpy(buf + i, p1_to, sizeof(p1_to) - 1);
			buf[i + sizeof(p1_to) - 1] = '\0';
			fprintf(stderr, "[+] Patched 'androidboot.selinux=enforcing' -> 'permissive' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	for (i = 0; i + sizeof(p2_from) - 1 <= size; i++) {
		if (memcmp(buf + i, p2_from, sizeof(p2_from) - 1) == 0) {
			memcpy(buf + i, p2_to, sizeof(p2_to) - 1);
			fprintf(stderr, "[+] Patched 'selinux_enforcing=1' -> '0' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	return modified;
}

static bool patch_samsung_rkp(uint8_t *buf, size_t size) {
	bool modified = false;
	size_t i;
	for (i = 0; i + 8 <= size; i++) {
		if (memcmp(buf + i, "rkp_init", 8) == 0) {
			memcpy(buf + i, "rkp_skip", 8);
			fprintf(stderr, "[+] Patched Samsung RKP 'rkp_init' -> 'rkp_skip' @ 0x%08zX\n", i);
			modified = true;
		}
	}
	return modified;
}

static void scan_kcfi_hashes(const uint8_t *buf, size_t size) {
	size_t count = 0;
	size_t i, step;

	if (!buf || size < 16) return;

	printf("====================================================\n");
	printf("  ARM64 KCFI Call Site & Type Hash Inspector\n");
	printf("====================================================\n");

	for (i = 0; i + 4 <= size; i += 4) {
		uint32_t inst = arm64_read_u32(buf, i);
		if ((inst & 0xffe0001fU) == 0xd4200000U) {
			uint32_t imm16 = (inst >> 5) & 0xffffU;
			if ((imm16 & 0x8000U) == 0x8000U) {
				uint8_t target_reg = (uint8_t)(imm16 & 0x1fU);
				uint8_t type_reg = (uint8_t)((imm16 >> 5) & 0x1fU);
				uint16_t low_imm = 0, high_imm = 0;
				bool has_low = false, has_high = false;
				size_t scan_steps = (i / 4 < 16) ? (i / 4) : 16;

				for (step = 1; step <= scan_steps; step++) {
					uint32_t pinst = arm64_read_u32(buf, i - step * 4);
					int mrd, mshift, mopc;
					uint16_t mimm;
					if (arm64_decode_mov_wide(pinst, &mrd, &mimm, &mshift, &mopc)) {
						if ((uint8_t)mrd == type_reg && (mopc == 2 || mopc == 3)) {
							if (mshift == 0) { low_imm = mimm; has_low = true; }
							else if (mshift == 16) { high_imm = mimm; has_high = true; }
						}
					}
					if (has_low && has_high) break;
				}

				if (has_low && has_high) {
					uint32_t hash = ((uint32_t)high_imm << 16) | (uint32_t)low_imm;
					printf("  [+] Call site @ 0x%08zX: KCFI hash 0x%08x (type=w%u, target=x%u)\n",
					       i, hash, type_reg, target_reg);
					count++;
				}
			}
		}
	}
	printf("====================================================\n");
	printf("[+] Total KCFI call sites discovered: %zu\n", count);
}

static void kernel_status_buf(const uint8_t *buf, size_t size, const char *name) {
	const char *banner = NULL;
	size_t i;
	int kcfi_count = 0;
	bool has_sig_check = false;
	bool sig_neutralized = false;
	bool selinux_permissive = false;
	bool rkp_patched = false;

	printf("====================================================\n");
	printf("  Kernel Security & Image Status: %s\n", name);
	printf("====================================================\n");
	printf("Kernel Payload Size: %zu bytes (%.2f MB)\n", size, (double)size / (1024.0 * 1024.0));

	if (size >= sizeof(struct arm64_image_header)) {
		const struct arm64_image_header *hdr = (const struct arm64_image_header *)buf;
		if (hdr->magic == ARM64_IMAGE_MAGIC) {
			printf("Architecture:        ARM64 (magic 'ARM\\x64')\n");
			printf("Text Offset:         0x%lx\n", (unsigned long)hdr->text_offset);
			printf("Image Size:          0x%lx (%lu bytes)\n", (unsigned long)hdr->image_size, (unsigned long)hdr->image_size);
			printf("Flags:               0x%lx\n", (unsigned long)hdr->flags);
		}
	}

	for (i = 0; i + 14 <= size; i++) {
		if (memcmp(buf + i, "Linux version ", 14) == 0) {
			banner = (const char *)(buf + i);
			break;
		}
	}
	if (banner) {
		char bstr[128];
		size_t blen = 0;
		while (blen < sizeof(bstr) - 1 && banner[blen] && banner[blen] != '\n' && banner[blen] != '\r') blen++;
		memcpy(bstr, banner, blen);
		bstr[blen] = '\0';
		printf("Kernel Banner:       %s\n", bstr);
	}

	for (i = 0; i + 16 <= size; i += 4) {
		uint32_t inst3 = arm64_read_u32(buf, i + 12);
		if ((inst3 & 0x7fffffe0U) == 0x12800fa0U) {
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			if ((inst2 & ARM64_CBZ_MASK) == ARM64_CBZ_VAL) {
				uint32_t inst1 = arm64_read_u32(buf, i + 4);
				has_sig_check = true;
				if ((inst1 & 0xffffffe0U) == ARM64_MOV_W0_WZR_OPCODE) {
					sig_neutralized = true;
				}
				break;
			}
		}
	}
	if (has_sig_check) {
		printf("Module Sig Enforce:  %s\n", sig_neutralized ? "NEUTRALIZED (MOV wzr)" : "ACTIVE (enforcing)");
	} else {
		printf("Module Sig Enforce:  NOT PRESENT / INACTIVE\n");
	}

	for (i = 0; i + 16 <= size; i += 4) {
		uint32_t inst0 = arm64_read_u32(buf, i);
		if (inst0 == ARM64_CMP_W0_1) {
			uint32_t inst1 = arm64_read_u32(buf, i + 4);
			uint32_t inst2 = arm64_read_u32(buf, i + 8);
			uint32_t inst3 = arm64_read_u32(buf, i + 12);
			if (inst1 == ARM64_B_EQ_40 && inst2 == ARM64_CMP_W0_2) {
				if (inst3 == ARM64_B_TO_SKIP) kcfi_count++;
			}
		}
	}
	printf("KCFI Skip Status:    %s\n", (kcfi_count > 0) ? "NEUTRALIZED (B to skip)" : "STANDARD (or N/A)");

	for (i = 0; i + 30 <= size; i++) {
		if (memcmp(buf + i, "androidboot.selinux=permissive", 30) == 0) {
			selinux_permissive = true;
			break;
		}
	}
	printf("SELinux Default:     %s\n", selinux_permissive ? "PERMISSIVE" : "ENFORCING");

	for (i = 0; i + 8 <= size; i++) {
		if (memcmp(buf + i, "rkp_skip", 8) == 0) {
			rkp_patched = true;
			break;
		}
	}
	if (rkp_patched) {
		printf("Samsung RKP:         NEUTRALIZED (rkp_skip)\n");
	}
	printf("====================================================\n");
}

static int magiskboot_kernel_op(const char *image, const char *action, int argc, char **argv) {
	boot_img_t boot;
	bool is_boot_img = false;
	uint8_t *k_data = NULL;
	size_t k_size = 0;
	uint8_t k_fmt = BOOT_FMT_UNKNOWN;
	char tmp_kdecomp[PATH_MAX];
	int kd_fd = -1;
	struct stat kd_st;
	bool modified = false;
	const char *outfile = NULL;
	char final_target[PATH_MAX];
	char tmp_out_boot[PATH_MAX + 64];

	bool do_sigenforce = false;
	bool do_cfi = false;
	bool do_permissive = false;
	bool do_rkp = false;
	const char *hex_from = NULL;
	const char *hex_to = NULL;
	bool do_hash_scan = false;

	static const char k_acts[] ALIGN1 =
		"status\0"
		"info\0"
		"sigenforce\0"
		"patch-sigenforce\0"
		"nosig\0"
		"cfi\0"
		"patch-cfi\0"
		"de-enforce\0"
		"permissive\0"
		"disable-rkp\0"
		"rkp\0"
		"cfi-hash\0"
		"hexpatch\0"
		"patch\0"
		"patch-all\0";
	enum {
		K_ACT_status = 0,
		K_ACT_info,
		K_ACT_sigenforce,
		K_ACT_patch_sigenforce,
		K_ACT_nosig,
		K_ACT_cfi,
		K_ACT_patch_cfi,
		K_ACT_de_enforce,
		K_ACT_permissive,
		K_ACT_disable_rkp,
		K_ACT_rkp,
		K_ACT_cfi_hash,
		K_ACT_hexpatch,
		K_ACT_patch,
		K_ACT_patch_all,
	};

	if (!image || !action) return 1;

	/* Parse subcommand & options */
	switch (index_in_strings(k_acts, action)) {
	case K_ACT_status:
	case K_ACT_info:
		/* read-only status */
		break;
	case K_ACT_sigenforce:
	case K_ACT_patch_sigenforce:
	case K_ACT_nosig:
		do_sigenforce = true;
		if (argc >= 4 && strcmp(argv[1], "patch-sigenforce") == 0) {
			if (argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
		break;
	case K_ACT_cfi:
	case K_ACT_patch_cfi:
		do_cfi = true;
		if (argc >= 4 && strcmp(argv[1], "patch-cfi") == 0) {
			if (argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
		break;
	case K_ACT_de_enforce:
		do_sigenforce = true;
		do_cfi = true;
		if (argc >= 4 && strcmp(argv[1], "de-enforce") == 0) {
			if (argc >= 4 && argv[3][0] != '-') outfile = argv[3];
		} else if (argc >= 5 && argv[4][0] != '-') {
			outfile = argv[4];
		}
		break;
	case K_ACT_permissive:
		do_permissive = true;
		if (argc >= 5 && argv[4][0] != '-') outfile = argv[4];
		break;
	case K_ACT_disable_rkp:
	case K_ACT_rkp:
		do_rkp = true;
		if (argc >= 5 && argv[4][0] != '-') outfile = argv[4];
		break;
	case K_ACT_cfi_hash:
		do_hash_scan = true;
		break;
	case K_ACT_hexpatch:
		if (argc < 6) {
			bb_error_msg("usage: magiskboot kernel <image> hexpatch <from_hex> <to_hex> [out]");
			return 1;
		}
		hex_from = argv[4];
		hex_to = argv[5];
		if (argc >= 7 && argv[6][0] != '-') outfile = argv[6];
		break;
	case K_ACT_patch:
	case K_ACT_patch_all: {
		int i;
		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--sigenforce") == 0 || strcmp(argv[i], "--no-module-verify") == 0 ||
			    strcmp(argv[i], "--de-enforce") == 0) {
				do_sigenforce = true;
			} else if (strcmp(argv[i], "--cfi") == 0) {
				do_cfi = true;
			} else if (strcmp(argv[i], "--permissive") == 0) {
				do_permissive = true;
			} else if (strcmp(argv[i], "--disable-rkp") == 0 || strcmp(argv[i], "--rkp") == 0) {
				do_rkp = true;
			} else if (strcmp(argv[i], "--all") == 0) {
				do_sigenforce = true;
				do_cfi = true;
				do_permissive = true;
				do_rkp = true;
			} else if (strcmp(argv[i], "--hex") == 0) {
				if (i + 2 < argc) {
					hex_from = argv[i + 1];
					hex_to = argv[i + 2];
					i += 2;
				} else {
					bb_error_msg("--hex requires <from_hex> <to_hex>");
					return 1;
				}
			} else if (argv[i][0] != '-' && !outfile) {
				outfile = argv[i];
			}
		}
		if (strcmp(action, "patch-all") == 0) {
			do_sigenforce = true;
			do_cfi = true;
			do_permissive = true;
			do_rkp = true;
		}
		break;
	}
	default:
		bb_error_msg("unknown kernel action '%s' (supported: status, patch, sigenforce, cfi, de-enforce, permissive, rkp, hexpatch, cfi-hash)", action);
		return 1;
	}

	/* Try opening image as Android Boot Image */
	if (boot_img_parse(&boot, image)) {
		is_boot_img = true;
		if (!boot.kernel || boot.kernel_size == 0) {
			bb_error_msg("no kernel section found in boot image '%s'", image);
			boot_img_free(&boot);
			return 1;
		}
		k_fmt = boot.k_fmt;
		snprintf(tmp_kdecomp, sizeof(tmp_kdecomp), "%s.kraw.%d", image, (int)getpid());
		kd_fd = open3_or_warn(tmp_kdecomp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (kd_fd < 0) {
			boot_img_free(&boot);
			return 1;
		}
		if (boot_fmt_compressed(k_fmt)) {
			bb_decompress_data(k_fmt, boot.kernel, boot.kernel_size, kd_fd);
		} else {
			full_write(kd_fd, boot.kernel, boot.kernel_size);
		}
	} else {
		int in_fd = open_or_warn(image, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *in_map;

		if (in_fd < 0 || fstat(in_fd, &st) < 0 || st.st_size < 16) {
			if (in_fd >= 0) close(in_fd);
			return 1;
		}
		in_map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, in_fd, 0);
		close(in_fd);
		if (in_map == MAP_FAILED) {
			bb_perror_msg("mmap failed");
			return 1;
		}
		k_fmt = boot_check_fmt(in_map, st.st_size);

		snprintf(tmp_kdecomp, sizeof(tmp_kdecomp), "%s.kraw.%d", image, (int)getpid());
		kd_fd = open3_or_warn(tmp_kdecomp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (kd_fd < 0) {
			munmap(in_map, st.st_size);
			return 1;
		}
		if (boot_fmt_compressed(k_fmt)) {
			bb_decompress_data(k_fmt, in_map, st.st_size, kd_fd);
		} else {
			full_write(kd_fd, in_map, st.st_size);
		}
		munmap(in_map, st.st_size);
	}

	if (fstat(kd_fd, &kd_st) < 0 || kd_st.st_size <= 0) {
		bb_error_msg("failed to obtain kernel payload from '%s'", image);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 1;
	}
	k_size = (size_t)kd_st.st_size;

	k_data = mmap(NULL, k_size, PROT_READ | PROT_WRITE, MAP_SHARED, kd_fd, 0);
	if (k_data == MAP_FAILED) {
		bb_perror_msg("mmap failed for kernel payload");
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 1;
	}

	/* Read-only inspections */
	if (strcmp(action, "status") == 0 || strcmp(action, "info") == 0) {
		kernel_status_buf(k_data, k_size, image);
		munmap(k_data, k_size);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	if (do_hash_scan) {
		scan_kcfi_hashes(k_data, k_size);
		munmap(k_data, k_size);
		close(kd_fd);
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	/* Apply patches */
	if (do_sigenforce) {
		int chks = 0, sets = 0;
		if (patch_sigenforce_buf(k_data, k_size, &chks, &sets)) {
			fprintf(stderr, "[+] Signature enforcement neutralized (checks: %d, setters: %d)\n", chks, sets);
			modified = true;
		}
	}

	if (do_cfi) {
		int kcfi = 0, leg = 0;
		if (patch_cfi_buf(k_data, k_size, &kcfi, &leg)) {
			fprintf(stderr, "[+] Control Flow Integrity neutralized (KCFI: %d, Legacy: %d)\n", kcfi, leg);
			modified = true;
		}
	}

	if (do_permissive) {
		if (patch_selinux_permissive(k_data, k_size)) {
			modified = true;
		}
	}

	if (do_rkp) {
		if (patch_samsung_rkp(k_data, k_size)) {
			modified = true;
		}
	}

	if (hex_from && hex_to) {
		if (hexpatch_buffer(k_data, k_size, hex_from, hex_to)) {
			modified = true;
		}
	}

	msync(k_data, k_size, MS_SYNC);
	munmap(k_data, k_size);
	close(kd_fd);

	if (!modified) {
		fprintf(stderr, "[!] No kernel modifications were required or matched\n");
		unlink(tmp_kdecomp);
		if (is_boot_img) boot_img_free(&boot);
		return 0;
	}

	/* Determine destination */
	if (outfile && outfile[0] != '\0') {
		safe_strncpy(final_target, outfile, sizeof(final_target));
	} else {
		safe_strncpy(final_target, image, sizeof(final_target));
	}

	snprintf(tmp_out_boot, sizeof(tmp_out_boot), "%s.tmp.XXXXXX", final_target);
	close(xmkstemp(tmp_out_boot));

	if (is_boot_img) {
		char tmp_new_k[PATH_MAX];
		const char *k_payload_path = tmp_kdecomp;
		int out_fd;
		uint32_t page_sz;
		size_t hdr_pad;
		uint32_t kernel_sz = 0;
		uint32_t ramdisk_sz = 0;
		uint32_t second_sz, extra_sz, recov_dtbo_sz, dtb_sz, bootconfig_sz;

		if (boot_fmt_compressed(k_fmt)) {
			safe_strncpy(tmp_new_k, "/tmp/mb_kcomp_XXXXXX", sizeof(tmp_new_k));
			close(xmkstemp(tmp_new_k));
			if (compress_file_format(tmp_kdecomp, tmp_new_k, k_fmt) != 0) {
				bb_error_msg("failed to recompress kernel payload");
				unlink(tmp_kdecomp);
				boot_img_free(&boot);
				return 1;
			}
			k_payload_path = tmp_new_k;
		}

		out_fd = open3_or_warn(tmp_out_boot, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
		if (out_fd < 0) {
			unlink(tmp_kdecomp);
			if (k_payload_path == tmp_new_k) unlink(tmp_new_k);
			boot_img_free(&boot);
			return 1;
		}

		page_sz = dyn_hdr_page_size(&boot.hdr);
		hdr_pad = align_to(boot.hdr.raw_sz, page_sz);
		lseek(out_fd, hdr_pad, SEEK_SET);

		/* 1. Write kernel section */
		copy_file_section(out_fd, k_payload_path, page_sz, &kernel_sz);
		if (boot.kernel_dtb && boot.kernel_dtb_size > 0) {
			size_t rem;
			full_write(out_fd, boot.kernel_dtb, boot.kernel_dtb_size);
			kernel_sz += (uint32_t)boot.kernel_dtb_size;
			rem = kernel_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}
		*dyn_hdr_kernel_size(&boot.hdr) = kernel_sz;
		unlink(tmp_kdecomp);
		if (k_payload_path == tmp_new_k) unlink(tmp_new_k);

		/* 2. Write ramdisk section */
		ramdisk_sz = (uint32_t)boot.ramdisk_size;
		if (boot.ramdisk && ramdisk_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.ramdisk, ramdisk_sz);
			rem = ramdisk_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}
		*dyn_hdr_ramdisk_size(&boot.hdr) = ramdisk_sz;

		/* 3. Write remaining sections from memory */
		second_sz = (uint32_t)boot.second_size;
		if (boot.second && second_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.second, second_sz);
			rem = second_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		extra_sz = (uint32_t)boot.extra_size;
		if (boot.extra && extra_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.extra, extra_sz);
			rem = extra_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		recov_dtbo_sz = (uint32_t)boot.recovery_dtbo_size;
		if (boot.recovery_dtbo && recov_dtbo_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.recovery_dtbo, recov_dtbo_sz);
			rem = recov_dtbo_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		dtb_sz = (uint32_t)boot.dtb_size;
		if (boot.dtb && dtb_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.dtb, dtb_sz);
			rem = dtb_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		bootconfig_sz = (uint32_t)boot.bootconfig_size;
		if (boot.bootconfig && bootconfig_sz > 0) {
			size_t rem;
			full_write(out_fd, boot.bootconfig, bootconfig_sz);
			rem = bootconfig_sz % page_sz;
			if (rem > 0) {
				static const uint8_t zeros[4096] = {0};
				full_write(out_fd, zeros, page_sz - rem);
			}
		}

		/* 4. Recalculate SHA ID */
		dyn_hdr_recalc_id(&boot.hdr, out_fd, hdr_pad, page_sz,
		                  kernel_sz, ramdisk_sz, second_sz, extra_sz,
		                  recov_dtbo_sz, dtb_sz);

		/* 5. Handle AVB footer */
		if ((boot.flags & BOOT_FLAG_AVB) && boot.avb_footer) {
			uint64_t orig_vbmeta_off = SWAP_BE64(boot.avb_footer->vbmeta_offset);
			uint64_t orig_vbmeta_sz = SWAP_BE64(boot.avb_footer->vbmeta_size);
			if (orig_vbmeta_sz > 0 && orig_vbmeta_off + orig_vbmeta_sz <= boot.map_sz) {
				struct avb_footer new_footer;
				size_t rem;
				off_t aosp_img_size = lseek(out_fd, 0, SEEK_CUR);
				off_t new_vbmeta_off;

				rem = (size_t)aosp_img_size % 4096;
				if (rem > 0) {
					static const uint8_t zeros[4096] = {0};
					full_write(out_fd, zeros, 4096 - rem);
				}
				new_vbmeta_off = lseek(out_fd, 0, SEEK_CUR);
				full_write(out_fd, (const uint8_t *)boot.map_ptr + orig_vbmeta_off, orig_vbmeta_sz);
				rem = (size_t)orig_vbmeta_sz % 4096;
				if (rem > 0) {
					static const uint8_t zeros[4096] = {0};
					full_write(out_fd, zeros, 4096 - rem);
				}
				memcpy(&new_footer, boot.avb_footer, sizeof(new_footer));
				new_footer.original_image_size = SWAP_BE64((uint64_t)aosp_img_size);
				new_footer.vbmeta_offset = SWAP_BE64((uint64_t)new_vbmeta_off);
				new_footer.vbmeta_size = boot.avb_footer->vbmeta_size;
				full_write(out_fd, &new_footer, sizeof(new_footer));
			}
		}

		/* 6. Write finalized header at offset 0 */
		lseek(out_fd, 0, SEEK_SET);
		full_write(out_fd, boot.hdr.raw, boot.hdr.raw_sz);
		if (hdr_pad > boot.hdr.raw_sz) {
			static const uint8_t zeros[4096] = {0};
			full_write(out_fd, zeros, hdr_pad - boot.hdr.raw_sz);
		}

		close(out_fd);
		boot_img_free(&boot);

		if (safe_rename_or_copy(tmp_out_boot, final_target) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}

		fprintf(stderr, "[+] Successfully updated boot image kernel -> '%s'\n", final_target);
		return 0;
	} else {
		/* Standalone kernel output */
		if (boot_fmt_compressed(k_fmt)) {
			if (compress_file_format(tmp_kdecomp, tmp_out_boot, k_fmt) != 0) {
				bb_error_msg("failed to recompress kernel payload");
				unlink(tmp_kdecomp);
				return 1;
			}
			unlink(tmp_kdecomp);
		} else {
			if (safe_rename_or_copy(tmp_kdecomp, tmp_out_boot) != 0) {
				bb_perror_msg("failed to create '%s'", tmp_out_boot);
				unlink(tmp_kdecomp);
				return 1;
			}
		}

		if (safe_rename_or_copy(tmp_out_boot, final_target) != 0) {
			bb_perror_msg("failed to update '%s'", final_target);
			unlink(tmp_out_boot);
			return 1;
		}

		fprintf(stderr, "[+] Successfully updated kernel -> '%s'\n", final_target);
		return 0;
	}
}

/* =========================================================================
 * Kernel Module Vermagic Patcher (patch-vermagic)
 * ========================================================================= */

static int magiskboot_patch_vermagic_op(int argc, char **argv)
{
	const char *mod_path = NULL;
	const char *out_path = NULL;
	const char *target_magic = NULL;
	const char *boot_img_path = NULL;
	int i;

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--out") == 0) {
			if (i + 1 < argc) out_path = argv[++i];
		} else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--vermagic") == 0) {
			if (i + 1 < argc) target_magic = argv[++i];
		} else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--boot") == 0) {
			if (i + 1 < argc) boot_img_path = argv[++i];
		} else if (argv[i][0] != '-' && !mod_path) {
			mod_path = argv[i];
		} else if (argv[i][0] != '-' && !out_path) {
			out_path = argv[i];
		}
	}

	if (!mod_path) {
		mod_path = resolve_default_module_path(argc, argv, 2);
	}
	if (!out_path) {
		out_path = mod_path;
	}

	return module_patch_file(mod_path, out_path, target_magic, boot_img_path);
}
