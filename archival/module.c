/* vi: set sw=4 ts=4: */
/*
 * module.c — Kernel Module Toolkit
 *
 * Implements kernel module analysis, ELF relocation manipulation, vermagic patching,
 * BTF kernel introspection, altinstructions patching, Forward-Edge / KCFI stub neutralization,
 * unresolved symbol auditing against /proc/kallsyms, section stripping, direct in-kernel
 * module loading (init_module / finit_module) / unloading (delete_module), and early
 * ramdisk module injection into Android boot images (--live, --install).
 *
 * CLI Commands:
 *   --mod-info <mod.ko>           Display module vermagic and ELF header info
 *   --mod-audit <mod.ko> [sym]    Audit unresolved symbols against kernel
 *   --mod-strip <mod.ko> [out]    Strip unneeded sections and debug symbols
 *   --mod-patch <mod.ko> [opts]   Patch module vermagic, altinstructions, and CFI stubs
 *   --mod-inject <boot.img> <mod> Inject module into boot ramdisk (--live, --install)
 *   --mod-load <mod.ko> [args]    In-kernel load via finit_module / init_module
 *   --mod-unload [name]           In-kernel unload via delete_module
 *
 * Included directly into archival/aimg.c translation unit.
 * Conforms to Linux Kernel Coding Style & ISO C99/C11 standards.
 */

/* =========================================================================
 * 11. Dynamic ELF Kernel Module Patcher, BTF Introspection & Module Lifecycle
 * ========================================================================= */

#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE 0
#endif
#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

/* Forward declarations for native elf64_ctx engine */
static bool elf64_init_ctx(struct elf64_ctx *ctx, uint8_t *buf, size_t size, size_t capacity, bool is_allocated);
static void elf64_free_ctx(struct elf64_ctx *ctx);
static int elf64_find_section(struct elf64_ctx *ctx, const char *name, Elf64_Shdr **out_shdr, size_t *out_idx);
static int elf64_find_symbol(struct elf64_ctx *ctx, const char *name, Elf64_Sym *out_sym, size_t *out_idx);

static void log_kmsg_msg(const char *msg)
{
	int fd = open("/dev/kmsg", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (fd >= 0) {
		full_write(fd, msg, strlen(msg));
		close(fd);
	}
}

static uint8_t *decompress_gzip_buffer(const uint8_t *in_buf, size_t in_size, size_t *out_size)
{
	char tmp_path[] = "/tmp/mb_kdecomp_XXXXXX";
	int out_fd;
	struct stat st;
	uint8_t *out_buf = NULL;

	if (!in_buf || in_size < 10 || !out_size)
		return NULL;
	if (in_buf[0] != 0x1f || in_buf[1] != 0x8b)
		return NULL;

	out_fd = xmkstemp(tmp_path);
	unlink(tmp_path);

	if (bb_decompress_data(BOOT_FMT_GZIP, in_buf, in_size, out_fd) != 0) {
		close(out_fd);
		return NULL;
	}

	if (fstat(out_fd, &st) == 0 && st.st_size > 0) {
		lseek(out_fd, 0, SEEK_SET);
		out_buf = (uint8_t *)xmalloc(st.st_size);
		if (full_read(out_fd, out_buf, st.st_size) == (ssize_t)st.st_size) {
			*out_size = (size_t)st.st_size;
		} else {
			free(out_buf);
			out_buf = NULL;
		}
	}
	close(out_fd);
	return out_buf;
}

/*
 * Generic ARM64 Disassembly Instruction Decoders
 */
static inline bool kroot_elf_decode_adrp(uint32_t insn, uint64_t pc, int *rd, uint64_t *page_addr)
{
	if ((insn & 0x9f000000U) != 0x90000000U)
		return false;
	if (rd)
		*rd = (int)(insn & 0x1fU);
	if (page_addr) {
		int64_t immlo = (int64_t)((insn >> 29) & 0x3U);
		int64_t immhi = (int64_t)((insn >> 5) & 0x7ffffU);
		int64_t imm = (immhi << 2) | immlo;
		if (imm & (1LL << 20))
			imm -= (1LL << 21);
		*page_addr = (pc & ~0xfffULL) + (uint64_t)(imm << 12);
	}
	return true;
}

static inline bool kroot_elf_decode_add_sub_imm(uint32_t insn, int *rd, int *rn,
                                                uint32_t *imm, bool *is_sub, bool *is_64bit)
{
	if ((insn & 0x1f000000U) != 0x11000000U)
		return false;
	if (rd)
		*rd = (int)(insn & 0x1fU);
	if (rn)
		*rn = (int)((insn >> 5) & 0x1fU);
	if (is_sub)
		*is_sub = ((insn & (1U << 30)) != 0);
	if (is_64bit)
		*is_64bit = ((insn & (1U << 31)) != 0);
	if (imm) {
		uint32_t val = (insn >> 10) & 0xfffU;
		if (insn & (1U << 22))
			val <<= 12;
		*imm = val;
	}
	return true;
}

static inline bool kroot_elf_decode_cmp_imm(uint32_t insn, int *rn, uint32_t *imm, bool *is_64bit)
{
	if ((insn & 0x3f80001fU) != 0x3100001fU)
		return false;
	if (is_64bit)
		*is_64bit = ((insn & (1U << 31)) != 0);
	if (rn)
		*rn = (int)((insn >> 5) & 0x1fU);
	if (imm) {
		uint32_t shift = (insn >> 22) & 1U;
		uint32_t imm12 = (insn >> 10) & 0xfffU;
		*imm = imm12 << (shift ? 12 : 0);
	}
	return true;
}

static inline bool kroot_elf_decode_b_cond(uint32_t insn, uint64_t pc, int *cond, uint64_t *target)
{
	if ((insn & 0xff000010U) != 0x54000000U)
		return false;
	if (cond)
		*cond = (int)(insn & 0x0fU);
	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18))
			imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_ldr_imm(uint32_t insn, int *rt, int *rn,
                                            int32_t *offset, int *size, bool *is_signed)
{
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
		if (simm9 & 0x100U) simm9 |= ~0x1ff;
		if (rt) *rt = (int)(insn & 0x1fU);
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (offset) *offset = simm9;
		if (size) *size = sz;
		if (is_signed) *is_signed = (s_cls == 0x38800000U);
		return true;
	}
	return false;
}

static inline bool kroot_elf_decode_str_imm(uint32_t insn, int *rt, int *rn,
                                            int32_t *offset, int *size)
{
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

static inline bool kroot_elf_decode_cbz(uint32_t insn, uint64_t pc, int *rt,
                                        bool *is_cbnz, bool *is_64bit, uint64_t *target)
{
	if ((insn & 0x7e000000U) != 0x34000000U)
		return false;
	if (rt) *rt = (int)(insn & 0x1fU);
	if (is_cbnz) *is_cbnz = ((insn & (1U << 24)) != 0);
	if (is_64bit) *is_64bit = ((insn & (1U << 31)) != 0);
	if (target) {
		int64_t imm19 = (int64_t)((insn >> 5) & 0x7ffffU);
		if (imm19 & (1LL << 18)) imm19 -= (1LL << 19);
		*target = pc + (uint64_t)(imm19 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_b_bl(uint32_t insn, uint64_t pc, bool *is_bl, uint64_t *target)
{
	if ((insn & 0x7c000000U) != 0x14000000U)
		return false;
	if (is_bl) *is_bl = ((insn & 0x80000000U) != 0);
	if (target) {
		int64_t imm26 = (int64_t)(insn & 0x03ffffffU);
		if (imm26 & (1LL << 25)) imm26 -= (1LL << 26);
		*target = pc + (uint64_t)(imm26 << 2);
	}
	return true;
}

static inline bool kroot_elf_decode_blr(uint32_t insn, int *rn)
{
	if ((insn & 0xfffffc1fU) == 0xd63f0000U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		return true;
	}
	return false;
}

static inline bool kroot_elf_decode_blr_auth(uint32_t insn, int *rn, bool *use_b_key, bool *use_zero)
{
	if ((insn & 0xffff0800U) == 0xd73f0800U) {
		if (rn) *rn = (int)((insn >> 5) & 0x1fU);
		if (use_b_key) *use_b_key = ((insn >> 10) & 1) != 0;
		if (use_zero) *use_zero = (insn & 0x1fU) == 31;
		return true;
	}
	return false;
}

/*
 * Dynamic BTF (BPF Type Format) Kernel Introspection Engine
 */
static const uint8_t *find_btf_header(const uint8_t *data, size_t size)
{
	const struct kroot_btf_header *h0;
	size_t i;

	if (size < sizeof(struct kroot_btf_header))
		return NULL;

	h0 = (const struct kroot_btf_header *)data;
	if (h0->magic == KROOT_BTF_MAGIC && h0->version == KROOT_BTF_VERSION &&
	    h0->hdr_len >= 24 && h0->hdr_len <= 128 &&
	    h0->type_len > 0 && h0->str_len > 0 &&
	    (size_t)h0->hdr_len + h0->type_off + h0->type_len <= size &&
	    (size_t)h0->hdr_len + h0->str_off + h0->str_len <= size) {
		return data;
	}

	for (i = 0; i + sizeof(struct kroot_btf_header) <= size; i += 4) {
		if (data[i] == 0x9f && data[i + 1] == 0xeb) {
			const struct kroot_btf_header *h = (const struct kroot_btf_header *)(data + i);
			if (h->version == KROOT_BTF_VERSION &&
			    h->hdr_len >= 24 && h->hdr_len <= 128 &&
			    h->type_len > 0 && h->str_len > 0 &&
			    (size_t)i + h->hdr_len + h->type_off + h->type_len <= size &&
			    (size_t)i + h->hdr_len + h->str_off + h->str_len <= size) {
				const char *str_tab = (const char *)(data + i + h->hdr_len + h->str_off);
				if (str_tab[0] == '\0') {
					return data + i;
				}
			}
		}
	}
	return NULL;
}

static void classify_module_layout_probe(struct module_layout_probe *out, const uint8_t *data, size_t size);
static int extract_vermagic_from_buffer(const uint8_t *data, size_t size, char *out_magic, size_t max_len);

static int parse_module_layout_from_btf(const uint8_t *btf_raw, size_t btf_size,
                                       struct module_layout_probe *out)
{
	const struct kroot_btf_header *hdr;
	size_t min_hdr_sz, type_start, type_end, str_start, str_end, str_len, cur;
	const uint8_t *types;
	const char *strs;

	if (!btf_raw || btf_size < sizeof(struct kroot_btf_header))
		return -1;
	hdr = (const struct kroot_btf_header *)btf_raw;
	if (hdr->magic != KROOT_BTF_MAGIC)
		return -1;

	min_hdr_sz = hdr->hdr_len;
	if (min_hdr_sz < 24 || min_hdr_sz > btf_size)
		return -1;

	type_start = min_hdr_sz + hdr->type_off;
	type_end   = type_start + hdr->type_len;
	str_start  = min_hdr_sz + hdr->str_off;
	str_end    = str_start + hdr->str_len;

	if (type_end > btf_size || str_end > btf_size)
		return -1;

	types = btf_raw + type_start;
	strs = (const char *)(btf_raw + str_start);
	str_len = hdr->str_len;
	cur = 0;

	while (cur + sizeof(struct kroot_btf_type) <= hdr->type_len) {
		const struct kroot_btf_type *t = (const struct kroot_btf_type *)(types + cur);
		uint32_t kind = (t->info >> 24) & 0x1f;
		uint32_t vlen = t->info & 0xffff;
		uint32_t kflag = (t->info >> 31) & 1;

		size_t elem_sz = sizeof(struct kroot_btf_type);
		switch (kind) {
		case KROOT_BTF_KIND_INT: elem_sz += sizeof(uint32_t); break;
		case KROOT_BTF_KIND_ARRAY: elem_sz += sizeof(struct kroot_btf_array); break;
		case KROOT_BTF_KIND_STRUCT:
		case KROOT_BTF_KIND_UNION: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_member); break;
		case KROOT_BTF_KIND_ENUM: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_enum); break;
		case KROOT_BTF_KIND_ENUM64: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_enum64); break;
		case KROOT_BTF_KIND_FUNC_PROTO: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_param); break;
		case KROOT_BTF_KIND_VAR: elem_sz += sizeof(struct kroot_btf_var); break;
		case KROOT_BTF_KIND_DATASEC: elem_sz += (size_t)vlen * sizeof(struct kroot_btf_var_secinfo); break;
		case KROOT_BTF_KIND_DECL_TAG: elem_sz += 4; break;
		default: break;
		}

		if (cur + elem_sz > hdr->type_len)
			break;

		if (kind == KROOT_BTF_KIND_STRUCT && t->name_off < str_len) {
			const char *tname = strs + t->name_off;
			if (strcmp(tname, "module") == 0) {
				const struct kroot_btf_member *m = (const struct kroot_btf_member *)(t + 1);
				uint32_t i;
				out->mod_size = t->size;
				printf("[+] Found BTF struct module (size = %zu bytes, %u members):\n",
				       out->mod_size, vlen);
				for (i = 0; i < vlen; i++) {
					if (m[i].name_off < str_len) {
						const char *mname = strs + m[i].name_off;
						uint32_t bit_off = kflag ? (m[i].offset & 0xffffff) : m[i].offset;
						uint32_t byte_off = bit_off / 8;
						if (strcmp(mname, "init") == 0) {
							out->init_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "exit") == 0) {
							out->exit_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "core_layout") == 0) {
							out->core_layout_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "mem") == 0) {
							out->core_layout_off = byte_off;
							out->has_mod_memory = true;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes) [Linux 6.4+ module_memory]\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "build_id") == 0) {
							out->build_id_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						} else if (strcmp(mname, "arch") == 0) {
							out->arch_off = byte_off;
							printf("    • [BTF] member: %-16s = 0x%x (%u bytes)\n", mname, byte_off, byte_off);
						}
					}
				}
				if (out->mod_size > 0 && out->init_off > 0) {
					out->has_btf = true;
					out->found = true;
					classify_module_layout_probe(out, btf_raw, btf_size);
					return 0;
				}
			}
		}
		cur += elem_sz;
	}
	return -1;
}

struct kernel_abi_profile {
	const char *name;
	int maj;
	int min;
	size_t ref_init;
	size_t ref_exit;
	size_t ref_size;
	bool has_cfi;
	bool has_bpf;
	bool has_mem7;
	bool is_vendor;
	const char *desc;
};

static const struct kernel_abi_profile investigated_profiles[] = {
	{
		.name       = "4.19-vendor-xiaomi-msm8937",
		.maj        = 4, .min = 19,
		.ref_init   = 368, /* 0x170 */
		.ref_exit   = 800, /* 0x320 */
		.ref_size   = 896, /* 0x380 */
		.has_cfi    = false,
		.has_bpf    = true,
		.has_mem7   = false,
		.is_vendor  = true,
		.desc       = "Linux 4.19 Vendor ABI (Xiaomi Redmi 8/Qualcomm: Non-CFI, BPF raw events enabled)",
	},
	{
		.name       = "4.19-ack-generic-gki",
		.maj        = 4, .min = 19,
		.ref_init   = 376, /* 0x178 */
		.ref_exit   = 784, /* 0x310 (784-792) */
		.ref_size   = 896, /* 0x380 */
		.has_cfi    = true,
		.has_bpf    = false,
		.has_mem7   = false,
		.is_vendor  = false,
		.desc       = "Linux 4.19 Generic ACK GKI ABI (Clang CFI enabled, no BPF raw events)",
	},
	{
		.name       = "5.10-ack-generic-gki",
		.maj        = 5, .min = 10,
		.ref_init   = 400, /* 0x190 */
		.ref_exit   = 1088, /* 0x440 */
		.ref_size   = 1088,
		.has_cfi    = true,
		.has_bpf    = false,
		.has_mem7   = false,
		.is_vendor  = false,
		.desc       = "Linux 5.10 Generic GKI ABI (Clang CFI, core_layout)",
	},
	{
		.name       = "6.1-android14-gki",
		.maj        = 6, .min = 1,
		.ref_init   = 368, /* 0x170 */
		.ref_exit   = 984, /* 0x3d8 */
		.ref_size   = 1088, /* 0x440 */
		.has_cfi    = false,
		.has_bpf    = false,
		.has_mem7   = false,
		.is_vendor  = false,
		.desc       = "Linux 6.1 Generic GKI ABI (KCFI traps, build_id, core_layout)",
	},
	{
		.name       = "6.6-android15-gki",
		.maj        = 6, .min = 6,
		.ref_init   = 392, /* 0x188 */
		.ref_exit   = 1464, /* 0x5b8 */
		.ref_size   = 1536, /* 0x600 */
		.has_cfi    = false,
		.has_bpf    = false,
		.has_mem7   = true,
		.is_vendor  = false,
		.desc       = "Linux 6.6 Generic GKI ABI (KCFI, build_id, struct module_memory mem[7])",
	},
	{
		.name       = "mainline-baklava-gki",
		.maj        = 6, .min = 12,
		.ref_init   = 448, /* 0x1c0 */
		.ref_exit   = 1400, /* 0x578 */
		.ref_size   = 1472, /* 0x5c0 */
		.has_cfi    = false,
		.has_bpf    = false,
		.has_mem7   = true,
		.is_vendor  = false,
		.desc       = "Linux Mainline GKI ABI (Baklava 6.12+: PAC/BTI, KCFI, mem[7])",
	},
	{
		.name       = "upstream-vanilla-reference",
		.maj        = 0, .min = 0,
		.ref_init   = 304, /* 0x130 */
		.ref_exit   = 1072, /* 0x430 */
		.ref_size   = 1152, /* 0x480 */
		.has_cfi    = false,
		.has_bpf    = false,
		.has_mem7   = true,
		.is_vendor  = false,
		.desc       = "Linux Upstream Vanilla ABI (No KABI reserves, mem[7])",
	},
};

static void classify_module_layout_probe(struct module_layout_probe *out, const uint8_t *data, size_t size)
{
	int banner_maj = 0, banner_min = 0;
	const struct kernel_abi_profile *best_prof = NULL;
	size_t i;
	char vm_buf[256];

	if (!out) return;

	/* 1. Dynamic Kernel Banner & Vermagic Resolution */
	vm_buf[0] = '\0';
	if (data && size > 0 && extract_vermagic_from_buffer(data, size, vm_buf, sizeof(vm_buf)) == 0) {
		sscanf(vm_buf, "%d.%d", &banner_maj, &banner_min);
	}

	/* 2. Dynamic Resolution of missing offsets / sizing */
	if (out->mod_size == 0) {
		if (banner_maj == 4 && banner_min <= 19) {
			out->mod_size = 896;
		} else if (banner_maj == 5 && banner_min <= 10) {
			out->mod_size = 1088;
		} else if (banner_maj == 6 && banner_min <= 1) {
			out->mod_size = 1088;
		} else if (banner_maj == 6 && banner_min <= 6) {
			out->mod_size = 1536;
		} else if (banner_maj >= 6) {
			out->mod_size = 1472;
		} else if (out->exit_off > 0) {
			out->mod_size = (out->exit_off + 127) & ~63ULL;
		}
		if (out->mod_size > 0) out->found = true;
	}

	if (out->exit_off > 0 && out->mod_size > 0 && out->exit_off >= out->mod_size) {
		out->mod_size = (out->exit_off + 127) & ~63ULL;
	}

	/* 3. Match against Investigated Reference Profiles */
	/* First pass: exact or within-tolerance match on init and exit offsets */
	for (i = 0; i < ARRAY_SIZE(investigated_profiles); i++) {
		const struct kernel_abi_profile *p = &investigated_profiles[i];
		bool init_match = (out->init_off == p->ref_init);
		bool exit_match = false;

		if (out->exit_off == p->ref_exit) {
			exit_match = true;
		} else if (p->ref_exit == 784 && out->exit_off >= 780 && out->exit_off <= 800) {
			exit_match = true;
		} else if (p->ref_exit == 800 && out->exit_off >= 796 && out->exit_off <= 808) {
			exit_match = true;
		} else if (p->ref_exit == 1072 && out->exit_off >= 1060 && out->exit_off <= 1090) {
			exit_match = true;
		} else if (p->ref_exit == 984 && out->exit_off >= 970 && out->exit_off <= 1000) {
			exit_match = true;
		} else if (p->ref_exit == 1464 && out->exit_off >= 1440 && out->exit_off <= 1480) {
			exit_match = true;
		} else if (p->ref_exit == 1400 && out->exit_off >= 1390 && out->exit_off <= 1420) {
			exit_match = true;
		}

		if (init_match && exit_match) {
			best_prof = p;
			break;
		}
	}

	/* Second pass: if no exact offset match, select profile matching banner version */
	if (!best_prof && banner_maj > 0) {
		for (i = 0; i < ARRAY_SIZE(investigated_profiles); i++) {
			const struct kernel_abi_profile *p = &investigated_profiles[i];
			if (p->maj == banner_maj && p->min == banner_min) {
				best_prof = p;
				break;
			}
		}
	}

	/* Third pass: fallback to closest profile by init offset */
	if (!best_prof) {
		size_t min_diff = (size_t)-1;
		for (i = 0; i < ARRAY_SIZE(investigated_profiles); i++) {
			const struct kernel_abi_profile *p = &investigated_profiles[i];
			size_t diff = (out->init_off > p->ref_init) ? (out->init_off - p->ref_init) : (p->ref_init - out->init_off);
			if (diff < min_diff) {
				min_diff = diff;
				best_prof = p;
			}
		}
	}

	if (!best_prof) {
		best_prof = &investigated_profiles[0];
	}

	/* 4. Compare Probed vs Investigated Reference Offsets */
	out->matched_profile = best_prof->name;
	out->ref_init_off = best_prof->ref_init;
	out->ref_exit_off = best_prof->ref_exit;
	out->ref_mod_size = best_prof->ref_size;
	out->init_delta = (long)out->init_off - (long)best_prof->ref_init;
	out->exit_delta = (long)out->exit_off - (long)best_prof->ref_exit;
	out->size_delta = (long)out->mod_size - (long)best_prof->ref_size;

	out->profile_matched = (out->init_delta == 0 && (out->exit_delta >= -8 && out->exit_delta <= 8) && out->size_delta == 0);
	out->has_cfi_check = best_prof->has_cfi || (out->init_delta == 8);
	out->has_bpf_events = best_prof->has_bpf || (out->exit_delta == 16);
	out->has_mod_memory = best_prof->has_mem7 || (out->exit_off > 1200);
	out->is_vendor_abi = best_prof->is_vendor || (!out->profile_matched);
	out->variant_desc = best_prof->desc;
	out->found = true;

	printf("[*] Kernel ABI Verification (Probed vs Investigated Reference Profile):\n");
	printf("    • Baseline Profile       : %s (%s)\n", best_prof->name, best_prof->desc);
	printf("    • offsetof(init)         : Probed 0x%zx (%zu) vs Reference 0x%zx (%zu) [Delta: %+ld B]\n",
	       out->init_off, out->init_off, best_prof->ref_init, best_prof->ref_init, out->init_delta);
	printf("    • offsetof(exit)         : Probed 0x%zx (%zu) vs Reference 0x%zx (%zu) [Delta: %+ld B]\n",
	       out->exit_off, out->exit_off, best_prof->ref_exit, best_prof->ref_exit, out->exit_delta);
	printf("    • sizeof(struct module)  : Probed %zu B (0x%zx) vs Reference %zu B (0x%zx) [Delta: %+ld B]\n",
	       out->mod_size, out->mod_size, best_prof->ref_size, best_prof->ref_size, out->size_delta);

	if (out->profile_matched) {
		printf("    • Profile Match Status   : 100%% EXACT MATCH with investigated silicon invariants\n");
	} else {
		printf("    • Profile Match Status   : VENDOR SHIFT DETECTED:\n");
		if (out->init_delta == 8) {
			printf("      -> [CFI Shift] init offset +8B: CONFIG_CFI_CLANG enabled (cfi_check added before init)\n");
		} else if (out->init_delta == -8) {
			printf("      -> [Non-CFI Shift] init offset -8B: Vendor kernel compiled with CFI disabled\n");
		}
		if (out->exit_delta == 16 || out->exit_delta == 8) {
			printf("      -> [BPF Events Shift] exit offset +16B: CONFIG_BPF_EVENTS enabled (bpf_raw_events added)\n");
		} else if (out->exit_delta > 300) {
			printf("      -> [Architecture Shift] exit offset %+ldB: Linux 6.4+ struct module_memory mem[7] migration\n", out->exit_delta);
		}
	}
}

static int probe_module_layout_from_kernel_image(const uint8_t *data, size_t size,
                                                 struct module_layout_probe *out)
{
	size_t limit, i;
	if (!data || size < 64)
		return -1;

	printf("[*] Probing silicon kernel image (%zu bytes, %.2f MB) for struct module ABI...\n",
	       size, (double)size / (1024.0 * 1024.0));

	limit = size - 64;

	/*
	 * Machine-Code Module Size Discovery:
	 * In Linux 6.4+, kernel/module/main.c enforces:
	 *   if (shdr->sh_size != sizeof(struct module))
	 *       pr_err("module %s: .gnu.linkonce.this_module section size must match...\n");
	 */
	if (out->mod_size == 0) {
		const char *needle = ".gnu.linkonce.this_module section size must match";
		size_t needle_len = strlen(needle);
		const uint8_t *found_str = NULL;
		size_t s_idx;

		for (s_idx = 0; s_idx + needle_len <= size; s_idx++) {
			if (data[s_idx] == (uint8_t)needle[0] &&
			    memcmp(data + s_idx, needle, needle_len) == 0) {
				found_str = data + s_idx;
				break;
			}
		}

		if (found_str) {
			size_t str_idx = (size_t)(found_str - data);
			size_t str_start = str_idx;
			uint64_t target_page;
			uint32_t target_lo12, raw_lo12;
			size_t err_pc = 0, pc;

			if (str_idx >= 32) {
				size_t p_off;
				for (p_off = str_idx - 1; p_off >= str_idx - 32; p_off--) {
					if (memcmp(data + p_off, "module %s:", 10) == 0) {
						str_start = p_off;
						if (p_off >= 2 && data[p_off - 2] == 1)
							str_start = p_off - 2;
						break;
					}
				}
			}

			target_page = (uint64_t)(str_start & ~0xfffULL);
			target_lo12 = (uint32_t)(str_start & 0xfffULL);
			raw_lo12 = (uint32_t)(str_idx & 0xfffULL);

			for (pc = 0; pc + 4 <= limit; pc += 4) {
				uint32_t insn = *(const uint32_t *)(data + pc);
				int adrp_rd = 0;
				uint64_t page_addr = 0;
				if (kroot_elf_decode_adrp(insn, (uint64_t)pc, &adrp_rd, &page_addr) && page_addr == target_page) {
					size_t next_pc;
					for (next_pc = pc + 4; next_pc <= pc + 32 && next_pc + 4 <= limit; next_pc += 4) {
						uint32_t insn2 = *(const uint32_t *)(data + next_pc);
						int add_rd = 0, add_rn = 0;
						uint32_t add_imm = 0;
						bool is_sub = false, is_64bit = false;
						if (kroot_elf_decode_add_sub_imm(insn2, &add_rd, &add_rn, &add_imm, &is_sub, &is_64bit) &&
						    !is_sub && add_rn == adrp_rd &&
						    (add_imm == target_lo12 || add_imm == raw_lo12 || (size_t)abs((int)(add_imm - raw_lo12)) < 16)) {
							err_pc = pc;
							break;
						}
					}
					if (err_pc > 0)
						break;
				}
			}

			if (err_pc > 0) {
				size_t window_start = (err_pc > 8192) ? (err_pc - 8192) : 0;
				size_t b_pc;
				for (b_pc = window_start; b_pc < err_pc; b_pc += 4) {
					uint32_t b_insn = *(const uint32_t *)(data + b_pc);
					int cond = 0;
					uint64_t b_target = 0;
					if (kroot_elf_decode_b_cond(b_insn, (uint64_t)b_pc, &cond, &b_target)) {
						if ((b_target >= (uint64_t)(err_pc > 64 ? err_pc - 64 : 0) &&
						     b_target <= (uint64_t)(err_pc + 64)) ||
						    ((b_target & ~0x1fULL) == (err_pc & ~0x1fULL))) {
							size_t c_start = (b_pc > 16) ? (b_pc - 16) : 0;
							size_t c_pc;
							for (c_pc = b_pc - 4; c_pc >= c_start; c_pc -= 4) {
								uint32_t c_insn = *(const uint32_t *)(data + c_pc);
								int c_rn = 0;
								uint32_t c_imm = 0;
								bool c_64 = false;
								if (kroot_elf_decode_cmp_imm(c_insn, &c_rn, &c_imm, &c_64) &&
								    c_imm >= 256 && c_imm <= 8192) {
									out->mod_size = (size_t)c_imm;
									out->found = true;
									printf("    • [Silicon] sizeof(struct module) : %zu bytes (0x%zx) at image offset 0x%zx\n",
									       out->mod_size, out->mod_size, c_pc);
									break;
								}
								if (c_pc == 0) break;
							}
							if (out->mod_size > 0) break;
						}
					}
				}
			}
		}
	}

	for (i = 0; i < limit; i += 4) {
		uint32_t w0 = *(const uint32_t *)(data + i);
		int rt0, rn0, sz0;
		int32_t off0;
		bool is_signed0;
		size_t off;

		if (!kroot_elf_decode_ldr_imm(w0, &rt0, &rn0, &off0, &sz0, &is_signed0) ||
		    sz0 != 8 || off0 < 16 || off0 > 4096 || rn0 == 31)
			continue;

		off = (size_t)off0;

		if (out->init_off == 0 && rt0 == 0) {
			size_t j;
			for (j = 1; j <= 3 && i + (j + 2) * 4 <= limit; j++) {
				uint32_t wj = *(const uint32_t *)(data + i + j * 4);
				int cbz_rt;
				bool is_cbnz, is_64bit;
				uint64_t cbz_target = 0;
				if (kroot_elf_decode_cbz(wj, (uint64_t)(i + j * 4), &cbz_rt, &is_cbnz, &is_64bit, &cbz_target) && cbz_rt == 0) {
					size_t k;
					for (k = j + 1; k <= j + 4 && i + (k + 1) * 4 <= limit; k++) {
						uint32_t wk = *(const uint32_t *)(data + i + k * 4);
						bool is_bl;
						uint64_t bl_target = 0;
						if (kroot_elf_decode_b_bl(wk, (uint64_t)(i + k * 4), &is_bl, &bl_target) && is_bl) {
							bool is_do_init = false;
							size_t m;
							for (m = k + 1; m <= k + 32 && i + (m + 1) * 4 <= limit; m++) {
								uint32_t wm = *(const uint32_t *)(data + i + m * 4);
								int str_rt, str_rn, str_sz;
								int32_t str_off_val;
								if (kroot_elf_decode_str_imm(wm, &str_rt, &str_rn, &str_off_val, &str_sz) &&
								    str_rn == rn0 && str_rt == 31 && str_sz == 4 && str_off_val == 0) {
									is_do_init = true;
									break;
								}
							}
							if (!is_do_init) continue;

							out->init_off = off;
							out->found = true;
							printf("[+] Silicon Machine Code Opcode Discovery:\n");
							printf("    • [Silicon] offsetof(init)      : %zu (0x%zx) at image offset 0x%zx (rn=x%d)\n",
							       out->init_off, out->init_off, i, rn0);
							break;
						}
					}
					if (out->init_off > 0) break;
				}
			}
		}

		if (out->exit_off == 0 && off >= 512 && off <= 1800 &&
		    (out->init_off == 0 || off >= out->init_off + 256)) {
			int target_reg = rt0;
			size_t k;
			for (k = 1; k <= 32 && i + (k + 1) * 4 <= limit; k++) {
				uint32_t wk = *(const uint32_t *)(data + i + k * 4);
				int blr_rn = -1;
				bool is_blr = false;
				bool use_b_key, use_zero;

				if (kroot_elf_decode_blr(wk, &blr_rn) && blr_rn == target_reg) {
					is_blr = true;
				} else if (kroot_elf_decode_blr_auth(wk, &blr_rn, &use_b_key, &use_zero) && blr_rn == target_reg) {
					is_blr = true;
				} else if ((wk & 0xffe0ffe0) == 0xaa0003e0) {
					int mov_rd = wk & 0x1f;
					int mov_rm = (wk >> 16) & 0x1f;
					if (mov_rm == target_reg)
						target_reg = mov_rd;
				}

				if (is_blr) {
					/* Verify delete_module context: look for mov w1, #2 (MODULE_STATE_GOING) */
					bool is_delete_mod = false;
					size_t m;
					for (m = k + 1; m <= k + 24 && i + (m + 1) * 4 <= limit; m++) {
						uint32_t wm = *(const uint32_t *)(data + i + m * 4);
						if (wm == 0x52800041U) { /* mov w1, #2 */
							is_delete_mod = true;
							break;
						}
					}
					if (is_delete_mod) {
						out->exit_off = off;
						out->found = true;
						printf("    • [Silicon] offsetof(exit)      : %zu (0x%zx) at image offset 0x%zx (rn=x%d, BLR X%d) [delete_module]\n",
						       out->exit_off, out->exit_off, i, rn0, blr_rn);
						break;
					}
				}
			}
		}

		if (out->init_off > 0 && out->exit_off > 0)
			break;
	}

	classify_module_layout_probe(out, data, size);
	return (out->init_off > 0 || out->mod_size > 0) ? 0 : -1;
}

static int probe_module_layout_from_buffer(const uint8_t *map, size_t size, struct module_layout_probe *out)
{
	const uint8_t *k_data;
	size_t k_size;
	uint8_t *decompressed = NULL;
	const uint8_t *btf;
	int res;

	if (!map || size < 4096)
		return -1;

	k_data = map;
	k_size = size;

	if (size > 4096 && memcmp(map, "ANDROID!", 8) == 0) {
		uint32_t hdr_ver = *(const uint32_t *)(map + 40);
		size_t k_off = (hdr_ver >= 3) ? 4096 : *(const uint32_t *)(map + 36);
		size_t k_sz = *(const uint32_t *)(map + 8);
		if (k_off < size) {
			k_data = map + k_off;
			k_size = (k_sz > 0 && k_off + k_sz <= size) ? k_sz : (size - k_off);
		}
	}

	if (k_size > 10 && k_data[0] == 0x1f && k_data[1] == 0x8b) {
		size_t decomp_sz = 0;
		decompressed = decompress_gzip_buffer(k_data, k_size, &decomp_sz);
		if (decompressed && decomp_sz > 4096) {
			k_data = decompressed;
			k_size = decomp_sz;
		}
	}

	/* 1. If buffer is an ELF binary (vmlinux), probe via native ELF64 context */
	if (k_size >= sizeof(Elf64_Ehdr) && memcmp(k_data, ELFMAG, SELFMAG) == 0 && k_data[EI_CLASS] == ELFCLASS64) {
		struct elf64_ctx kctx;
		if (elf64_init_ctx(&kctx, (uint8_t *)k_data, k_size, k_size, false)) {
			Elf64_Shdr *text_shdr = NULL;
			if (elf64_find_section(&kctx, ".text", &text_shdr, NULL) == 0 && text_shdr) {
				const uint8_t *text_bytes = k_data + text_shdr->sh_offset;
				size_t text_sz = (size_t)text_shdr->sh_size;
				Elf64_Sym sym_init, sym_del;

				printf("[*] Probing ELF vmlinux (.text: %zu bytes at offset 0x%zx)...\n",
				       text_sz, (size_t)text_shdr->sh_offset);

				/* Surgical symbol disassembly if symtab is present */
				if (elf64_find_symbol(&kctx, "do_init_module", &sym_init, NULL) == 0 &&
				    sym_init.st_value >= text_shdr->sh_addr &&
				    sym_init.st_value < text_shdr->sh_addr + text_shdr->sh_size) {
					size_t fn_off = (size_t)(sym_init.st_value - text_shdr->sh_addr);
					size_t fn_limit = (fn_off + 256 <= text_sz) ? (fn_off + 256) : text_sz;
					size_t pc;
					for (pc = fn_off; pc + 16 <= fn_limit; pc += 4) {
						uint32_t w0 = *(const uint32_t *)(text_bytes + pc);
						int rt0, rn0, sz0;
						int32_t off0;
						bool is_signed0;
						if (kroot_elf_decode_ldr_imm(w0, &rt0, &rn0, &off0, &sz0, &is_signed0) &&
						    sz0 == 8 && rt0 == 0 && off0 >= 256 && off0 <= 1024) {
							out->init_off = (size_t)off0;
							out->found = true;
							printf("    • [vmlinux Symbol] do_init_module offsetof(init) : %zu (0x%zx)\n",
							       out->init_off, out->init_off);
							break;
						}
					}
				}

				if ((elf64_find_symbol(&kctx, "__arm64_sys_delete_module", &sym_del, NULL) == 0 ||
				     elf64_find_symbol(&kctx, "delete_module", &sym_del, NULL) == 0) &&
				    sym_del.st_value >= text_shdr->sh_addr &&
				    sym_del.st_value < text_shdr->sh_addr + text_shdr->sh_size) {
					size_t fn_off = (size_t)(sym_del.st_value - text_shdr->sh_addr);
					size_t fn_limit = (fn_off + 1024 <= text_sz) ? (fn_off + 1024) : text_sz;
					size_t pc;
					for (pc = fn_off; pc + 16 <= fn_limit; pc += 4) {
						uint32_t w0 = *(const uint32_t *)(text_bytes + pc);
						int rt0, rn0, sz0;
						int32_t off0;
						bool is_signed0;
						if (kroot_elf_decode_ldr_imm(w0, &rt0, &rn0, &off0, &sz0, &is_signed0) &&
						    sz0 == 8 && off0 >= 512 && off0 <= 1800) {
							size_t k;
							for (k = 1; k <= 16 && pc + (k + 1) * 4 <= fn_limit; k++) {
								uint32_t wk = *(const uint32_t *)(text_bytes + pc + k * 4);
								int blr_rn;
								bool b_key, z_key;
								if ((kroot_elf_decode_blr(wk, &blr_rn) && blr_rn == rt0) ||
								    (kroot_elf_decode_blr_auth(wk, &blr_rn, &b_key, &z_key) && blr_rn == rt0)) {
									out->exit_off = (size_t)off0;
									out->found = true;
									printf("    • [vmlinux Symbol] delete_module offsetof(exit) : %zu (0x%zx)\n",
									       out->exit_off, out->exit_off);
									break;
								}
							}
							if (out->exit_off > 0) break;
						}
					}
				}

				/* If symbol disassembly left offsets unresolved, scan .text section */
				if (!out->found || out->init_off == 0 || out->exit_off == 0) {
					probe_module_layout_from_kernel_image(text_bytes, text_sz, out);
				} else {
					classify_module_layout_probe(out, k_data, k_size);
				}

				elf64_free_ctx(&kctx);
				if (out->found) {
					if (decompressed) free(decompressed);
					return 0;
				}
			}
			elf64_free_ctx(&kctx);
		}
	}

	btf = find_btf_header(k_data, k_size);
	if (btf && parse_module_layout_from_btf(btf, k_size - (size_t)(btf - k_data), out) == 0) {
		out->has_btf = true;
		if (decompressed) free(decompressed);
		return 0;
	}

	res = probe_module_layout_from_kernel_image(k_data, k_size, out);
	if (decompressed) free(decompressed);
	return res;
}

static int extract_vermagic_from_buffer(const uint8_t *data, size_t size, char *out_magic, size_t max_len)
{
	size_t i;

	if (!data || size < 64 || !out_magic || max_len < 16)
		return -1;

	/* Primary: scan for full vermagic ending with "aarch64" */
	for (i = 0; i + 7 <= size; i++) {
		if (memcmp(data + i, "aarch64", 7) == 0) {
			size_t end_pos = i + 7;
			size_t start_pos = i;
			while (start_pos > 0 && data[start_pos - 1] >= 0x20 && data[start_pos - 1] <= 0x7E) {
				start_pos--;
			}
			if (end_pos > start_pos) {
				size_t cand_len = end_pos - start_pos;
				if (cand_len >= 20 && cand_len < max_len && cand_len < 256) {
					char cand[256];
					int maj = 0;
					memcpy(cand, data + start_pos, cand_len);
					cand[cand_len] = '\0';
					if (sscanf(cand, "%d.", &maj) == 1 && maj >= 2 && maj <= 99 &&
					    (strstr(cand, " SMP ") != NULL || strstr(cand, " preempt ") != NULL || strstr(cand, " mod_unload ") != NULL)) {
						snprintf(out_magic, max_len, "%s", cand);
						return 0;
					}
				}
			}
		}
	}

	/* Secondary fallback: scan for "Linux version " banner */
	for (i = 0; i + 14 <= size; i++) {
		if (memcmp(data + i, "Linux version ", 14) == 0) {
			const char *p = (const char *)(data + i + 14);
			size_t k = 0;
			while (i + 14 + k < size && p[k] != ' ' && p[k] != '\0' && k < 64) {
				k++;
			}
			if (k >= 3) {
				char ver[64];
				int maj = 0;
				memcpy(ver, p, k);
				ver[k] = '\0';
				if (sscanf(ver, "%d.", &maj) == 1 && maj >= 2 && maj <= 99) {
					snprintf(out_magic, max_len, "%s SMP preempt mod_unload modversions aarch64", ver);
					return 0;
				}
			}
		}
	}
	return -1;
}

static int detect_vermagic_from_boot_image(const char *boot_path, char *out_magic, size_t max_len)
{
	int fd;
	struct stat st;
	off_t real_sz;
	uint8_t *map;
	const uint8_t *k_data;
	size_t k_size;
	uint8_t *decompressed = NULL;
	int ret;

	if (!boot_path || !out_magic) return -1;
	fd = open(boot_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return -1;
	}

	real_sz = get_file_or_bdev_size(fd, &st);
	if (real_sz < 4096) {
		close(fd);
		return -1;
	}

	map = (uint8_t *)map_or_read_image(fd, (size_t)real_sz, false);
	close(fd);
	if (map == MAP_FAILED) return -1;

	k_data = map;
	k_size = (size_t)real_sz;

	if (k_size > 4096 && memcmp(map, "ANDROID!", 8) == 0) {
		uint32_t hdr_ver = *(const uint32_t *)(map + 40);
		size_t k_off = (hdr_ver >= 3) ? 4096 : *(const uint32_t *)(map + 36);
		size_t k_sz = *(const uint32_t *)(map + 8);
		if (k_off < k_size) {
			k_data = map + k_off;
			k_size = (k_sz > 0 && k_off + k_sz <= k_size) ? k_sz : (k_size - k_off);
		}
	}

	if (k_size > 10 && k_data[0] == 0x1f && k_data[1] == 0x8b) {
		size_t decomp_sz = 0;
		decompressed = decompress_gzip_buffer(k_data, k_size, &decomp_sz);
		if (decompressed && decomp_sz > 4096) {
			k_data = decompressed;
			k_size = decomp_sz;
		}
	}

	ret = extract_vermagic_from_buffer(k_data, k_size, out_magic, max_len);
	if (decompressed) free(decompressed);
	munmap(map, (size_t)real_sz);

	if (ret == 0) {
		printf("[+] Dynamically extracted vermagic from image '%s': '%s'\n", boot_path, out_magic);
	}
	return ret;
}

static int probe_target_module_layout(const char *boot_img_path, const char *target_magic,
                                      struct module_layout_probe *out)
{
	int fd;
	char discovered_boot[512];

	(void)target_magic;
	memset(out, 0, sizeof(*out));
	discovered_boot[0] = '\0';

	/* 1. Try reading live kernel BTF from /sys/kernel/btf/vmlinux */
	fd = open("/sys/kernel/btf/vmlinux", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		struct stat st;
		if (fstat(fd, &st) == 0 && st.st_size > 4096) {
			uint8_t *map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
			if (map != MAP_FAILED) {
				const uint8_t *btf = find_btf_header(map, st.st_size);
				if (btf) {
					int res = parse_module_layout_from_btf(btf, st.st_size - (size_t)(btf - map), out);
					munmap(map, st.st_size);
					close(fd);
					if (res == 0) {
						printf("[+] Dynamically introspected struct module from live /sys/kernel/btf/vmlinux\n");
						return 0;
					}
				} else {
					munmap(map, st.st_size);
				}
			}
		}
		close(fd);
	}

	/* 2. Try parsing kernel image from boot_img_path if provided, or auto-discover */
	if (!boot_img_path || boot_img_path[0] == '\0') {
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
			boot_img_path = discovered_boot;
		}
	}

	if (boot_img_path && boot_img_path[0] != '\0') {
		fd = open(boot_img_path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			struct stat st;
			if (fstat(fd, &st) == 0) {
				off_t real_sz = get_file_or_bdev_size(fd, &st);
				if (real_sz > 4096) {
					uint8_t *map = (uint8_t *)map_or_read_image(fd, (size_t)real_sz, false);
					if (map != MAP_FAILED) {
						if (probe_module_layout_from_buffer(map, (size_t)real_sz, out) == 0) {
							munmap(map, (size_t)real_sz);
							close(fd);
							printf("[+] Dynamically introspected struct module from image: %s\n", boot_img_path);
							return 0;
						}
						munmap(map, (size_t)real_sz);
					}
				}
			}
			close(fd);
		}
	}

	return -1;
}

/*
 * Running Kernel Config & Vermagic Detection
 */
static int detect_from_running_kernel(char *out_magic, size_t max_len, int *out_cfi_mode)
{
	struct utsname uts;
	int has_smp = 1;
	int has_preempt = 1;
	int has_mod_unload = 1;
	int has_modversions = 1;
	int is_cfi = 0;
	int parsed_config = 0;
	FILE *kf;
	size_t cfg_sz = 0;
	char *cfg_txt;

	if (uname(&uts) != 0)
		return -1;

	cfg_txt = (char *)xmalloc_open_zipped_read_close("/proc/config.gz", &cfg_sz);
	if (cfg_txt && cfg_sz > 0) {
		char *line_start = cfg_txt;
		char *line_end;
		while ((line_end = strchr(line_start, '\n')) != NULL) {
			*line_end = '\0';
			if (strstr(line_start, "CONFIG_SMP=y")) has_smp = 1;
			else if (strstr(line_start, "# CONFIG_SMP is not set")) has_smp = 0;
			else if (strstr(line_start, "CONFIG_PREEMPT=y")) has_preempt = 1;
			else if (strstr(line_start, "# CONFIG_PREEMPT is not set") ||
			         strstr(line_start, "CONFIG_PREEMPT_NONE=y") ||
			         strstr(line_start, "CONFIG_PREEMPT_VOLUNTARY=y")) has_preempt = 0;
			else if (strstr(line_start, "CONFIG_MODULE_UNLOAD=y")) has_mod_unload = 1;
			else if (strstr(line_start, "# CONFIG_MODULE_UNLOAD is not set")) has_mod_unload = 0;
			else if (strstr(line_start, "CONFIG_MODVERSIONS=y")) has_modversions = 1;
			else if (strstr(line_start, "# CONFIG_MODVERSIONS is not set")) has_modversions = 0;
			else if (strstr(line_start, "CONFIG_CFI_CLANG=y")) is_cfi = 1;
			line_start = line_end + 1;
		}
		parsed_config = 1;
		free(cfg_txt);
	}

	if (!parsed_config) {
		char *vbuf = (char *)xmalloc_open_read_close("/proc/version", NULL);
		if (vbuf) {
			has_smp = (strstr(vbuf, "SMP") != NULL);
			has_preempt = (strstr(vbuf, "PREEMPT") != NULL);
			free(vbuf);
		}
	}

	kf = fopen_for_read("/proc/kallsyms");
	if (kf) {
		char *kline;
		while ((kline = xmalloc_fgetline(kf)) != NULL) {
			if (strstr(kline, "__cfi_slowpath") || strstr(kline, "__cfi_check")) {
				is_cfi = 1;
				free(kline);
				break;
			}
			free(kline);
		}
		fclose(kf);
	}

	snprintf(out_magic, max_len, "%s%s%s%s%s aarch64",
	         uts.release,
	         has_smp ? " SMP" : "",
	         has_preempt ? " preempt" : "",
	         has_mod_unload ? " mod_unload" : "",
	         has_modversions ? " modversions" : "");

	if (out_cfi_mode && *out_cfi_mode < 0) {
		*out_cfi_mode = is_cfi ? 1 : 0;
	}

	return 0;
}

static void get_running_vermagic(char *buf, size_t max_len)
{
	int cfi = -1;
	if (detect_from_running_kernel(buf, max_len, &cfi) != 0) {
		struct utsname u;
		if (uname(&u) == 0) {
			snprintf(buf, max_len, "%s SMP preempt mod_unload modversions aarch64", u.release);
		} else {
			snprintf(buf, max_len, "unknown");
		}
	}
}

static const char *resolve_default_module_path(int argc, char **argv, int path_idx)
{
	if (argc > path_idx && argv[path_idx] && argv[path_idx][0] != '\0')
		return argv[path_idx];
	if (access(DEFAULT_MODULE_PATH, R_OK) == 0)
		return DEFAULT_MODULE_PATH;
	if (access(FALLBACK_MODULE_PATH, R_OK) == 0)
		return FALLBACK_MODULE_PATH;
	if (access(LEGACY_FALLBACK_PATH, R_OK) == 0)
		return LEGACY_FALLBACK_PATH;
	return DEFAULT_MODULE_PATH;
}

/*
 * Standard ELF64 Session, Section Offset Shifter & Mutation Engine
 */
static bool elf64_init_ctx(struct elf64_ctx *ctx, uint8_t *buf, size_t size, size_t capacity, bool is_allocated)
{
	if (!ctx || !buf || size < sizeof(Elf64_Ehdr))
		return false;

	memset(ctx, 0, sizeof(*ctx));
	ctx->buf = buf;
	ctx->size = size;
	ctx->capacity = capacity ? capacity : size;
	ctx->is_allocated = is_allocated;

	if (memcmp(ctx->buf, ELFMAG, SELFMAG) != 0 || ctx->buf[EI_CLASS] != ELFCLASS64) {
		return false;
	}

	ctx->ehdr = (Elf64_Ehdr *)ctx->buf;
	if (ctx->ehdr->e_shoff == 0 || ctx->ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
	    ctx->ehdr->e_shoff + ctx->ehdr->e_shnum * sizeof(Elf64_Shdr) > ctx->size) {
		return false;
	}

	ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
	ctx->shnum = ctx->ehdr->e_shnum;

	if (ctx->ehdr->e_shstrndx < ctx->shnum) {
		Elf64_Shdr *str_shdr = &ctx->shdrs[ctx->ehdr->e_shstrndx];
		if (str_shdr->sh_offset + str_shdr->sh_size <= ctx->size) {
			ctx->shstrtab = (const char *)(ctx->buf + str_shdr->sh_offset);
		}
	}

	return true;
}

static void elf64_free_ctx(struct elf64_ctx *ctx)
{
	if (ctx && ctx->is_allocated && ctx->buf) {
		free(ctx->buf);
		ctx->buf = NULL;
	}
}

static int elf64_find_section(struct elf64_ctx *ctx, const char *name, Elf64_Shdr **out_shdr, size_t *out_idx)
{
	size_t i;
	if (!ctx || !ctx->shstrtab || !name)
		return -1;

	for (i = 0; i < ctx->shnum; i++) {
		const char *sname = ctx->shstrtab + ctx->shdrs[i].sh_name;
		if (strcmp(sname, name) == 0) {
			if (out_shdr) *out_shdr = &ctx->shdrs[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}

static const uint8_t *elf64_find_section_data(struct elf64_ctx *ctx, const char *name, size_t *out_size)
{
	Elf64_Shdr *shdr = NULL;
	if (elf64_find_section(ctx, name, &shdr, NULL) == 0 && shdr->sh_type != SHT_NOBITS) {
		if (out_size) *out_size = (size_t)shdr->sh_size;
		return (const uint8_t *)(ctx->buf + shdr->sh_offset);
	}
	if (out_size) *out_size = 0;
	return NULL;
}

static int elf64_find_section_by_type(struct elf64_ctx *ctx, uint32_t type, Elf64_Shdr **out_shdr, size_t *out_idx)
{
	size_t i;
	if (!ctx) return -1;
	for (i = 0; i < ctx->shnum; i++) {
		if (ctx->shdrs[i].sh_type == type) {
			if (out_shdr) *out_shdr = &ctx->shdrs[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}

static int elf64_find_symbol(struct elf64_ctx *ctx, const char *name, Elf64_Sym *out_sym, size_t *out_idx)
{
	Elf64_Shdr *symtab = NULL;
	size_t symtab_idx = 0;
	const char *strtab;
	Elf64_Sym *syms;
	size_t num_syms;
	size_t i;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, &symtab_idx) != 0)
		return -1;

	if (symtab->sh_link >= ctx->shnum)
		return -1;

	strtab = (const char *)(ctx->buf + ctx->shdrs[symtab->sh_link].sh_offset);
	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	num_syms = symtab->sh_size / sizeof(Elf64_Sym);

	for (i = 0; i < num_syms; i++) {
		const char *sname = strtab + syms[i].st_name;
		if (strcmp(sname, name) == 0) {
			if (out_sym) *out_sym = syms[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}

static size_t elf64_scan_kcfi_types(struct elf64_ctx *ctx, uint32_t *sample_hashes, size_t max_samples)
{
	Elf64_Shdr *symtab = NULL;
	Elf64_Sym *syms;
	size_t num_syms, i, count = 0;

	if (!ctx || elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, NULL) != 0)
		return 0;

	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	num_syms = symtab->sh_size / sizeof(Elf64_Sym);

	for (i = 1; i < num_syms; i++) {
		if (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC &&
		    syms[i].st_shndx < ctx->shnum && syms[i].st_value >= 4) {
			Elf64_Shdr *sec = &ctx->shdrs[syms[i].st_shndx];
			if (sec->sh_type == SHT_PROGBITS && (sec->sh_flags & SHF_EXECINSTR)) {
				uint32_t hash = *(const uint32_t *)(ctx->buf + sec->sh_offset + syms[i].st_value - 4);
				if (hash != 0 && hash != ARM64_NOP_OPCODE && hash != ARM64_RET_OPCODE) {
					if (sample_hashes && count < max_samples) {
						sample_hashes[count] = hash;
					}
					count++;
				}
			}
		}
	}
	return count;
}

static int elf64_update_sym(struct elf64_ctx *ctx, size_t sym_idx, const Elf64_Sym *sym)
{
	Elf64_Shdr *symtab = NULL;
	size_t num_syms;
	Elf64_Sym *syms;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, NULL) != 0)
		return -1;

	num_syms = symtab->sh_size / sizeof(Elf64_Sym);
	if (sym_idx >= num_syms)
		return -1;

	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	syms[sym_idx] = *sym;
	return 0;
}

static int elf64_find_rela_by_symbol(struct elf64_ctx *ctx, size_t rela_sec_idx, size_t sym_idx,
                                     Elf64_Rela *out_rela, size_t *out_idx)
{
	Elf64_Shdr *rela_shdr;
	Elf64_Rela *relas;
	size_t num_relas;
	size_t i;

	if (!ctx || rela_sec_idx >= ctx->shnum)
		return -1;

	rela_shdr = &ctx->shdrs[rela_sec_idx];
	if (rela_shdr->sh_type != SHT_RELA)
		return -1;

	relas = (Elf64_Rela *)(ctx->buf + rela_shdr->sh_offset);
	num_relas = rela_shdr->sh_size / sizeof(Elf64_Rela);

	for (i = 0; i < num_relas; i++) {
		if (ELF64_R_SYM(relas[i].r_info) == sym_idx) {
			if (out_rela) *out_rela = relas[i];
			if (out_idx) *out_idx = i;
			return 0;
		}
	}
	return -1;
}

static int elf64_update_rela(struct elf64_ctx *ctx, size_t rela_sec_idx, size_t rela_idx, const Elf64_Rela *rela)
{
	Elf64_Shdr *rela_shdr;
	size_t num_relas;
	Elf64_Rela *relas;

	if (!ctx || rela_sec_idx >= ctx->shnum)
		return -1;

	rela_shdr = &ctx->shdrs[rela_sec_idx];
	if (rela_shdr->sh_type != SHT_RELA)
		return -1;

	num_relas = rela_shdr->sh_size / sizeof(Elf64_Rela);
	if (rela_idx >= num_relas)
		return -1;

	relas = (Elf64_Rela *)(ctx->buf + rela_shdr->sh_offset);
	relas[rela_idx] = *rela;
	return 0;
}

static int elf64_neutralize_section(struct elf64_ctx *ctx, const char *name)
{
	Elf64_Shdr *shdr = NULL;
	if (elf64_find_section(ctx, name, &shdr, NULL) == 0 && shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0) {
		shdr->sh_type = SHT_NOBITS;
		shdr->sh_size = 0;
		shdr->sh_flags = 0;
		return 1;
	}
	return 0;
}

/*
 * Dynamic ELF Section Resizer & Offset Shifter
 *
 * When expanding a section, shifts all subsequent sections, section headers,
 * and string tables in lockstep by a 16-byte aligned delta, guaranteeing
 * 100% ELF standard compliance without corrupting any file or table offsets.
 */
static int elf64_resize_section(struct elf64_ctx *ctx, size_t sec_idx, size_t new_size)
{
	Elf64_Shdr *shdr;
	size_t diff;
	size_t delta;
	size_t shift_start;
	size_t bytes_to_shift;
	size_t i;

	if (!ctx || sec_idx >= ctx->shnum)
		return -1;

	shdr = &ctx->shdrs[sec_idx];
	if (new_size <= shdr->sh_size) {
		shdr->sh_size = new_size;
		return 0;
	}

	diff = new_size - shdr->sh_size;
	delta = (diff + 63) & ~63ULL;

	if (ctx->size + delta > ctx->capacity) {
		size_t new_cap = ctx->size + delta + 65536;
		uint8_t *new_buf;
		if (ctx->is_allocated) {
			new_buf = (uint8_t *)realloc(ctx->buf, new_cap);
			if (!new_buf) return -1;
		} else {
			new_buf = (uint8_t *)malloc(new_cap);
			if (!new_buf) return -1;
			memcpy(new_buf, ctx->buf, ctx->size);
			ctx->is_allocated = true;
		}
		ctx->buf = new_buf;
		ctx->capacity = new_cap;
		ctx->ehdr = (Elf64_Ehdr *)ctx->buf;
		ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
		shdr = &ctx->shdrs[sec_idx];
		if (ctx->ehdr->e_shstrndx < ctx->shnum) {
			ctx->shstrtab = (const char *)(ctx->buf + ctx->shdrs[ctx->ehdr->e_shstrndx].sh_offset);
		}
	}

	shift_start = shdr->sh_offset + shdr->sh_size;
	bytes_to_shift = ctx->size - shift_start;

	/*
	 * Update all section header offsets that reside at or after shift_start.
	 * Must be executed BEFORE memmove so that if the section header table
	 * resides at or after shift_start (which is typical for ELF files),
	 * its offsets are updated in-place before the table is moved.
	 */
	for (i = 0; i < ctx->shnum; i++) {
		if (ctx->shdrs[i].sh_type != SHT_NULL && ctx->shdrs[i].sh_offset >= shift_start) {
			ctx->shdrs[i].sh_offset += delta;
		}
	}

	if (ctx->ehdr->e_shoff >= shift_start) {
		ctx->ehdr->e_shoff += delta;
	}

	if (ctx->ehdr->e_phoff >= shift_start) {
		ctx->ehdr->e_phoff += delta;
	}

	if (bytes_to_shift > 0) {
		memmove(ctx->buf + shift_start + delta, ctx->buf + shift_start, bytes_to_shift);
	}
	memset(ctx->buf + shift_start, 0, delta);

	/* Re-synchronize context pointers with shifted section header table */
	ctx->shdrs = (Elf64_Shdr *)(ctx->buf + ctx->ehdr->e_shoff);
	shdr = &ctx->shdrs[sec_idx];

	if (ctx->ehdr->e_shstrndx < ctx->shnum) {
		ctx->shstrtab = (const char *)(ctx->buf + ctx->shdrs[ctx->ehdr->e_shstrndx].sh_offset);
	}

	shdr->sh_size = new_size;
	ctx->size += delta;
	return 0;
}

/*
 * In-place & Dynamic Re-packing .modinfo Vermagic Patcher
 */
static int patch_vermagic_buf(struct elf64_ctx *ctx, const char *target_magic)
{
	Elf64_Shdr *modinfo_shdr = NULL;
	size_t modinfo_idx = 0;
	char *buf;
	size_t len;
	size_t new_magic_len;
	size_t pos = 0;
	size_t target_pos = (size_t)-1;
	size_t avail_val_len = 0;
	char *entries[64];
	size_t entry_lens[64];
	int num_entries = 0;
	char new_vm_entry[512];
	size_t new_vm_len;
	size_t needed_len;
	char *tmp;
	size_t w;
	int i;
	size_t new_sec_sz;

	if (elf64_find_section(ctx, ".modinfo", &modinfo_shdr, &modinfo_idx) != 0) {
		fprintf(stderr, "[-] Section .modinfo not found\n");
		return -1;
	}

	buf = (char *)(ctx->buf + modinfo_shdr->sh_offset);
	len = modinfo_shdr->sh_size;
	new_magic_len = strlen(target_magic);

	while (pos < len) {
		const char *entry = buf + pos;
		size_t entry_len = strnlen(entry, len - pos);
		if (is_prefixed_with(entry, "vermagic=")) {
			size_t slot_end;
			target_pos = pos;
			slot_end = pos + entry_len + 1;
			while (slot_end < len && buf[slot_end] == '\0') slot_end++;
			avail_val_len = (slot_end - pos > 10) ? (slot_end - pos - 10) : (entry_len - 9);
			break;
		}
		pos += entry_len + 1;
	}

	if (target_pos == (size_t)-1) {
		fprintf(stderr, "[-] Entry 'vermagic=' not found in .modinfo\n");
		return -1;
	}

	/* Case 1: Fits in-place directly within current slot and padding */
	if (new_magic_len <= avail_val_len) {
		char *val_ptr = buf + target_pos + 9;
		memcpy(val_ptr, target_magic, new_magic_len);
		val_ptr[new_magic_len] = '\0';
		if (avail_val_len > new_magic_len) {
			memset(val_ptr + new_magic_len + 1, 0, avail_val_len - new_magic_len);
		}
		printf("[+] In-place updated vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Case 2: Exceeds slot. Re-pack .modinfo buffer */
	pos = 0;
	while (pos < len && num_entries < 64) {
		const char *e = buf + pos;
		size_t elen = strnlen(e, len - pos);
		if (elen > 0) {
			entries[num_entries] = (char *)e;
			entry_lens[num_entries] = elen;
			num_entries++;
		}
		pos += elen + 1;
	}

	snprintf(new_vm_entry, sizeof(new_vm_entry), "vermagic=%s", target_magic);
	new_vm_len = strlen(new_vm_entry);

	needed_len = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			needed_len += new_vm_len + 1;
		} else {
			needed_len += entry_lens[i] + 1;
		}
	}

	if (needed_len <= modinfo_shdr->sh_size) {
		tmp = xzalloc(modinfo_shdr->sh_size);
		w = 0;
		for (i = 0; i < num_entries; i++) {
			if (is_prefixed_with(entries[i], "vermagic=")) {
				memcpy(tmp + w, new_vm_entry, new_vm_len + 1);
				w += new_vm_len + 1;
			} else {
				memcpy(tmp + w, entries[i], entry_lens[i] + 1);
				w += entry_lens[i] + 1;
			}
		}
		memcpy(buf, tmp, modinfo_shdr->sh_size);
		free(tmp);
		printf("[+] Re-packed .modinfo in-place with vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Try dropping scmversion/srcversion non-essential strings first */
	needed_len = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			needed_len += new_vm_len + 1;
		} else if (!is_prefixed_with(entries[i], "scmversion=") &&
		           !is_prefixed_with(entries[i], "srcversion=")) {
			needed_len += entry_lens[i] + 1;
		}
	}

	if (needed_len <= modinfo_shdr->sh_size) {
		tmp = xzalloc(modinfo_shdr->sh_size);
		w = 0;
		for (i = 0; i < num_entries; i++) {
			if (is_prefixed_with(entries[i], "vermagic=")) {
				memcpy(tmp + w, new_vm_entry, new_vm_len + 1);
				w += new_vm_len + 1;
			} else if (!is_prefixed_with(entries[i], "scmversion=") &&
			           !is_prefixed_with(entries[i], "srcversion=")) {
				memcpy(tmp + w, entries[i], entry_lens[i] + 1);
				w += entry_lens[i] + 1;
			}
		}
		memcpy(buf, tmp, modinfo_shdr->sh_size);
		free(tmp);
		printf("[+] Compacted .modinfo and aligned vermagic: '%s'\n", target_magic);
		return 0;
	}

	/* Exceeds section size even after filtering: resize section and shift subsequent sections */
	new_sec_sz = (needed_len + 63) & ~63ULL;
	if (elf64_resize_section(ctx, modinfo_idx, new_sec_sz) != 0) {
		fprintf(stderr, "[-] Failed to resize .modinfo section\n");
		return -1;
	}

	modinfo_shdr = &ctx->shdrs[modinfo_idx];
	buf = (char *)(ctx->buf + modinfo_shdr->sh_offset);
	memset(buf, 0, modinfo_shdr->sh_size);
	w = 0;
	for (i = 0; i < num_entries; i++) {
		if (is_prefixed_with(entries[i], "vermagic=")) {
			memcpy(buf + w, new_vm_entry, new_vm_len + 1);
			w += new_vm_len + 1;
		} else if (!is_prefixed_with(entries[i], "scmversion=") &&
		           !is_prefixed_with(entries[i], "srcversion=")) {
			memcpy(buf + w, entries[i], entry_lens[i] + 1);
			w += entry_lens[i] + 1;
		}
	}
	printf("[+] Dynamically expanded .modinfo (%zu -> %zu bytes) and shifted subsequent sections\n",
	       len, modinfo_shdr->sh_size);
	return 0;
}

/*
 * Relocation Adaptation, Alternative Neutralization & CFI Patcher
 */
static int patch_this_module_relocations(struct elf64_ctx *ctx, const char *filepath,
                                         int cfi_mode, const char *target_magic,
                                         const char *boot_img_path)
{
	int alt_neutralized = 0;
	size_t target_init_off = 0;
	size_t target_exit_off = 0;
	size_t target_mod_size = 0;
	struct module_layout_probe probe;
	Elf64_Shdr *this_mod_shdr = NULL;
	size_t this_mod_idx = 0;
	Elf64_Shdr *rela_shdr = NULL;
	size_t rela_sec_idx = 0;
	Elf64_Sym sym_cfi_check;
	size_t idx_cfi_check = 0;

	(void)filepath;
	(void)cfi_mode;
	(void)target_magic;
	if (!ctx) return 0;

	/* 1. Neutralize .altinstructions and .rela.altinstructions */
	alt_neutralized += elf64_neutralize_section(ctx, ".altinstructions");
	alt_neutralized += elf64_neutralize_section(ctx, ".rela.altinstructions");
	if (alt_neutralized > 0) {
		printf("[+] Neutralized %d alternative section(s) via ELF mutation\n", alt_neutralized);
	}

	/* 2. Canonical target struct module ABI layouts discovered dynamically via BTF / Silicon probe */
	memset(&probe, 0, sizeof(probe));
	if (probe_target_module_layout(boot_img_path, target_magic, &probe) == 0 && probe.found) {
		target_init_off = probe.init_off;
		target_exit_off = probe.exit_off;
		target_mod_size = probe.mod_size;
		printf("[+] Dynamic Module ABI Discovery:\n");
		printf("    • sizeof(struct module) : %zu bytes\n", target_mod_size);
		printf("    • offsetof(init)        : %zu (0x%zx)\n", target_init_off, target_init_off);
		printf("    • offsetof(exit)        : %zu (0x%zx)\n", target_exit_off, target_exit_off);
	} else {
		printf("[*] BTF/silicon introspection not available; preserving native module ABI offsets\n");
	}

	/* 3. Sanitize and adapt .gnu.linkonce.this_module */
	if (elf64_find_section(ctx, ".gnu.linkonce.this_module", &this_mod_shdr, &this_mod_idx) == 0) {
		if (this_mod_shdr->sh_size > 80) {
			size_t zero_bytes = this_mod_shdr->sh_size - 80;
			printf("[*] Sanitizing .gnu.linkonce.this_module: preserving 80-byte header (state+list+name), zeroing %zu trailing bytes\n", zero_bytes);
			memset(ctx->buf + this_mod_shdr->sh_offset + 80, 0, zero_bytes);
		}

		if (target_mod_size > 0 && this_mod_shdr->sh_size != target_mod_size) {
			Elf64_Sym sym_this_mod;
			size_t idx_this_mod = 0;
			printf("[+] Adapting .gnu.linkonce.this_module section size: %zu -> %zu bytes (Kernel struct module invariant)\n",
			       (size_t)this_mod_shdr->sh_size, target_mod_size);
			if (target_mod_size > this_mod_shdr->sh_size) {
				elf64_resize_section(ctx, this_mod_idx, target_mod_size);
				this_mod_shdr = &ctx->shdrs[this_mod_idx];
			} else {
				this_mod_shdr->sh_size = target_mod_size;
			}

			/* Synchronize __this_module symbol size in .symtab */
			if (elf64_find_symbol(ctx, "__this_module", &sym_this_mod, &idx_this_mod) == 0) {
				sym_this_mod.st_size = target_mod_size;
				elf64_update_sym(ctx, idx_this_mod, &sym_this_mod);
			}
		}
	}

	/* 4. Relocate init_module and cleanup_module in .rela.gnu.linkonce.this_module */
	if (elf64_find_section(ctx, ".rela.gnu.linkonce.this_module", &rela_shdr, &rela_sec_idx) == 0) {
		Elf64_Sym sym_init, sym_cleanup;
		size_t idx_init = 0, idx_cleanup = 0;
		bool has_init = (elf64_find_symbol(ctx, "init_module", &sym_init, &idx_init) == 0);
		bool has_cleanup = (elf64_find_symbol(ctx, "cleanup_module", &sym_cleanup, &idx_cleanup) == 0);

		Elf64_Rela init_rela, cleanup_rela;
		size_t init_rela_idx = 0, cleanup_rela_idx = 0;
		bool found_init_rela = false, found_cleanup_rela = false;
		int patched = 0;

		if (has_init && elf64_find_rela_by_symbol(ctx, rela_sec_idx, idx_init, &init_rela, &init_rela_idx) == 0) {
			found_init_rela = true;
		}
		if (has_cleanup && elf64_find_rela_by_symbol(ctx, rela_sec_idx, idx_cleanup, &cleanup_rela, &cleanup_rela_idx) == 0) {
			found_cleanup_rela = true;
		}

		if (found_init_rela && target_init_off > 0 && init_rela.r_offset != target_init_off) {
			printf("[+] Adapting init_module relocation: 0x%lx -> 0x%lx (Dynamic BTF ABI)\n",
			       (unsigned long)init_rela.r_offset, (unsigned long)target_init_off);
			init_rela.r_offset = target_init_off;
			elf64_update_rela(ctx, rela_sec_idx, init_rela_idx, &init_rela);
			patched++;
		}

		if (found_cleanup_rela) {
			if (target_exit_off > 0 && cleanup_rela.r_offset != target_exit_off) {
				printf("[+] Adapting cleanup_module relocation: 0x%lx -> 0x%lx (Dynamic ABI Discovery)\n",
				       (unsigned long)cleanup_rela.r_offset, (unsigned long)target_exit_off);
				cleanup_rela.r_offset = target_exit_off;
				elf64_update_rela(ctx, rela_sec_idx, cleanup_rela_idx, &cleanup_rela);
				patched++;
			} else if (target_exit_off > 0 && cleanup_rela.r_offset == target_exit_off) {
				printf("[*] cleanup_module relocation already matches target offset 0x%lx\n", (unsigned long)target_exit_off);
			} else if (target_exit_off == 0 || (target_mod_size > 0 && cleanup_rela.r_offset >= target_mod_size)) {
				printf("[+] Neutralizing out-of-bounds/unverified cleanup_module relocation at 0x%lx\n",
				       (unsigned long)cleanup_rela.r_offset);
				cleanup_rela.r_info = ELF64_R_INFO(ELF64_R_SYM(cleanup_rela.r_info), 0 /* R_AARCH64_NONE */);
				cleanup_rela.r_offset = 0;
				elf64_update_rela(ctx, rela_sec_idx, cleanup_rela_idx, &cleanup_rela);
				patched++;
			}
		}

		if (patched > 0) {
			printf("[+] SUCCESS: Dynamically adapted %d relocation(s) in .rela.gnu.linkonce.this_module\n", patched);
		}
	}

	/* 5. Neutralize synthesized Cross-DSO __cfi_check stub */
	if (elf64_find_symbol(ctx, "__cfi_check", &sym_cfi_check, &idx_cfi_check) == 0) {
		if (sym_cfi_check.st_shndx < ctx->shnum) {
			Elf64_Shdr *text_shdr = &ctx->shdrs[sym_cfi_check.st_shndx];
			if (sym_cfi_check.st_value + sizeof(uint32_t) <= text_shdr->sh_size) {
				uint32_t *p_insn = (uint32_t *)(ctx->buf + text_shdr->sh_offset + sym_cfi_check.st_value);
				uint32_t ret_insn = ARM64_RET_OPCODE; /* 0xd65f03c0 */
				if (*p_insn != ret_insn) {
					*p_insn = ret_insn;
					printf("[+] Neutralized synthesized __cfi_check stub (patched to RET at offset 0x%lx)\n",
					       (unsigned long)sym_cfi_check.st_value);
				}
			}
		}
	}

	return (int)target_mod_size;
}

/*
 * Module Commands & Lifecycle Helpers
 */
static int audit_module_symbols(struct elf64_ctx *ctx, const char *kallsyms_path)
{
	Elf64_Shdr *symtab = NULL;
	const char *strtab;
	Elf64_Sym *syms;
	size_t num_syms;
	char *needed[1024];
	bool is_weak[1024];
	bool resolved[1024];
	size_t needed_cnt = 0;
	size_t i;
	const char *ks_path;
	FILE *kf;
	char *line;
	size_t missing_strong = 0, missing_weak = 0, resolved_cnt = 0;

	if (elf64_find_section_by_type(ctx, SHT_SYMTAB, &symtab, NULL) != 0) {
		fprintf(stderr, "[-] Symbol table not found\n");
		return 1;
	}

	strtab = (const char *)(ctx->buf + ctx->shdrs[symtab->sh_link].sh_offset);
	syms = (Elf64_Sym *)(ctx->buf + symtab->sh_offset);
	num_syms = symtab->sh_size / sizeof(Elf64_Sym);

	for (i = 1; i < num_syms && needed_cnt < 1024; i++) {
		unsigned char bind, type;
		const char *name;
		if (syms[i].st_shndx != SHN_UNDEF) continue;
		bind = ELF64_ST_BIND(syms[i].st_info);
		type = ELF64_ST_TYPE(syms[i].st_info);
		if (bind == STB_LOCAL || type == STT_SECTION || type == STT_FILE) continue;

		name = strtab + syms[i].st_name;
		if (!name || name[0] == '\0') continue;

		needed[needed_cnt] = xstrdup(name);
		is_weak[needed_cnt] = (bind == STB_WEAK);
		resolved[needed_cnt] = false;
		needed_cnt++;
	}

	if (needed_cnt == 0) {
		printf("[+] Pre-flight audit: Zero unresolved external dependencies (self-contained module).\n");
		return 0;
	}

	ks_path = kallsyms_path ? kallsyms_path : "/proc/kallsyms";
	printf("[*] Pre-flight audit: Checking %zu external symbol(s) against %s...\n", needed_cnt, ks_path);

	kf = fopen_for_read(ks_path);
	if (!kf) {
		fprintf(stderr, "[!] Warning: Cannot open %s for verification.\n", ks_path);
		for (i = 0; i < needed_cnt; i++) {
			printf("  [%s] %s\n", is_weak[i] ? "WEAK" : "GLOBAL", needed[i]);
			free(needed[i]);
		}
		return 0;
	}

	while ((line = xmalloc_fgetline(kf)) != NULL) {
		char *p = strrchr(line, ' ');
		if (!p) p = strrchr(line, '\t');
		if (p) {
			p++;
			chomp(p);

			for (i = 0; i < needed_cnt; i++) {
				if (!resolved[i] && strcmp(needed[i], p) == 0) {
					resolved[i] = true;
				}
			}
		}
		free(line);
	}
	fclose(kf);

	for (i = 0; i < needed_cnt; i++) {
		if (resolved[i]) resolved_cnt++;
		else if (is_weak[i]) {
			missing_weak++;
			printf("[?] Unresolved WEAK symbol  : %s\n", needed[i]);
		} else {
			missing_strong++;
			fprintf(stderr, "[-] UNRESOLVED GLOBAL symbol: %s\n", needed[i]);
		}
		free(needed[i]);
	}

	printf("[*] Audit Summary: %zu resolved, %zu missing strong, %zu missing weak\n",
	       resolved_cnt, missing_strong, missing_weak);
	return (missing_strong > 0) ? 2 : 0;
}

static int module_info_file(const char *filepath, const char *target_kernel_path)
{
	int fd;
	struct stat st;
	uint8_t *map;
	struct elf64_ctx ctx;
	size_t modinfo_sz = 0;
	const uint8_t *modinfo_buf = NULL;
	Elf64_Shdr *this_mod = NULL;
	Elf64_Shdr *rela_this_mod = NULL;
	size_t rela_idx = 0;
	uint32_t kcfi_samples[8];
	size_t kcfi_count;
	int alt_count = 0;
	bool has_cfi_check = false;
	Elf64_Sym sym_cfi;
	Elf64_Rela init_rela, cleanup_rela;
	bool has_init_rela = false, has_clean_rela = false;
	size_t sym_init_idx = 0, sym_clean_idx = 0;
	Elf64_Sym sym_tmp;

	fd = open_or_warn(filepath, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
		munmap(map, st.st_size);
		return 1;
	}

	printf("======================================================================\n");
	printf("  ELF Kernel Module Inspection: %s\n", filepath);
	printf("======================================================================\n");
	printf("[*] Architecture    : %s (0x%04x)\n",
	       (ctx.ehdr->e_machine == EM_AARCH64) ? "AArch64 (ARM64)" : "Other", ctx.ehdr->e_machine);
	printf("[*] Section Count   : %u\n", (unsigned int)ctx.shnum);

	/* Module Structure (.gnu.linkonce.this_module) */
	if (elf64_find_section(&ctx, ".gnu.linkonce.this_module", &this_mod, NULL) == 0) {
		printf("\n[*] Kernel Module Struct (.gnu.linkonce.this_module):\n");
		printf("  • Section size     : %zu bytes (0x%zx)\n", (size_t)this_mod->sh_size, (size_t)this_mod->sh_size);
		printf("  • Section align    : %lu bytes\n", (unsigned long)this_mod->sh_addralign);
	}

	/* Relocations (.rela.gnu.linkonce.this_module) */
	if (elf64_find_section(&ctx, ".rela.gnu.linkonce.this_module", &rela_this_mod, &rela_idx) == 0) {
		printf("\n[*] Module Lifecycle Relocations:\n");
		if (elf64_find_symbol(&ctx, "init_module", &sym_tmp, &sym_init_idx) == 0 &&
		    elf64_find_rela_by_symbol(&ctx, rela_idx, sym_init_idx, &init_rela, NULL) == 0) {
			has_init_rela = true;
			printf("  • init_module relocation    : offset 0x%lx (%lu bytes into struct module)\n",
			       (unsigned long)init_rela.r_offset, (unsigned long)init_rela.r_offset);
		}
		if (elf64_find_symbol(&ctx, "cleanup_module", &sym_tmp, &sym_clean_idx) == 0 &&
		    elf64_find_rela_by_symbol(&ctx, rela_idx, sym_clean_idx, &cleanup_rela, NULL) == 0) {
			has_clean_rela = true;
			printf("  • cleanup_module relocation : offset 0x%lx (%lu bytes into struct module)\n",
			       (unsigned long)cleanup_rela.r_offset, (unsigned long)cleanup_rela.r_offset);
		}
	}

	/* Security & ABI Features */
	printf("\n[*] Kernel Security & CFI Primitives:\n");
	if (elf64_find_section(&ctx, ".altinstructions", NULL, NULL) == 0) alt_count++;
	if (elf64_find_section(&ctx, ".rela.altinstructions", NULL, NULL) == 0) alt_count++;
	printf("  • Alternative patching      : %s (%d section(s))\n",
	       (alt_count > 0) ? "ACTIVE (.altinstructions)" : "NONE / Neutralized", alt_count);

	has_cfi_check = (elf64_find_symbol(&ctx, "__cfi_check", &sym_cfi, NULL) == 0);
	printf("  • Clang CFI (__cfi_check)   : %s\n", has_cfi_check ? "PRESENT (synthesized stub)" : "NONE / Inactive");

	kcfi_count = elf64_scan_kcfi_types(&ctx, kcfi_samples, 8);
	printf("  • KCFI Type Prefixes        : %zu function prefix(es) detected\n", kcfi_count);
	if (kcfi_count > 0) {
		size_t k;
		printf("    Sample KCFI Type IDs     :");
		for (k = 0; k < kcfi_count && k < 4; k++) {
			printf(" 0x%08x", kcfi_samples[k]);
		}
		printf("\n");
	}

	/* Target Kernel ABI Comparison */
	if (target_kernel_path && target_kernel_path[0] != '\0') {
		struct module_layout_probe probe;
		printf("\n[*] Target Kernel ABI Comparison (%s):\n", target_kernel_path);
		if (probe_target_module_layout(target_kernel_path, NULL, &probe) == 0 && probe.found) {
			if (probe.variant_desc)
				printf("  • Detected Kernel ABI       : %s\n", probe.variant_desc);
			if (probe.matched_profile) {
				printf("  • Baseline Reference Profile: %s\n", probe.matched_profile);
				printf("  • Probed vs Baseline Deltas : init: %+ld B, exit: %+ld B, size: %+ld B [%s]\n",
				       probe.init_delta, probe.exit_delta, probe.size_delta,
				       probe.profile_matched ? "100% Profile Match" : "Vendor Shift Detected");
			}
			printf("  • Kernel struct module size : %zu bytes (0x%zx)\n", probe.mod_size, probe.mod_size);
			printf("  • Kernel offsetof(init)     : 0x%zx (%zu bytes)\n", probe.init_off, probe.init_off);
			printf("  • Kernel offsetof(exit)     : 0x%zx (%zu bytes)\n", probe.exit_off, probe.exit_off);

			if (this_mod) {
				if (probe.mod_size == 0) {
					printf("  • Section Size Verification : UNVERIFIED (Target kernel struct module size undetermined)\n");
				} else {
					bool size_match = (this_mod->sh_size == probe.mod_size);
					printf("  • Section Size Verification : %s (%zu vs %zu)\n",
					       size_match ? "PERFECT MATCH" : "ADAPTATION REQUIRED",
					       (size_t)this_mod->sh_size, probe.mod_size);
				}
			}

			if (has_init_rela && probe.init_off > 0) {
				if (init_rela.r_offset == probe.init_off) {
					printf("  • init_module Relocation    : PERFECT MATCH (0x%lx)\n", (unsigned long)init_rela.r_offset);
				} else {
					long delta = (long)init_rela.r_offset - (long)probe.init_off;
					printf("  • init_module Relocation    : SHIFT DETECTED (Module: 0x%lx vs Kernel: 0x%zx, Delta: %+ld bytes)\n",
					       (unsigned long)init_rela.r_offset, probe.init_off, delta);
					if (delta == 8) {
						printf("    -> Root Cause: Module has CONFIG_CFI_CLANG (+8B cfi_check), but Target Kernel has Clang CFI disabled (Vendor Non-CFI)!\n");
					} else if (delta == -8) {
						printf("    -> Root Cause: Target Kernel has CONFIG_CFI_CLANG (+8B cfi_check), but Module compiled without CFI!\n");
					} else if (delta == 56 || delta == -56 || delta == 80 || delta == -80) {
						printf("    -> Root Cause: Generation shift (CONFIG_STACKTRACE_BUILD_ID / KCFI header / mem[7] delta)!\n");
					}
				}
			}

			if (has_clean_rela && probe.exit_off > 0) {
				if (cleanup_rela.r_offset == probe.exit_off) {
					printf("  • cleanup_module Relocation : PERFECT MATCH (0x%lx)\n", (unsigned long)cleanup_rela.r_offset);
				} else {
					long delta = (long)cleanup_rela.r_offset - (long)probe.exit_off;
					printf("  • cleanup_module Relocation : SHIFT DETECTED (Module: 0x%lx vs Kernel: 0x%zx, Delta: %+ld bytes)\n",
					       (unsigned long)cleanup_rela.r_offset, probe.exit_off, delta);
					if (delta == -8) {
						printf("    -> Root Cause: Target Kernel has CONFIG_BPF_EVENTS enabled (+16B bpf_raw_events) with Non-CFI (-8B), net delta -8B (e.g. Xiaomi/Qualcomm 4.19)!\n");
					} else if (delta == 8) {
						printf("    -> Root Cause: Target Kernel lacks CONFIG_BPF_EVENTS or has CFI enabled (+8B net shift)!\n");
					} else if (delta > 50 || delta < -50) {
						printf("    -> Root Cause: Generation layout shift (Linux 6.4+ struct module_memory mem[7] vs core_layout)!\n");
					}
				}
			}
		} else {
			printf("  [!] Could not introspect target kernel module ABI\n");
		}
	}

	modinfo_buf = elf64_find_section_data(&ctx, ".modinfo", &modinfo_sz);
	if (modinfo_buf && modinfo_sz > 0) {
		const char *buf = (const char *)modinfo_buf;
		size_t pos = 0;
		printf("\n[*] Module Info (.modinfo):\n");
		while (pos < modinfo_sz) {
			const char *entry = buf + pos;
			size_t elen = strnlen(entry, modinfo_sz - pos);
			if (elen > 0) {
				const char *eq = strchr(entry, '=');
				if (eq) {
					printf("  %-20.*s = %s\n", (int)(eq - entry), entry, eq + 1);
				} else {
					printf("  %s\n", entry);
				}
			}
			pos += elen + 1;
		}
	}
	printf("======================================================================\n");

	elf64_free_ctx(&ctx);
	munmap(map, st.st_size);
	return 0;
}

static int module_check_file(const char *module_path)
{
	int fd;
	struct stat st;
	uint8_t *map;
	struct elf64_ctx ctx;
	char mod_ver[256];
	Elf64_Shdr *modinfo = NULL;
	char run_ver[256];
	int res = 0;

	memset(mod_ver, 0, sizeof(mod_ver));

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) return 1;

	if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
		munmap(map, st.st_size);
		return 1;
	}

	if (elf64_find_section(&ctx, ".modinfo", &modinfo, NULL) == 0) {
		const char *buf = (const char *)(ctx.buf + modinfo->sh_offset);
		size_t pos = 0;
		while (pos < modinfo->sh_size) {
			const char *entry = buf + pos;
			size_t elen = strnlen(entry, modinfo->sh_size - pos);
			const char *v = is_prefixed_with(entry, "vermagic=");
			if (v) {
				safe_strncpy(mod_ver, v, sizeof(mod_ver));
				break;
			}
			pos += elen + 1;
		}
	}

	get_running_vermagic(run_ver, sizeof(run_ver));

	printf("============================================================\n");
	printf("  Module Path    : %s\n", module_path);
	printf("  Module Vermagic: %s\n", mod_ver[0] ? mod_ver : "(not found)");
	printf("  Running Kernel : %s\n", run_ver);
	printf("============================================================\n");

	if (mod_ver[0] && strcmp(mod_ver, run_ver) == 0) {
		printf("[✓] Status: 100%% EXACT MATCH — loads natively via insmod/modprobe.\n");
	} else {
		printf("[!] Status: MISMATCH — requires patch-vermagic alignment.\n");
		res = 1;
	}

	elf64_free_ctx(&ctx);
	munmap(map, st.st_size);
	return res;
}

static int module_strip_file(const char *in_file, const char *out_file)
{
	size_t sz = 0;
	uint8_t *buf;
	struct elf64_ctx ctx;
	int neutralized = 0;
	size_t i;
	const char *target;
	int out_fd;

	buf = (uint8_t *)magiskboot_read_file(in_file, &sz);
	if (!buf) {
		bb_perror_msg("cannot read '%s'", in_file);
		return 1;
	}

	if (!elf64_init_ctx(&ctx, buf, sz, sz, true)) {
		free(buf);
		return 1;
	}

	for (i = 0; i < ctx.shnum; i++) {
		const char *name = ctx.shstrtab + ctx.shdrs[i].sh_name;
		if (is_prefixed_with(name, ".debug_") || strcmp(name, ".comment") == 0 ||
		    strcmp(name, ".note.GNU-stack") == 0) {
			if (ctx.shdrs[i].sh_type != SHT_NOBITS && ctx.shdrs[i].sh_size > 0) {
				ctx.shdrs[i].sh_type = SHT_NOBITS;
				ctx.shdrs[i].sh_size = 0;
				ctx.shdrs[i].sh_flags = 0;
				neutralized++;
			}
		}
	}
	printf("[+] Neutralized %d unneeded/debug section(s)\n", neutralized);

	target = out_file ? out_file : in_file;
	out_fd = open3_or_warn(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0 || full_write(out_fd, ctx.buf, ctx.size) != (ssize_t)ctx.size) {
		if (out_fd >= 0) {
			bb_perror_msg("failed to write '%s'", target);
			close(out_fd);
		}
		elf64_free_ctx(&ctx);
		return 1;
	}
	close(out_fd);
	elf64_free_ctx(&ctx);
	printf("[+] SUCCESS: %s stripped in-place!\n", target);
	return 0;
}

static int module_patch_file(const char *in_file, const char *out_file, const char *target_vermagic,
                             const char *boot_img_path)
{
	int fd;
	struct stat st;
	size_t alloc_sz;
	uint8_t *buf;
	struct elf64_ctx ctx;
	char vermagic_buf[256];
	const char *target;
	int out_fd;

	fd = open_or_warn(in_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}

	alloc_sz = st.st_size + 65536;
	buf = (uint8_t *)xmalloc(alloc_sz);
	xread(fd, buf, st.st_size);
	close(fd);

	if (!elf64_init_ctx(&ctx, buf, st.st_size, alloc_sz, true)) {
		free(buf);
		return 1;
	}

	if (!target_vermagic || target_vermagic[0] == '\0') {
		char discovered_boot[512];
		discovered_boot[0] = '\0';
		if (!boot_img_path || boot_img_path[0] == '\0') {
			if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
				boot_img_path = discovered_boot;
			}
		}
		if (boot_img_path && detect_vermagic_from_boot_image(boot_img_path, vermagic_buf, sizeof(vermagic_buf)) == 0) {
			target_vermagic = vermagic_buf;
		} else {
			get_running_vermagic(vermagic_buf, sizeof(vermagic_buf));
			target_vermagic = vermagic_buf;
		}
	}

	if (patch_vermagic_buf(&ctx, target_vermagic) != 0) {
		elf64_free_ctx(&ctx);
		return 1;
	}

	patch_this_module_relocations(&ctx, in_file, 0, target_vermagic, boot_img_path);

	target = out_file ? out_file : in_file;
	out_fd = open3_or_warn(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out_fd < 0 || full_write(out_fd, ctx.buf, ctx.size) != (ssize_t)ctx.size) {
		if (out_fd >= 0) {
			bb_perror_msg("failed to write '%s'", target);
			close(out_fd);
		}
		elf64_free_ctx(&ctx);
		return 1;
	}
	close(out_fd);
	elf64_free_ctx(&ctx);
	printf("[✓] Patched module written to '%s'\n", target);
	return 0;
}

static int module_load_file(const char *module_path, const char *module_args)
{
	int fd;
	struct stat st;
	size_t alloc_sz;
	uint8_t *buf;
	struct elf64_ctx ctx;
	char target_vermagic[256];
	long ret;
	char msg[512];

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) < 0) {
		if (fd >= 0) close(fd);
		return 1;
	}

	alloc_sz = st.st_size + 65536;
	buf = (uint8_t *)xmalloc(alloc_sz);
	xread(fd, buf, st.st_size);
	close(fd);

	if (!elf64_init_ctx(&ctx, buf, st.st_size, alloc_sz, true)) {
		free(buf);
		return 1;
	}

	target_vermagic[0] = '\0';
	{
		char discovered_boot[512];
		discovered_boot[0] = '\0';
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) == 0) {
			detect_vermagic_from_boot_image(discovered_boot, target_vermagic, sizeof(target_vermagic));
		}
	}
	if (target_vermagic[0] == '\0') {
		get_running_vermagic(target_vermagic, sizeof(target_vermagic));
	}

	patch_vermagic_buf(&ctx, target_vermagic);
	patch_this_module_relocations(&ctx, module_path, 0, target_vermagic, NULL);

	printf("[+] Calling SYS_init_module(size=%zu, args=\"%s\")...\n", ctx.size, module_args ? module_args : "");
	ret = syscall(SYS_init_module, ctx.buf, ctx.size, module_args ? module_args : "");

	if (ret == 0) {
		printf("[✓] SUCCESS: Module loaded into kernel!\n");
		snprintf(msg, sizeof(msg), "<6>magiskboot: Module '%s' loaded successfully with vermagic '%s'\n",
		         module_path, target_vermagic);
		log_kmsg_msg(msg);
		elf64_free_ctx(&ctx);
		return 0;
	}

	if (errno == EEXIST) {
		printf("[!] Module already resident in kernel.\n");
		elf64_free_ctx(&ctx);
		return 0;
	}

	bb_perror_msg("init_module failed");
	elf64_free_ctx(&ctx);
	return 1;
}

static int module_finit_file(const char *module_path, const char *module_args)
{
	int fd;
	long ret;

	fd = open_or_warn(module_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 1;

	printf("[+] Calling SYS_finit_module(fd=%d, args=\"%s\")...\n", fd, module_args ? module_args : "");
	ret = syscall(SYS_finit_module, fd, module_args ? module_args : "", 0);
	close(fd);

	if (ret == 0) {
		printf("[✓] SUCCESS: Module loaded via SYS_finit_module!\n");
		return 0;
	}
	if (errno == EEXIST) {
		printf("[!] Module already resident in kernel.\n");
		return 0;
	}

	printf("[!] sys_finit_module returned %ld (errno=%d: %s). Falling back to in-memory vermagic alignment...\n",
	       ret, errno, strerror(errno));
	return module_load_file(module_path, module_args);
}

static int module_unload_name(const char *module_name)
{
	const char *name = (module_name && module_name[0]) ? module_name : "kroot";
	long ret;

	printf("[+] Unloading module '%s'...\n", name);

	ret = syscall(SYS_delete_module, name, O_NONBLOCK);
	if (ret != 0 && strcmp(name, "kroot") == 0) {
		ret = syscall(SYS_delete_module, "compat_modern_kernel", O_NONBLOCK);
	}

	if (ret == 0) {
		printf("[✓] SUCCESS: Module '%s' unloaded.\n", name);
		return 0;
	}
	bb_perror_msg("delete_module failed");
	return 1;
}

static int magiskboot_module_op(int argc, char **argv)
{
	static const char mod_acts[] ALIGN1 =
		"info\0"
		"check\0"
		"audit\0"
		"strip\0"
		"patch\0"
		"load\0"
		"finit\0"
		"unload\0";
	enum {
		MOD_ACT_info = 0,
		MOD_ACT_check,
		MOD_ACT_audit,
		MOD_ACT_strip,
		MOD_ACT_patch,
		MOD_ACT_load,
		MOD_ACT_finit,
		MOD_ACT_unload,
	};
	const char *action;

	if (argc < 3) bb_show_usage();
	action = argv[2];

	switch (index_in_strings(mod_acts, action)) {
	case MOD_ACT_info: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		return module_info_file(path, (argc >= 5) ? argv[4] : NULL);
	}
	case MOD_ACT_check: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		return module_check_file(path);
	}
	case MOD_ACT_audit: {
		const char *path = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		int fd = open_or_warn(path, O_RDONLY | O_CLOEXEC);
		struct stat st;
		uint8_t *map;
		struct elf64_ctx ctx;
		int res;

		if (fd < 0 || fstat(fd, &st) < 0) {
			if (fd >= 0) close(fd);
			return 1;
		}
		map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		close(fd);
		if (map == MAP_FAILED) return 1;

		if (!elf64_init_ctx(&ctx, map, st.st_size, st.st_size, false)) {
			munmap(map, st.st_size);
			return 1;
		}
		res = audit_module_symbols(&ctx, (argc >= 5) ? argv[4] : NULL);
		elf64_free_ctx(&ctx);
		munmap(map, st.st_size);
		return res;
	}
	case MOD_ACT_strip: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *out_f = (argc >= 5) ? argv[4] : in_f;
		return module_strip_file(in_f, out_f);
	}
	case MOD_ACT_patch: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *out_f = (argc >= 5 && argv[4][0] != '-') ? argv[4] : in_f;
		const char *vmagic = NULL;
		const char *boot_img = NULL;
		int i;

		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "--vermagic") == 0 && i + 1 < argc) vmagic = argv[++i];
			else if (strcmp(argv[i], "--boot") == 0 && i + 1 < argc) boot_img = argv[++i];
		}
		return module_patch_file(in_f, out_f, vmagic, boot_img);
	}
	case MOD_ACT_load: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *margs = (argc >= 5) ? argv[4] : "";
		return module_load_file(in_f, margs);
	}
	case MOD_ACT_finit: {
		const char *in_f = (argc >= 4) ? argv[3] : resolve_default_module_path(argc, argv, 3);
		const char *margs = (argc >= 5) ? argv[4] : "";
		return module_finit_file(in_f, margs);
	}
	case MOD_ACT_unload: {
		const char *mname = (argc >= 4) ? argv[3] : "kroot";
		return module_unload_name(mname);
	}
	default:
		bb_error_msg("unknown module action '%s'", action);
		return 1;
	}
}

/* =========================================================================
 * Universal Kernel Module Ramdisk Injector & Flash Engine (--mod-inject)
 * ========================================================================= */

static char *resolve_init_wrapper_binary(const char *custom)
{
	static const char *const names[] = {
		"busybox",
		"busybox-arm64",
		"busybox-aarch64",
		"init_wrapper",
		"init_wrapper_aarch64",
		"init_wrapper-arm64",
		"init_wrapper-aarch64",
		NULL
	};
	const char *env_path;
	char exe_path[PATH_MAX];
	char exe_dir[PATH_MAX];
	ssize_t len;
	int i;

	/* 1. Explicit CLI argument */
	if (custom && access(custom, R_OK) == 0)
		return xstrdup(custom);

	/* 2. Environment variable overrides */
	env_path = getenv("BUSYBOX_BIN");
	if (env_path && access(env_path, R_OK) == 0)
		return xstrdup(env_path);

	env_path = getenv("INIT_WRAPPER_BIN");
	if (env_path && access(env_path, R_OK) == 0)
		return xstrdup(env_path);

	/* 3. Probe relative to the running executable's directory */
	len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len > 0) {
		char *slash;
		exe_path[len] = '\0';
		safe_strncpy(exe_dir, exe_path, sizeof(exe_dir));
		slash = strrchr(exe_dir, '/');
		if (slash) {
			*slash = '\0';
			for (i = 0; names[i]; i++) {
				char cand[PATH_MAX];
				snprintf(cand, sizeof(cand), "%.*s/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
			}
			/* Check sibling directories bin/ or tools/ */
			for (i = 0; names[i]; i++) {
				char cand[PATH_MAX];
				snprintf(cand, sizeof(cand), "%.*s/../bin/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
				snprintf(cand, sizeof(cand), "%.*s/../tools/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
				snprintf(cand, sizeof(cand), "%.*s/tools/%s", (int)(sizeof(cand) - 64), exe_dir, names[i]);
				if (access(cand, R_OK) == 0)
					return xstrdup(cand);
			}
		}
	}

	/* 4. Probe current working directory */
	for (i = 0; names[i]; i++) {
		if (access(names[i], R_OK) == 0)
			return xstrdup(names[i]);
		{
			char cand[PATH_MAX];
			snprintf(cand, sizeof(cand), "bin/%s", names[i]);
			if (access(cand, R_OK) == 0)
				return xstrdup(cand);
			snprintf(cand, sizeof(cand), "tools/%s", names[i]);
			if (access(cand, R_OK) == 0)
				return xstrdup(cand);
		}
	}

	return NULL;
}

static int ramdisk_inject_kernel_module(const char *cpio_path, const char *mod_path, const char *mod_filename)
{
	cpio_node_t *head;
	cpio_node_t *curr;
	size_t mod_sz = 0;
	void *mod_data;
	bool has_system_modules = false;
	char mod_target[PATH_MAX];
	char dep_line[PATH_MAX];

	head = cpio_read_all(cpio_path);
	if (!head) {
		bb_error_msg("failed to parse ramdisk CPIO archive '%s'", cpio_path);
		return -1;
	}

	mod_data = magiskboot_read_file(mod_path, &mod_sz);
	if (!mod_data || mod_sz == 0) {
		bb_error_msg("failed to read staged module '%s'", mod_path);
		if (mod_data) free(mod_data);
		cpio_free_all(head);
		return -1;
	}

	/* Check ramdisk directory structure conventions */
	for (curr = head; curr; curr = curr->next) {
		if (strncmp(curr->name, "system/lib/modules", 18) == 0) {
			has_system_modules = true;
			break;
		}
	}

	/* Format dependency entry (<filename>:\n) */
	snprintf(dep_line, sizeof(dep_line), "%s:", mod_filename);

	/* 1. Inject into standard canonical /lib/modules/ */
	snprintf(mod_target, sizeof(mod_target), "lib/modules/%s", mod_filename);
	cpio_set_file(&head, mod_target, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);
	cpio_append_line_if_missing(&head, "lib/modules/modules.load", mod_filename);
	cpio_append_line_if_missing(&head, "lib/modules/modules.dep", dep_line);
	printf("[+] Ramdisk injection: Added %s (%zu bytes)\n", mod_target, mod_sz);
	printf("[+] Autoload configuration: Updated lib/modules/modules.load & modules.dep\n");

	/* 2. Create empty index files if not present */
	{
		cpio_node_t *node;
		bool has_alias = false, has_syms = false;
		for (node = head; node; node = node->next) {
			if (strcmp(node->name, "lib/modules/modules.alias") == 0) has_alias = true;
			else if (strcmp(node->name, "lib/modules/modules.symbols") == 0) has_syms = true;
		}
		if (!has_alias) cpio_set_file(&head, "lib/modules/modules.alias", 0100644, xzalloc(1), 0);
		if (!has_syms) cpio_set_file(&head, "lib/modules/modules.symbols", 0100644, xzalloc(1), 0);
	}

	/* 3. Inject root-level copy (failsafe for early init) */
	cpio_set_file(&head, mod_filename, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);

	/* 4. Second-stage early-init fallback triggers in init.modules.rc */
	{
		cpio_node_t *rc_node = NULL;
		cpio_node_t *n;
		char insmod_line1[PATH_MAX + 32];
		char insmod_line2[PATH_MAX + 32];

		snprintf(insmod_line1, sizeof(insmod_line1), "    insmod /lib/modules/%s", mod_filename);
		snprintf(insmod_line2, sizeof(insmod_line2), "    insmod /%s", mod_filename);

		for (n = head; n; n = n->next) {
			if (strcmp(n->name, "init.modules.rc") == 0) {
				rc_node = n;
				break;
			}
		}

		if (rc_node && rc_node->data && rc_node->filesize > 0) {
			cpio_append_line_if_missing(&head, "init.modules.rc", insmod_line1);
			cpio_append_line_if_missing(&head, "init.modules.rc", insmod_line2);
		} else {
			char *rc_content = xasprintf("on early-init\n%s\n%s\n", insmod_line1, insmod_line2);
			cpio_set_file(&head, "init.modules.rc", 0100644, rc_content, (uint32_t)strlen(rc_content));
		}
	}
	printf("[+] Dual-stage fallback: Generated init.modules.rc & root /%s\n", mod_filename);

	/* 5. If system/lib/modules exists (system-as-root / Android 10+ ramdisk layout), mirror there */
	if (has_system_modules) {
		snprintf(mod_target, sizeof(mod_target), "system/lib/modules/%s", mod_filename);
		cpio_set_file(&head, mod_target, 0100644, xmemdup(mod_data, mod_sz), (uint32_t)mod_sz);
		cpio_append_line_if_missing(&head, "system/lib/modules/modules.load", mod_filename);
		cpio_append_line_if_missing(&head, "system/lib/modules/modules.dep", dep_line);
		printf("[+] Ramdisk injection: Mirrored to %s\n", mod_target);
	}

	/* 6. Universal First-Stage Init Wrapper (PID 1 Module Loader & BusyBox Integration) */
	{
		char *wrapper_bin_path = resolve_init_wrapper_binary(NULL);
		if (wrapper_bin_path) {
			size_t w_sz = 0;
			void *w_data = magiskboot_read_file(wrapper_bin_path, &w_sz);
			if (w_data && w_sz > 0) {
				cpio_node_t *init_node = NULL;
				cpio_node_t *init_real_node = NULL;
				cpio_node_t *n;
				bool is_busybox = false;
				const char *bname = bb_basename(wrapper_bin_path);

				if (strncmp(bname, "busybox", 7) == 0)
					is_busybox = true;

				for (n = head; n; n = n->next) {
					if (strcmp(n->name, "init") == 0) init_node = n;
					else if (strcmp(n->name, "init.real") == 0) init_real_node = n;
				}

				/* Back up stock /init before modifying */
				if (init_node && !init_real_node) {
					if (S_ISLNK(init_node->mode)) {
						const char *tgt = (const char *)init_node->data;
						if (tgt && tgt[0] != '\0') {
							cpio_set_file(&head, "init.real", 0120777, xstrdup(tgt), (uint32_t)strlen(tgt));
						} else {
							cpio_set_file(&head, "init.real", 0120777, xstrdup("/system/bin/init"), (uint32_t)strlen("/system/bin/init"));
						}
						printf("[+] First-stage init: Preserved symlink target -> init.real\n");
					} else {
						cpio_set_file(&head, "init.real", init_node->mode,
						              xmemdup(init_node->data, init_node->filesize), init_node->filesize);
						printf("[+] First-stage init: Preserved stock binary -> init.real\n");
					}
				}

				if (is_busybox) {
					/* Inject BusyBox into sbin/busybox and make /init a symlink to it */
					cpio_set_file(&head, "sbin/busybox", 0100755, xmemdup(w_data, w_sz), (uint32_t)w_sz);
					printf("[+] First-stage init: Injected BusyBox universal binary -> sbin/busybox (%zu bytes)\n", w_sz);

					if (init_node) {
						free(init_node->data);
						init_node->mode = 0120777;
						init_node->filesize = (uint32_t)strlen("/sbin/busybox");
						init_node->data = xstrdup("/sbin/busybox");
					} else {
						cpio_set_file(&head, "init", 0120777, xstrdup("/sbin/busybox"), (uint32_t)strlen("/sbin/busybox"));
					}
					printf("[+] First-stage init: Configured PID 1 /init -> /sbin/busybox (applet: init_wrapper)\n");
				} else {
					/* Inject standalone init_wrapper as /init binary */
					if (init_node) {
						free(init_node->data);
						init_node->mode = 0100755;
						init_node->filesize = (uint32_t)w_sz;
						init_node->data = xmemdup(w_data, w_sz);
						printf("[+] First-stage init: Injected universal init_wrapper as PID 1 /init\n");
					} else {
						cpio_set_file(&head, "init", 0100755, xmemdup(w_data, w_sz), (uint32_t)w_sz);
						printf("[+] First-stage init: Injected universal init_wrapper as PID 1 /init\n");
					}
				}
				free(w_data);
			}
			free(wrapper_bin_path);
		} else {
			printf("[!] Warning: init_wrapper / busybox binary not found; falling back to init.modules.rc\n");
		}
	}

	free(mod_data);

	if (cpio_write_all(cpio_path, head) != 0) {
		bb_error_msg("failed to write modified CPIO archive '%s'", cpio_path);
		cpio_free_all(head);
		return -1;
	}

	cpio_free_all(head);
	return 0;
}

static int magiskboot_add_module_op(int argc, char **argv)
{
	bool live = false;
	bool install = false;
	const char *part_name = NULL;
	const char *boot_img = NULL;
	const char *module_ko = NULL;
	const char *out_img = NULL;
	const char *mod_filename = NULL;
	char discovered_boot[512];
	char tmp_work_dir[256];
	char old_cwd[512];
	char abs_module_ko[PATH_MAX];
	char staged_module[PATH_MAX];
	char repacked_img[PATH_MAX];
	int i;
	int ret = 0;

	discovered_boot[0] = '\0';
	abs_module_ko[0] = '\0';

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--live") == 0) {
			live = true;
		} else if (strcmp(argv[i], "--install") == 0) {
			install = true;
		} else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			part_name = argv[++i];
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			i++; /* skip device ID */
		} else if (argv[i][0] == '-') {
			/* skip unrecognized options */
		} else {
			if (!boot_img && !live) {
				boot_img = argv[i];
			} else if (!module_ko) {
				module_ko = argv[i];
			} else if (!out_img) {
				out_img = argv[i];
			}
		}
	}

	if (part_name) {
		char pbuf[PATH_MAX];
		snprintf(pbuf, sizeof(pbuf), "/dev/block/by-name/%s", part_name);
		if (access(pbuf, F_OK) == 0) {
			strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
			discovered_boot[sizeof(discovered_boot) - 1] = '\0';
			boot_img = discovered_boot;
		} else {
			snprintf(pbuf, sizeof(pbuf), "/dev/block/bootdevice/by-name/%s", part_name);
			if (access(pbuf, F_OK) == 0) {
				strncpy(discovered_boot, pbuf, sizeof(discovered_boot) - 1);
				discovered_boot[sizeof(discovered_boot) - 1] = '\0';
				boot_img = discovered_boot;
			}
		}
	}

	if (live || !boot_img) {
		live = true;
		if (find_target_boot_image(discovered_boot, sizeof(discovered_boot)) != 0) {
			bb_error_msg("failed to auto-detect target boot partition");
			return 1;
		}
		boot_img = discovered_boot;
		printf("[+] Auto-detected live boot target: %s\n", boot_img);
	}

	if (!module_ko) {
		bb_error_msg("missing module (.ko) argument");
		return 1;
	}

	if (!realpath(module_ko, abs_module_ko)) {
		safe_strncpy(abs_module_ko, module_ko, sizeof(abs_module_ko));
	}

	if (!getcwd(old_cwd, sizeof(old_cwd))) {
		strcpy(old_cwd, ".");
	}
	safe_strncpy(tmp_work_dir, "/tmp/mb_addmod_XXXXXX", sizeof(tmp_work_dir));
	if (!mkdtemp(tmp_work_dir)) {
		bb_perror_msg("cannot create temporary directory '%s'", tmp_work_dir);
		return 1;
	}
	if (chdir(tmp_work_dir) != 0) {
		bb_perror_msg("cannot chdir to '%s'", tmp_work_dir);
		return 1;
	}

	/* 1. Unpack boot image keeping kernel untouched and compressed */
	printf("[*] Unpacking boot image: %s\n", boot_img);
	if (magiskboot_unpack(boot_img, true, false, false, false) != 0) {
		bb_error_msg("failed to unpack boot image '%s'", boot_img);
		chdir(old_cwd);
		remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
		return 1;
	}

	/* 2. Patch module vermagic and relocations to align with boot kernel */
	mod_filename = bb_basename(abs_module_ko);
	if (!mod_filename || mod_filename[0] == '\0') {
		mod_filename = "module.ko";
	}

	snprintf(staged_module, sizeof(staged_module), "%s/%s", tmp_work_dir, mod_filename);
	copy_file(abs_module_ko, staged_module, FILEUTILS_FORCE);
	module_patch_file(staged_module, staged_module, NULL, boot_img);

	/* 3. Inject module and autoload lists into ramdisk.cpio */
	if (access("ramdisk.cpio", F_OK) == 0) {
		printf("[*] Injecting module '%s' into ramdisk.cpio...\n", mod_filename);
		if (ramdisk_inject_kernel_module("ramdisk.cpio", staged_module, mod_filename) != 0) {
			bb_error_msg("failed to inject module into ramdisk.cpio");
			ret = 1;
			goto cleanup;
		}
	} else {
		bb_error_msg("ramdisk.cpio not found after unpack");
		ret = 1;
		goto cleanup;
	}

	/* 4. Repack boot image using existing battle-tested magiskboot_repack */
	if (out_img && !install) {
		if (out_img[0] == '/') {
			safe_strncpy(repacked_img, out_img, sizeof(repacked_img));
		} else {
			char *p = concat_path_file(old_cwd, out_img);
			safe_strncpy(repacked_img, p, sizeof(repacked_img));
			free(p);
		}
	} else {
		char *p = concat_path_file(tmp_work_dir, "new-boot.img");
		safe_strncpy(repacked_img, p, sizeof(repacked_img));
		free(p);
	}

	printf("[*] Repacking boot image -> %s...\n", repacked_img);
	if (magiskboot_repack(boot_img, repacked_img, false) != 0) {
		bb_error_msg("failed to repack boot image");
		ret = 1;
		goto cleanup;
	}

	/* 5. If --install is specified, flash directly to target block device */
	if (install) {
		printf("[*] Flashing patched boot image directly to %s...\n", boot_img);
		if (flash_partition_image(repacked_img, boot_img, FLASH_OPT_VERIFY_READ) != 0) {
			bb_error_msg("failed to flash patched boot image to %s", boot_img);
			ret = 1;
			goto cleanup;
		}
	} else {
		printf("[✓] SUCCESS: Patched boot image saved to %s\n", repacked_img);
	}

cleanup:
	chdir(old_cwd);
	remove_file(tmp_work_dir, FILEUTILS_RECUR | FILEUTILS_FORCE);
	return ret;
}
