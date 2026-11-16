/* vi: set sw=4 ts=4: */
/*
 * magiskboot_zip.c — Universal Recovery Flashable ZIP Packaging & ZIP Archive Engine
 *
 * Implements in-memory ZIP archive creation, directory recursion, recovery
 * flashable ZIP generation (META-INF, updater-script, update-binary DSL),
 * and BusyBox unzip integration for magiskboot.
 *
 * Included directly into archival/magiskboot.c translation unit.
 * Conforms to Linux Kernel Coding Style & ISO C99/C11 standards.
 */

/* =========================================================================
 * 12. Universal Recovery Flashable ZIP Packaging & ZIP Archive Engine
 * ========================================================================= */

static uint32_t zip_calc_crc32(const void *buf, size_t len) {
	if (!global_crc32_table) {
		global_crc32_new_table_le();
	}
	return crc32_block_endian0(0xffffffff, buf, len, global_crc32_table) ^ 0xffffffff;
}

static bool zip_writer_init(struct zip_writer *zw, const char *out_path) {
	if (!zw || !out_path) return false;
	memset(zw, 0, sizeof(*zw));
	zw->fp = fopen_or_warn(out_path, "wb");
	if (!zw->fp) return false;
	zw->capacity = 64;
	zw->entries = xzalloc(zw->capacity * sizeof(struct zip_entry_info));
	zw->num_entries = 0;
	zw->current_offset = 0;
	return true;
}

static bool zip_writer_add_mem(struct zip_writer *zw, const char *zip_name, const void *data, size_t data_len, mode_t mode) {
	struct zip_local_hdr lhdr;
	size_t name_len;
	uint32_t crc;

	if (!zw || !zw->fp || !zip_name) return false;

	name_len = strlen(zip_name);
	crc = zip_calc_crc32(data, data_len);

	memset(&lhdr, 0, sizeof(lhdr));
	lhdr.signature = SWAP_LE32(ZIP_LOCAL_HDR_MAGIC);
	lhdr.version_needed = SWAP_LE16(20);
	lhdr.flags = 0;
	lhdr.compression = 0; /* Method 0: ZIP_STORED (pure in-memory, zero fork/temp-file overhead) */
	lhdr.mod_time = 0;
	lhdr.mod_date = SWAP_LE16(0x5421);
	lhdr.crc32 = SWAP_LE32(crc);
	lhdr.comp_size = SWAP_LE32((uint32_t)data_len);
	lhdr.uncomp_size = SWAP_LE32((uint32_t)data_len);
	lhdr.filename_len = SWAP_LE16((uint16_t)name_len);
	lhdr.extra_len = 0;

	if (fwrite(&lhdr, 1, sizeof(lhdr), zw->fp) != sizeof(lhdr) ||
	    fwrite(zip_name, 1, name_len, zw->fp) != name_len) {
		return false;
	}

	if (data_len > 0 && fwrite(data, 1, data_len, zw->fp) != data_len) {
		return false;
	}

	if (zw->num_entries >= zw->capacity) {
		zw->capacity *= 2;
		zw->entries = xrealloc(zw->entries, zw->capacity * sizeof(struct zip_entry_info));
	}

	zw->entries[zw->num_entries].name = xstrdup(zip_name);
	zw->entries[zw->num_entries].crc32 = crc;
	zw->entries[zw->num_entries].comp_size = (uint32_t)data_len;
	zw->entries[zw->num_entries].uncomp_size = (uint32_t)data_len;
	zw->entries[zw->num_entries].local_hdr_offset = zw->current_offset;
	zw->entries[zw->num_entries].comp_method = 0;
	zw->entries[zw->num_entries].external_attr = ((uint32_t)mode) << 16;
	zw->num_entries++;

	zw->current_offset += (uint32_t)(sizeof(lhdr) + name_len + data_len);
	return true;
}

static bool zip_writer_add_file(struct zip_writer *zw, const char *zip_name, const char *disk_path, mode_t mode_override) {
	struct stat st;
	size_t sz = 0;
	void *buf;
	mode_t m;
	bool res;

	if (stat(disk_path, &st) < 0) {
		bb_perror_msg("cannot stat '%s'", disk_path);
		return false;
	}

	m = (mode_override != 0) ? mode_override : st.st_mode;

	buf = magiskboot_read_file(disk_path, &sz);
	if (!buf && st.st_size > 0) {
		bb_perror_msg("failed to read '%s'", disk_path);
		return false;
	}

	res = zip_writer_add_mem(zw, zip_name, buf ? buf : "", sz, m);
	free(buf);
	return res;
}

static bool zip_writer_add_dir_recursive(struct zip_writer *zw, const char *zip_prefix, const char *disk_dir) {
	DIR *dir;
	struct dirent *de;
	struct stat st;
	mode_t m;

	dir = opendir(disk_dir);
	if (!dir) return false;

	while ((de = readdir(dir)) != NULL) {
		char *sub_disk;
		char *sub_zip;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		sub_disk = concat_path_file(disk_dir, de->d_name);
		sub_zip = (zip_prefix && zip_prefix[0] != '\0') ?
			concat_path_file(zip_prefix, de->d_name) : xstrdup(de->d_name);

		if (stat(sub_disk, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				char *dir_zip_entry = xasprintf("%s/", sub_zip);
				zip_writer_add_mem(zw, dir_zip_entry, "", 0, S_IFDIR | 0755);
				free(dir_zip_entry);
				zip_writer_add_dir_recursive(zw, sub_zip, sub_disk);
			} else if (S_ISREG(st.st_mode)) {
				m = (st.st_mode & 0111) ? (S_IFREG | 0755) : (S_IFREG | 0644);
				zip_writer_add_file(zw, sub_zip, sub_disk, m);
			}
		}
		free(sub_disk);
		free(sub_zip);
	}
	closedir(dir);
	return true;
}

static bool zip_writer_finish(struct zip_writer *zw) {
	uint32_t cd_offset;
	uint32_t cd_size = 0;
	size_t i;
	struct zip_eocd_record eocd;

	if (!zw || !zw->fp) return false;

	cd_offset = zw->current_offset;

	for (i = 0; i < zw->num_entries; i++) {
		struct zip_entry_info *e = &zw->entries[i];
		struct zip_central_dir_hdr cd;
		size_t nlen = strlen(e->name);

		memset(&cd, 0, sizeof(cd));
		cd.signature = SWAP_LE32(ZIP_CENTRAL_DIR_MAGIC);
		cd.version_made_by = SWAP_LE16(0x031e); /* UNIX 3.0 */
		cd.version_needed = SWAP_LE16(20);
		cd.flags = 0;
		cd.compression = SWAP_LE16(e->comp_method);
		cd.mod_time = 0;
		cd.mod_date = SWAP_LE16(0x5421);
		cd.crc32 = SWAP_LE32(e->crc32);
		cd.comp_size = SWAP_LE32(e->comp_size);
		cd.uncomp_size = SWAP_LE32(e->uncomp_size);
		cd.filename_len = SWAP_LE16((uint16_t)nlen);
		cd.extra_len = 0;
		cd.comment_len = 0;
		cd.disk_num_start = 0;
		cd.internal_attr = 0;
		cd.external_attr = SWAP_LE32(e->external_attr);
		cd.local_hdr_offset = SWAP_LE32(e->local_hdr_offset);

		if (fwrite(&cd, 1, sizeof(cd), zw->fp) != sizeof(cd) ||
		    fwrite(e->name, 1, nlen, zw->fp) != nlen) {
			fclose(zw->fp);
			return false;
		}

		cd_size += (uint32_t)(sizeof(cd) + nlen);
		free(e->name);
	}

	memset(&eocd, 0, sizeof(eocd));
	eocd.signature = SWAP_LE32(ZIP_EOCD_MAGIC);
	eocd.disk_num = 0;
	eocd.cd_disk_num = 0;
	eocd.total_entries_disk = SWAP_LE16((uint16_t)zw->num_entries);
	eocd.total_entries = SWAP_LE16((uint16_t)zw->num_entries);
	eocd.cd_size = SWAP_LE32(cd_size);
	eocd.cd_offset = SWAP_LE32(cd_offset);
	eocd.comment_len = 0;

	if (fwrite(&eocd, 1, sizeof(eocd), zw->fp) != sizeof(eocd)) {
		fclose(zw->fp);
		return false;
	}

	fclose(zw->fp);
	zw->fp = NULL;
	free(zw->entries);
	zw->entries = NULL;
	return true;
}

/*
 * Validate whether a file exists, is readable, and is a valid ARM64 (AArch64) ELF binary.
 */
static bool is_arm64_elf(const char *path) {
	int fd;
	Elf64_Ehdr ehdr;
	ssize_t n;

	if (!path || access(path, R_OK) != 0)
		return false;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	n = full_read(fd, &ehdr, sizeof(ehdr));
	close(fd);

	if (n != (ssize_t)sizeof(ehdr))
		return false;

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		return false;

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 || ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
		return false;

	if (SWAP_LE16(ehdr.e_machine) != EM_AARCH64)
		return false;

	return true;
}

static char *resolve_magiskboot_binary(const char *custom) {
	static const char * const search_paths[] = {
		"bin/magiskboot-arm64",
		"bin/busybox-arm64",
		"bin/magiskboot-aarch64",
		"bin/busybox-aarch64",
		"./magiskboot-arm64",
		"./busybox-arm64",
		"./magiskboot",
		NULL
	};
	char *exe_path;
	char *exe_dir;
	char *slash;
	char candidate[PATH_MAX];
	size_t i;

	/* 1. Custom CLI path specified via --magiskboot */
	if (custom && custom[0] != '\0') {
		if (is_arm64_elf(custom))
			return xstrdup(custom);
		bb_error_msg("specified magiskboot binary '%s' is not an ARM64 ELF binary", custom);
		return NULL;
	}

	/* 2. If running natively on ARM64 host/device, current process can be used */
	if (is_arm64_elf("/proc/self/exe")) {
		return xstrdup("/proc/self/exe");
	}

	/* 3. Search relative build output candidates in current directory */
	for (i = 0; search_paths[i] != NULL; i++) {
		if (is_arm64_elf(search_paths[i])) {
			return xstrdup(search_paths[i]);
		}
	}

	/* 4. Search relative to current executable location */
	exe_path = xmalloc_readlink("/proc/self/exe");
	if (exe_path) {
		exe_dir = xstrdup(exe_path);
		slash = strrchr(exe_dir, '/');
		if (slash) {
			*slash = '\0';

			snprintf(candidate, sizeof(candidate), "%s/magiskboot-arm64", exe_dir);
			if (is_arm64_elf(candidate)) {
				free(exe_path);
				free(exe_dir);
				return xstrdup(candidate);
			}

			snprintf(candidate, sizeof(candidate), "%s/../bin/magiskboot-arm64", exe_dir);
			if (is_arm64_elf(candidate)) {
				free(exe_path);
				free(exe_dir);
				return xstrdup(candidate);
			}
		}
		free(exe_path);
		free(exe_dir);
	}

	return NULL;
}

static char *generate_universal_update_binary(const char *banner, const char *dev_check,
                                              const char *supported_versions, const char *supported_patchlevels,
                                              bool has_init_boot, bool has_vendor_boot,
                                              bool has_vendor_dlkm, bool has_system_dlkm,
                                              bool patch_vbmeta) {
	char dev_block[1024];
	char ver_block[1024];
	char level_block[1024];
	char *script;
	const char *banner_text = (banner && banner[0]) ? banner : "Universal Kernel & Root Engine";

	dev_block[0] = '\0';
	if (dev_check && dev_check[0]) {
		snprintf(dev_block, sizeof(dev_block),
			"\n# Target Device Guardrail Check\n"
			"CURRENT_DEV=$(getprop ro.product.device 2>/dev/null)\n"
			"[ -z \"$CURRENT_DEV\" ] && CURRENT_DEV=$(getprop ro.build.product 2>/dev/null)\n"
			"[ -z \"$CURRENT_DEV\" ] && CURRENT_DEV=$(getprop ro.product.model 2>/dev/null)\n"
			"ui_print \"- Target device detected: $CURRENT_DEV\"\n"
			"DEV_MATCH=0\n"
			"for d in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_DEV\" = \"$d\" ]; then DEV_MATCH=1; break; fi\n"
			"done\n"
			"if [ $DEV_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Error: Unsupported device '$CURRENT_DEV'!\"\n"
			"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
			"fi\n",
			dev_check);
	}

	ver_block[0] = '\0';
	if (supported_versions && supported_versions[0]) {
		snprintf(ver_block, sizeof(ver_block),
			"\n# Android OS Version Compatibility Gate\n"
			"CURRENT_VER=$(getprop ro.build.version.release 2>/dev/null)\n"
			"[ -z \"$CURRENT_VER\" ] && CURRENT_VER=$(getprop ro.build.version.sdk 2>/dev/null)\n"
			"ui_print \"- Android version detected: $CURRENT_VER\"\n"
			"VER_MATCH=0\n"
			"for v in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_VER\" = \"$v\" ]; then VER_MATCH=1; break; fi\n"
			"done\n"
			"if [ $VER_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Error: Unsupported Android version '$CURRENT_VER'! (Supported: %s)\"\n"
			"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
			"fi\n",
			supported_versions, supported_versions);
	}

	level_block[0] = '\0';
	if (supported_patchlevels && supported_patchlevels[0]) {
		snprintf(level_block, sizeof(level_block),
			"\n# Security Patch Level Compatibility Gate\n"
			"CURRENT_SPL=$(getprop ro.build.version.security_patch 2>/dev/null)\n"
			"ui_print \"- Security patch level detected: $CURRENT_SPL\"\n"
			"SPL_MATCH=0\n"
			"for l in $(echo \"%s\" | tr ',' ' '); do\n"
			"  if [ \"$CURRENT_SPL\" = \"$l\" ]; then SPL_MATCH=1; break; fi\n"
			"done\n"
			"if [ $SPL_MATCH -eq 0 ]; then\n"
			"  ui_print \"! Warning: Security patch level '$CURRENT_SPL' differs from target (%s)\"\n"
			"fi\n",
			supported_patchlevels, supported_patchlevels);
	}

	script = xasprintf(
		"#!/sbin/sh\n"
		"# SPDX-License-Identifier: GPL-2.0-or-later\n"
		"# Universal MagiskBoot & AnyKernel3 Recovery Flashable Installer\n\n"
		"OUTFD=$2\n"
		"ZIPFILE=\"$3\"\n\n"
		"ui_print() {\n"
		"  echo \"ui_print $1\" >> /proc/self/fd/$OUTFD\n"
		"  echo \"ui_print\" >> /proc/self/fd/$OUTFD\n"
		"}\n\n"
		"ui_print \"********************************************************\"\n"
		"ui_print \"* %-52s *\"\n"
		"ui_print \"*            Universal Recovery Live-Patcher           *\"\n"
		"ui_print \"********************************************************\"\n\n"
		"TMPDIR=\"/tmp/installer_$$\"\n"
		"mkdir -p \"$TMPDIR\"\n"
		"cd \"$TMPDIR\"\n\n"
		"ui_print \"- Extracting installer payload...\"\n"
		"unzip -o \"$ZIPFILE\" >/dev/null 2>&1\n\n"
		"MB=\"$TMPDIR/tools/magiskboot\"\n"
		"if [ ! -f \"$MB\" ]; then\n"
		"  ui_print \"! Error: Embedded magiskboot missing!\"\n"
		"  cd /; rm -rf \"$TMPDIR\"; exit 1\n"
		"fi\n"
		"chmod 755 \"$MB\"\n"
		"%s%s%s\n"
		"find_slot() {\n"
		"  local slot=$(getprop ro.boot.slot_suffix 2>/dev/null)\n"
		"  [ -z \"$slot\" ] && slot=$(grep -o 'androidboot.slot_suffix=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2)\n"
		"  [ -z \"$slot\" ] && slot=$(getprop ro.boot.slot 2>/dev/null)\n"
		"  [ -n \"$slot\" ] && [ \"${slot#_}\" = \"$slot\" ] && slot=\"_$slot\"\n"
		"  [ \"$slot\" = \"normal\" ] && slot=\"\"\n"
		"  # Virtual A/B OTA Background Snapshot Target Inversion\n"
		"  if [ -d /postinstall/tmp ] && [ -n \"$slot\" ]; then\n"
		"    case \"$slot\" in\n"
		"      _a) slot=\"_b\";;\n"
		"      _b) slot=\"_a\";;\n"
		"    esac\n"
		"  fi\n"
		"  [ -n \"$slot\" ] && echo \"$slot\"\n"
		"}\n\n"
		"find_part() {\n"
		"  local p=\"$1\"\n"
		"  local slot=$(find_slot)\n"
		"  for d in /dev/block/bootdevice/by-name /dev/block/by-name /dev/block/platform/*/by-name /dev/block/platform/*/*/by-name /dev/block/mapper; do\n"
		"    if [ -e \"$d/$p$slot\" ]; then echo \"$d/$p$slot\"; return 0; fi\n"
		"    if [ -e \"$d/$p\" ]; then echo \"$d/$p\"; return 0; fi\n"
		"  done\n"
		"  return 1\n"
		"}\n\n"
		"# Full AnyKernel3 Ramdisk & Configuration Modification DSL\n"
		"backup_file() { [ ! -f \"$1~\" ] && cp -fp \"$1\" \"$1~\"; }\n"
		"restore_file() { [ -f \"$1~\" ] && cp -fp \"$1~\" \"$1\"; rm -f \"$1~\"; }\n\n"
		"replace_string() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local orig=\"$3\"; local repl=\"$4\"\n"
		"  [ -z \"$orig\" ] && orig=\"$s\"; [ -z \"$repl\" ] && repl=\"$3\"\n"
		"  if [ -f \"$f\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    sed -i \"s|$orig|$repl|g\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"replace_section() {\n"
		"  local f=\"$1\"; local b=\"$2\"; local e=\"$3\"; local r=\"$4\"\n"
		"  local begin=$(grep -n -m1 \"$b\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  if [ -n \"$begin\" ]; then\n"
		"    [ -z \"$e\" ] && e='^[[:space:]]*$'\n"
		"    local last=$(wc -l < \"$f\" 2>/dev/null)\n"
		"    for end in $(grep -n \"$e\" \"$f\" 2>/dev/null | cut -d: -f1) $last; do\n"
		"      if [ \"$end\" -gt \"$begin\" ]; then\n"
		"        sed -i \"${begin},${end}d\" \"$f\" 2>/dev/null\n"
		"        [ \"$end\" -eq \"$last\" ] && echo \"\" >> \"$f\"\n"
		"        sed -i \"${begin}s|^|${r}\\n|\" \"$f\" 2>/dev/null\n"
		"        break\n"
		"      fi\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"remove_section() {\n"
		"  local f=\"$1\"; local b=\"$2\"; local e=\"$3\"\n"
		"  local begin=$(grep -n -m1 \"$b\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  if [ -n \"$begin\" ]; then\n"
		"    [ -z \"$e\" ] && e='^[[:space:]]*$'\n"
		"    local last=$(wc -l < \"$f\" 2>/dev/null)\n"
		"    for end in $(grep -n \"$e\" \"$f\" 2>/dev/null | cut -d: -f1) $last; do\n"
		"      if [ \"$end\" -gt \"$begin\" ]; then\n"
		"        sed -i \"${begin},${end}d\" \"$f\" 2>/dev/null\n"
		"        break\n"
		"      fi\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"insert_line() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local loc=\"$3\"; local m=\"$4\"; local l=\"$5\"\n"
		"  if [ -f \"$f\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local off=1; [ \"$loc\" = \"before\" ] && off=0\n"
		"    local lnum=$(( $(grep -n -m1 \"$m\" \"$f\" 2>/dev/null | cut -d: -f1) + off ))\n"
		"    if [ \"$(wc -l < \"$f\")\" -lt \"$lnum\" ]; then\n"
		"      echo \"$l\" >> \"$f\"\n"
		"    else\n"
		"      sed -i \"${lnum}s|^|${l}\\n|\" \"$f\" 2>/dev/null\n"
		"    fi\n"
		"  fi\n"
		"}\n\n"
		"replace_line() {\n"
		"  local f=\"$1\"; local m=\"$2\"; local r=\"$3\"; local sc=\"$4\"\n"
		"  if [ -f \"$f\" ] && grep -q \"$m\" \"$f\" 2>/dev/null; then\n"
		"    local lines=$(grep -n \"$m\" \"$f\" 2>/dev/null | cut -d: -f1 | sort -nr)\n"
		"    [ \"$sc\" != \"global\" ] && lines=$(echo \"$lines\" | tail -n1)\n"
		"    for line in $lines; do\n"
		"      sed -i \"${line}s|.*|${r}|\" \"$f\" 2>/dev/null\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"remove_line() {\n"
		"  local f=\"$1\"; local m=\"$2\"; local sc=\"$3\"\n"
		"  if [ -f \"$f\" ] && grep -q \"$m\" \"$f\" 2>/dev/null; then\n"
		"    local lines=$(grep -n \"$m\" \"$f\" 2>/dev/null | cut -d: -f1 | sort -nr)\n"
		"    [ \"$sc\" != \"global\" ] && lines=$(echo \"$lines\" | tail -n1)\n"
		"    for line in $lines; do\n"
		"      sed -i \"${line}d\" \"$f\" 2>/dev/null\n"
		"    done\n"
		"  fi\n"
		"}\n\n"
		"insert_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local loc=\"$3\"; local m=\"$4\"; local p=\"$5\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local off=1; [ \"$loc\" = \"before\" ] && off=0\n"
		"    local lnum=$(( $(grep -n -m1 \"$m\" \"$f\" 2>/dev/null | cut -d: -f1) + off ))\n"
		"    sed -i \"${lnum}s|^|\\n|\" \"$f\" 2>/dev/null\n"
		"    sed -i \"$((lnum - 1))r $p\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"prepend_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local p=\"$3\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    local tmp=\"$TMPDIR/prep_$$\"\n"
		"    cat \"$p\" \"$f\" > \"$tmp\" && mv -f \"$tmp\" \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"append_file() {\n"
		"  local f=\"$1\"; local s=\"$2\"; local p=\"$3\"\n"
		"  if [ -f \"$f\" ] && [ -f \"$p\" ] && ! grep -q \"$s\" \"$f\" 2>/dev/null; then\n"
		"    echo \"\" >> \"$f\"\n"
		"    cat \"$p\" >> \"$f\"\n"
		"    echo \"\" >> \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"replace_file() {\n"
		"  if [ -f \"$3\" ]; then\n"
		"    cp -pf \"$3\" \"$1\" && chmod \"$2\" \"$1\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_prop() {\n"
		"  local f=\"$1\"; local k=\"$2\"; local v=\"$3\"\n"
		"  [ -f \"$f\" ] || return 1\n"
		"  if ! grep -q \"^$k=\" \"$f\" 2>/dev/null; then\n"
		"    echo \"$k=$v\" >> \"$f\"\n"
		"  else\n"
		"    local line=$(grep -n -m1 \"^$k=\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"    sed -i \"${line}s|.*|${k}=${v}|\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_ueventd() {\n"
		"  local f=\"$1\"; local d=\"$2\"; local p=\"$3\"; local u=\"$4\"; shift 4; local g=\"$*\"\n"
		"  [ -f \"$f\" ] || return 1\n"
		"  local line=$(grep -n -m1 \"$d\" \"$f\" 2>/dev/null | cut -d: -f1)\n"
		"  local entry=\"$d   $p   $u   $g\"\n"
		"  if [ -n \"$line\" ]; then\n"
		"    sed -i \"${line}s|.*|${entry}|\" \"$f\" 2>/dev/null\n"
		"  else\n"
		"    echo \"$entry\" >> \"$f\"\n"
		"  fi\n"
		"}\n\n"
		"patch_fstab() {\n"
		"  local f=\"$1\"; local mnt=\"$2\"; local old=\"$3\"; local new=\"$4\"\n"
		"  if [ -f \"$f\" ]; then\n"
		"    \"$MB\" fstab \"$f\" patch \"$mnt\" \"$old\" \"$new\" 2>/dev/null || sed -i \"s|$old|$new|g\" \"$f\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"patch_cmdline() {\n"
		"  local f=\"$1\"; local key=\"$2\"; local val=\"$3\"\n"
		"  if [ -f \"$f\" ]; then\n"
		"    \"$MB\" cmdline \"$f\" patch \"$key\" \"$val\" 2>/dev/null\n"
		"  fi\n"
		"}\n\n"
		"# Dynamic Partition & Super Volume Flash Engine\n"
		"flash_generic() {\n"
		"  local p=\"$1\"\n"
		"  local img=\"\"\n"
		"  for f in \"$TMPDIR/$p\" \"$TMPDIR/$p.img\"; do\n"
		"    if [ -f \"$f\" ]; then img=\"$f\"; break; fi\n"
		"  done\n"
		"  [ -z \"$img\" ] && return 0\n"
		"  local part=$(find_part \"$p\")\n"
		"  if [ -z \"$part\" ]; then\n"
		"    ui_print \"! Notice: Partition $p not found on device, skipping\"\n"
		"    return 0\n"
		"  fi\n"
		"  ui_print \"- Flashing $p -> $part...\"\n"
		"  blockdev --setrw \"$part\" 2>/dev/null\n"
		"  if [ -d /postinstall/tmp ] && which snapshotupdater_static >/dev/null 2>&1; then\n"
		"    local imgsz=$(wc -c < \"$img\")\n"
		"    snapshotupdater_static update \"$p\" \"$imgsz\" 2>/dev/null || true\n"
		"  fi\n"
		"  case \"$part\" in\n"
		"    /dev/block/mapper/*)\n"
		"      if which lptools_static >/dev/null 2>&1; then\n"
		"        local imgsz=$(wc -c < \"$img\")\n"
		"        lptools_static resize \"$p$(find_slot)\" \"$imgsz\" 2>/dev/null || true\n"
		"      fi\n"
		"      ;;\n"
		"  esac\n"
		"  dd if=\"$img\" of=\"$part\" bs=1048576 2>/dev/null || cat \"$img\" > \"$part\"\n"
		"  local ret=$?\n"
		"  if [ $ret -eq 0 ]; then\n"
		"    ui_print \"- Successfully flashed $p\"\n"
		"  else\n"
		"    ui_print \"! Error flashing $p (code $ret)\"\n"
		"  fi\n"
		"  return $ret\n"
		"}\n\n"
		"# AVB 2.0 VBMeta dm-verity Neutralization Engine\n"
		"patch_vbmeta_device() {\n"
		"  for vbname in vbmeta vbmeta_system vbmeta_vendor; do\n"
		"    local vb=$(find_part \"$vbname\")\n"
		"    if [ -n \"$vb\" ]; then\n"
		"      ui_print \"- Neutralizing dm-verity on $vb ($vbname)...\"\n"
		"      blockdev --setrw \"$vb\" 2>/dev/null\n"
		"      \"$MB\" vbmeta \"$vb\" disable 2>/dev/null || true\n"
		"    fi\n"
		"  done\n"
		"}\n\n"
		"PATCH_VBMETA=%d\n"
		"if [ \"$PATCH_VBMETA\" = \"1\" ]; then\n"
		"  patch_vbmeta_device\n"
		"fi\n\n"
		"HAS_INIT_BOOT=%d\n"
		"if [ \"$HAS_INIT_BOOT\" = \"0\" ]; then\n"
		"  if find_part \"init_boot\" >/dev/null 2>&1; then HAS_INIT_BOOT=1; fi\n"
		"fi\n"
		"RD_PART=\"boot\"\n"
		"if [ \"$HAS_INIT_BOOT\" = \"1\" ]; then\n"
		"  RD_PART=\"init_boot\"\n"
		"  ui_print \"- GKI 2.0 multi-partition device detected: ramdisk in init_boot\"\n"
		"fi\n\n"
		"HAS_VENDOR_BOOT=%d\n"
		"if [ -f \"$TMPDIR/vendor_boot.img\" ] || [ \"$HAS_VENDOR_BOOT\" = \"1\" ]; then\n"
		"  VNDR_PART=$(find_part \"vendor_boot\")\n"
		"  if [ -n \"$VNDR_PART\" ] && [ -f \"$TMPDIR/vendor_boot.img\" ]; then\n"
		"    ui_print \"- Flashing vendor_boot image to $VNDR_PART...\"\n"
		"    dd if=\"$TMPDIR/vendor_boot.img\" of=\"$VNDR_PART\" bs=1048576 2>/dev/null || cat \"$TMPDIR/vendor_boot.img\" > \"$VNDR_PART\"\n"
		"  fi\n"
		"fi\n\n"
		"MODULES=\"\"\n"
		"[ -d \"$TMPDIR/modules\" ] && MODULES=\"$TMPDIR/modules\"\n\n"
		"KERNEL=\"\"\n"
		"if [ -f \"$TMPDIR/kernel\" ]; then KERNEL=\"$TMPDIR/kernel\";\n"
		"elif [ -f \"$TMPDIR/Image\" ]; then KERNEL=\"$TMPDIR/Image\";\n"
		"elif [ -f \"$TMPDIR/Image.gz\" ]; then KERNEL=\"$TMPDIR/Image.gz\"; fi\n\n"
		"ui_print \"- Live patching active hardware partitions via magiskboot...\"\n"
		"RET=0\n\n"
		"if [ -n \"$KERNEL\" ]; then\n"
		"  ui_print \"- Replacing kernel image...\"\n"
		"  CMD=\"kernel boot patch --kernel $KERNEL\"\n"
		"  [ -f \"$TMPDIR/dtb\" ] && CMD=\"$CMD --dtb $TMPDIR/dtb\"\n"
		"  [ -f \"$TMPDIR/dtbo.img\" ] && CMD=\"$CMD --dtbo $TMPDIR/dtbo.img\"\n"
		"  eval \"\\\"$MB\\\" $CMD\"\n"
		"  RET=$?\n"
		"fi\n\n"
		"if [ -n \"$MODULES\" ]; then\n"
		"  for ko in \"$MODULES\"/*.ko; do\n"
		"    if [ -f \"$ko\" ]; then\n"
		"      ui_print \"- Injecting module $(basename \"$ko\") into $RD_PART ramdisk...\"\n"
		"      \"$MB\" add-module --live -p \"$RD_PART\" --install \"$ko\"\n"
		"      RET=$?\n"
		"      if [ $RET -ne 0 ]; then ui_print \"! Failed to inject module $(basename \"$ko\")\"; break; fi\n"
		"    fi\n"
		"  done\n"
		"fi\n\n"
		"# Flash Dynamic / Logical Partitions (vendor_dlkm, system_dlkm, dtbo)\n"
		"HAS_VENDOR_DLKM=%d\n"
		"if [ \"$HAS_VENDOR_DLKM\" = \"1\" ] || [ -f \"$TMPDIR/vendor_dlkm.img\" ]; then\n"
		"  flash_generic \"vendor_dlkm\"\n"
		"fi\n\n"
		"HAS_SYSTEM_DLKM=%d\n"
		"if [ \"$HAS_SYSTEM_DLKM\" = \"1\" ] || [ -f \"$TMPDIR/system_dlkm.img\" ]; then\n"
		"  flash_generic \"system_dlkm\"\n"
		"fi\n\n"
		"if [ -f \"$TMPDIR/dtbo.img\" ]; then\n"
		"  flash_generic \"dtbo\"\n"
		"fi\n\n"
		"APK_PATH=\"\"\n"
		"if [ -d \"$TMPDIR/app\" ]; then\n"
		"  for a in \"$TMPDIR/app\"/*.apk; do if [ -f \"$a\" ]; then APK_PATH=\"$a\"; break; fi; done\n"
		"fi\n"
		"if [ $RET -eq 0 ] && [ -n \"$APK_PATH\" ]; then\n"
		"  if [ \"$(getprop sys.boot_completed 2>/dev/null)\" = \"1\" ] && which pm >/dev/null 2>&1; then\n"
		"    ui_print \"- Live Android: installing manager APK via pm...\"\n"
		"    pm install -g -r \"$APK_PATH\" >/dev/null 2>&1\n"
		"  else\n"
		"    [ ! -d /data/system ] && mount /data >/dev/null 2>&1\n"
		"    if [ -d /data ]; then\n"
		"      mkdir -p /data/system/kroot\n"
		"      cp -f \"$APK_PATH\" /data/system/kroot/kroot.apk\n"
		"      chmod 644 /data/system/kroot/kroot.apk 2>/dev/null\n"
		"      ui_print \"- Staged manager APK to /data/system/kroot\"\n"
		"    fi\n"
		"  fi\n"
		"fi\n\n"
		"cd /; rm -rf \"$TMPDIR\"\n"
		"if [ $RET -eq 0 ]; then\n"
		"  ui_print \"********************************************************\"\n"
		"  ui_print \"* Flash complete! Reboot to activate.                  *\"\n"
		"  ui_print \"********************************************************\"\n"
		"  exit 0\n"
		"else\n"
		"  ui_print \"! Installation failed with code $RET\"\n"
		"  exit $RET\n"
		"fi\n",
		banner_text,
		dev_block,
		ver_block,
		level_block,
		patch_vbmeta ? 1 : 0,
		has_init_boot ? 1 : 0,
		has_vendor_boot ? 1 : 0,
		has_vendor_dlkm ? 1 : 0,
		has_system_dlkm ? 1 : 0
	);

	return script;
}

static int package_dist_zip(struct dist_package_options *opts) {
	struct zip_writer zw;
	char *update_bin_script;
	char *mb_bin;
	size_t i;
	struct stat st;

	if (!opts || !opts->out_zip) {
		bb_error_msg("missing output zip file");
		return 1;
	}

	fprintf(stderr, "======================================================================\n");
	fprintf(stderr, "  Packaging Universal Recovery Flashable ZIP: %s\n", opts->out_zip);
	fprintf(stderr, "======================================================================\n");

	if (!zip_writer_init(&zw, opts->out_zip)) {
		return 1;
	}

	/* 1. META-INF/com/google/android/updater-script (#MAGISK) */
	zip_writer_add_mem(&zw, "META-INF/com/google/android/updater-script", "#MAGISK\n", 8, S_IFREG | 0644);

	/* 2. META-INF/com/google/android/update-binary */
	if (opts->update_binary_script && access(opts->update_binary_script, R_OK) == 0) {
		zip_writer_add_file(&zw, "META-INF/com/google/android/update-binary", opts->update_binary_script, S_IFREG | 0755);
		fprintf(stderr, "[+] Bundled custom update-binary from '%s'\n", opts->update_binary_script);
	} else {
		update_bin_script = generate_universal_update_binary(
			opts->banner,
			opts->device_check,
			opts->supported_versions,
			opts->supported_patchlevels,
			opts->target_init_boot,
			(opts->vendor_boot_path != NULL),
			(opts->vendor_dlkm_path != NULL),
			(opts->system_dlkm_path != NULL),
			opts->patch_vbmeta
		);
		zip_writer_add_mem(&zw, "META-INF/com/google/android/update-binary", update_bin_script, strlen(update_bin_script), S_IFREG | 0755);
		free(update_bin_script);
		fprintf(stderr, "[+] Bundled universal recovery live-patcher update-binary\n");
	}

	/* 3. tools/magiskboot */
	mb_bin = resolve_magiskboot_binary(opts->magiskboot_bin);
	if (mb_bin && access(mb_bin, R_OK) == 0) {
		zip_writer_add_file(&zw, "tools/magiskboot", mb_bin, S_IFREG | 0755);
		fprintf(stderr, "[+] Bundled tools/magiskboot from '%s'\n", mb_bin);
		free(mb_bin);
	} else {
		fprintf(stderr, "[!] Warning: No compiled target magiskboot found to embed into tools/magiskboot\n");
	}

	/* 4. Modules into modules/ (*.ko) */
	for (i = 0; i < opts->num_modules; i++) {
		const char *mpath = opts->modules[i];
		if (stat(mpath, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				DIR *mdir = opendir(mpath);
				if (mdir) {
					struct dirent *de;
					while ((de = readdir(mdir)) != NULL) {
						if (is_suffixed_with(de->d_name, ".ko")) {
							char *full_m = concat_path_file(mpath, de->d_name);
							char *zip_m = concat_path_file("modules", de->d_name);
							zip_writer_add_file(&zw, zip_m, full_m, S_IFREG | 0644);
							fprintf(stderr, "[+] Bundled module: %s\n", zip_m);
							free(full_m);
							free(zip_m);
						}
					}
					closedir(mdir);
				}
			} else if (S_ISREG(st.st_mode)) {
				const char *bname = bb_basename(mpath);
				char *zip_m = concat_path_file("modules", bname);
				zip_writer_add_file(&zw, zip_m, mpath, S_IFREG | 0644);
				fprintf(stderr, "[+] Bundled module: %s\n", zip_m);
				free(zip_m);
			}
		}
	}

	/* 5. Kernel image */
	if (opts->kernel_path && access(opts->kernel_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "kernel", opts->kernel_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled kernel payload: '%s'\n", opts->kernel_path);
	}

	/* 6. DTB */
	if (opts->dtb_path && access(opts->dtb_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "dtb", opts->dtb_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled DTB payload: '%s'\n", opts->dtb_path);
	}

	/* 7. DTBO */
	if (opts->dtbo_path && access(opts->dtbo_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "dtbo.img", opts->dtbo_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled DTBO payload: '%s'\n", opts->dtbo_path);
	}

	/* 7b. Vendor Boot */
	if (opts->vendor_boot_path && access(opts->vendor_boot_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "vendor_boot.img", opts->vendor_boot_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled vendor_boot payload: '%s'\n", opts->vendor_boot_path);
	}

	/* 7c. Vendor DLKM */
	if (opts->vendor_dlkm_path && access(opts->vendor_dlkm_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "vendor_dlkm.img", opts->vendor_dlkm_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled vendor_dlkm payload: '%s'\n", opts->vendor_dlkm_path);
	}

	/* 7d. System DLKM */
	if (opts->system_dlkm_path && access(opts->system_dlkm_path, R_OK) == 0) {
		zip_writer_add_file(&zw, "system_dlkm.img", opts->system_dlkm_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled system_dlkm payload: '%s'\n", opts->system_dlkm_path);
	}

	/* 8. Manager APK */
	if (opts->app_path && access(opts->app_path, R_OK) == 0) {
		const char *bname = bb_basename(opts->app_path);
		char zip_app[PATH_MAX];
		snprintf(zip_app, sizeof(zip_app), "app/%s", bname);
		zip_writer_add_file(&zw, zip_app, opts->app_path, S_IFREG | 0644);
		fprintf(stderr, "[+] Bundled manager APK: %s\n", zip_app);
	}

	/* 9. overlay.d/ */
	if (opts->overlay_dir && stat(opts->overlay_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
		zip_writer_add_dir_recursive(&zw, "overlay.d", opts->overlay_dir);
		fprintf(stderr, "[+] Bundled overlay tree from '%s'\n", opts->overlay_dir);
	}

	if (!zip_writer_finish(&zw)) {
		bb_error_msg("failed to finalize zip archive");
		return 1;
	}

	if (stat(opts->out_zip, &st) == 0) {
		fprintf(stderr, "[✓] SUCCESS: Universal recovery flashable ZIP generated: '%s' (%zu bytes)\n",
		        opts->out_zip, (size_t)st.st_size);
	}
	fprintf(stderr, "======================================================================\n");
	return 0;
}

static int run_busybox_applet(const char *name, char **argv) {
	int a = find_applet_by_name(name);
	pid_t pid;
	if (a < 0) {
		bb_error_msg("applet '%s' not enabled in busybox configuration", name);
		return -1;
	}
	pid = fork();
	if (pid == 0) {
		run_applet_no_and_exit(a, name, argv);
	}
	if (pid > 0) {
		return wait4pid(pid);
	}
	return -1;
}

static int zip_list_file(const char *zip_path) {
	char *args[4];
	args[0] = (char *)"unzip";
	args[1] = (char *)"-l";
	args[2] = (char *)zip_path;
	args[3] = NULL;
	return run_busybox_applet("unzip", args);
}

static int zip_extract_file(const char *zip_path, const char *target_entry, const char *dest_dir) {
	char *args[8];
	int i = 0;
	args[i++] = (char *)"unzip";
	args[i++] = (char *)"-o";
	args[i++] = (char *)"-q";
	if (dest_dir && dest_dir[0] && strcmp(dest_dir, ".") != 0) {
		args[i++] = (char *)"-d";
		args[i++] = (char *)dest_dir;
	}
	args[i++] = (char *)zip_path;
	if (target_entry && target_entry[0]) {
		args[i++] = (char *)target_entry;
	}
	args[i] = NULL;
	return run_busybox_applet("unzip", args);
}

static int zip_create_file(const char *out_zip, int num_files, char **files) {
	struct zip_writer zw;
	int i;
	struct stat st;
	const char *f, *bname;
	char dir_entry[PATH_MAX];
	mode_t m;

	if (!out_zip || num_files <= 0) {
		bb_error_msg("usage: magiskboot zip <out.zip> create <file1|dir1> [file2...]");
		return 1;
	}

	if (!zip_writer_init(&zw, out_zip)) return 1;

	for (i = 0; i < num_files; i++) {
		f = files[i];
		if (stat(f, &st) != 0) {
			bb_perror_msg("cannot stat '%s'", f);
			continue;
		}
		bname = bb_basename(f);
		if (S_ISDIR(st.st_mode)) {
			snprintf(dir_entry, sizeof(dir_entry), "%s/", bname);
			zip_writer_add_mem(&zw, dir_entry, "", 0, S_IFDIR | 0755);
			zip_writer_add_dir_recursive(&zw, bname, f);
		} else if (S_ISREG(st.st_mode)) {
			m = (st.st_mode & 0111) ? (S_IFREG | 0755) : (S_IFREG | 0644);
			zip_writer_add_file(&zw, bname, f, m);
			printf("[+] Added file '%s' -> '%s'\n", f, bname);
		}
	}

	if (!zip_writer_finish(&zw)) return 1;
	printf("[✓] SUCCESS: Created '%s'\n", out_zip);
	return 0;
}

static int magiskboot_dist_op(int argc, char **argv) {
	struct dist_package_options opts;
	int i;
	size_t mod_cap = 16;
	int ret;

	memset(&opts, 0, sizeof(opts));
	opts.modules = xzalloc(mod_cap * sizeof(char *));

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--module") == 0 || strcmp(argv[i], "--modules") == 0) {
			if (++i < argc) {
				if (opts.num_modules >= mod_cap) {
					mod_cap *= 2;
					opts.modules = xrealloc(opts.modules, mod_cap * sizeof(char *));
				}
				opts.modules[opts.num_modules++] = argv[i];
			}
		} else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel") == 0) {
			if (++i < argc) opts.kernel_path = argv[i];
		} else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dtb") == 0) {
			if (++i < argc) opts.dtb_path = argv[i];
		} else if (strcmp(argv[i], "--dtbo") == 0) {
			if (++i < argc) opts.dtbo_path = argv[i];
		} else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--app") == 0) {
			if (++i < argc) opts.app_path = argv[i];
		} else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--overlay") == 0) {
			if (++i < argc) opts.overlay_dir = argv[i];
		} else if (strcmp(argv[i], "--magiskboot") == 0) {
			if (++i < argc) opts.magiskboot_bin = argv[i];
		} else if (strcmp(argv[i], "--banner") == 0) {
			if (++i < argc) opts.banner = argv[i];
		} else if (strcmp(argv[i], "--device") == 0 || strcmp(argv[i], "--device-check") == 0) {
			if (++i < argc) opts.device_check = argv[i];
		} else if (strcmp(argv[i], "--android-version") == 0 || strcmp(argv[i], "--version-check") == 0) {
			if (++i < argc) opts.supported_versions = argv[i];
		} else if (strcmp(argv[i], "--patch-level") == 0 || strcmp(argv[i], "--level-check") == 0) {
			if (++i < argc) opts.supported_patchlevels = argv[i];
		} else if (strcmp(argv[i], "--vendor-boot") == 0) {
			if (++i < argc) opts.vendor_boot_path = argv[i];
		} else if (strcmp(argv[i], "--vendor-dlkm") == 0) {
			if (++i < argc) opts.vendor_dlkm_path = argv[i];
		} else if (strcmp(argv[i], "--system-dlkm") == 0) {
			if (++i < argc) opts.system_dlkm_path = argv[i];
		} else if (strcmp(argv[i], "--vbmeta-patch") == 0 || strcmp(argv[i], "--patch-vbmeta") == 0) {
			opts.patch_vbmeta = true;
		} else if (strcmp(argv[i], "--init-boot") == 0) {
			opts.target_init_boot = true;
		} else if (strcmp(argv[i], "--update-binary") == 0) {
			if (++i < argc) opts.update_binary_script = argv[i];
		} else if (argv[i][0] != '-') {
			opts.out_zip = argv[i];
		}
	}

	if (!opts.out_zip) {
		bb_error_msg("usage: magiskboot dist [options...] <output.zip>\n"
		             "  -m, --module <ko|dir>   Bundle kernel module(s)\n"
		             "  -k, --kernel <image>    Bundle kernel image\n"
		             "  -d, --dtb <dtb>         Bundle DTB image\n"
		             "  --dtbo <dtbo>           Bundle DTBO image\n"
		             "  -a, --app <apk>         Bundle Manager APK\n"
		             "  -o, --overlay <dir>     Bundle overlay.d/ directory\n"
		             "  --vendor-boot <image>   Bundle vendor_boot image\n"
		             "  --vendor-dlkm <img|dir> Bundle vendor_dlkm payload\n"
		             "  --system-dlkm <img|dir> Bundle system_dlkm payload\n"
		             "  --vbmeta-patch          Neutralize AVB/dm-verity on top-level vbmeta\n"
		             "  --magiskboot <bin>      Embed specific target magiskboot\n"
		             "  --banner <text>         Custom recovery installer banner\n"
		             "  --device <dev1,dev2>    Device check guardrails\n"
		             "  --android-version <ver> Supported Android version(s)\n"
		             "  --patch-level <date>    Supported security patch level\n"
		             "  --init-boot             Target init_boot partition (GKI 2.0)\n"
		             "  --update-binary <sh>    Custom update-binary script");
		free(opts.modules);
		return 1;
	}

	ret = package_dist_zip(&opts);
	free(opts.modules);
	return ret;
}

static int magiskboot_zip_op(int argc, char **argv) {
	static const char zip_acts[] ALIGN1 =
		"create\0"
		"list\0"
		"ls\0"
		"extract\0"
		"x\0";
	enum {
		ZIP_ACT_create = 0,
		ZIP_ACT_list,
		ZIP_ACT_ls,
		ZIP_ACT_extract,
		ZIP_ACT_x,
	};
	const char *zip_file;
	const char *action;
	const char *entry;
	const char *dest;

	if (argc < 4) {
		bb_error_msg("usage: magiskboot zip <file.zip> <create|list|extract> [args...]");
		return 1;
	}

	zip_file = argv[2];
	action = argv[3];

	switch (index_in_strings(zip_acts, action)) {
	case ZIP_ACT_create:
		return zip_create_file(zip_file, argc - 4, argv + 4);
	case ZIP_ACT_list:
	case ZIP_ACT_ls:
		return zip_list_file(zip_file);
	case ZIP_ACT_extract:
	case ZIP_ACT_x:
		entry = (argc >= 5 && argv[4][0] != '\0') ? argv[4] : NULL;
		dest = (argc >= 6 && argv[5][0] != '\0') ? argv[5] : ".";
		return zip_extract_file(zip_file, entry, dest);
	default:
		bb_error_msg("unknown zip action '%s' (supported: create, list, extract)", action);
		return 1;
	}
}
