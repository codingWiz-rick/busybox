/* vi: set sw=4 ts=4: */
/*
 * Native libc-independent file applet for BusyBox
 *
 * Classifies file types without requiring external magic database files.
 * Covers ELF binaries (32/64-bit, endianness, architecture, interpreter,
 * static/dynamic linking, stripped status, build-ID), Android images
 * (bootimg, sparse, DTB, DEX, CDEX, ART, super/LP, OTA payload), compressed
 * archives (gzip, bzip2, xz, zstd, lz4, zip/apk, 7z, tar, cpio),
 * filesystems (ext2/3/4, f2fs, erofs, squashfs), scripts and text documents.
 *
 * Copyright (C) 2026 Rick & the BusyBox Team
 * Licensed under GPLv2 or later.
 */

//config:config FILE
//config:	bool "file (determine file type)"
//config:	default y
//config:	help
//config:	  file tests each argument in an attempt to classify it.
//config:	  It recognizes ELF binaries, Android images, compressed archives,
//config:	  filesystems, scripts, and text files without requiring external
//config:	  magic database files.

//applet:IF_FILE(APPLET(file, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_FILE) += file.o

//usage:#define file_trivial_usage
//usage:       "[-bhiL] [FILE]..."
//usage:#define file_full_usage "\n\n"
//usage:       "Determine file type\n"
//usage:     "\n	-b	Brief mode (do not prepend filename)"
//usage:     "\n	-h	Do not follow symlinks (default)"
//usage:     "\n	-L	Follow symlinks"
//usage:     "\n	-i	Output MIME type strings"

#include "libbb.h"
#include <elf.h>

enum {
	OPT_b = (1 << 0), /* brief */
	OPT_h = (1 << 1), /* don't follow symlinks (default) */
	OPT_i = (1 << 2), /* mime output */
	OPT_L = (1 << 3), /* follow symlinks */
};

/* Endian conversion helpers (prefixed to avoid collision with platform.h macros) */
static uint16_t f_get_le16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint16_t)(b[0] | (b[1] << 8));
}

static uint32_t f_get_le32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint32_t)(b[0] | (b[1] << 8) | (b[2] << 16) | ((uint32_t)b[3] << 24));
}

static uint64_t f_get_le64(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint64_t)f_get_le32(b) | ((uint64_t)f_get_le32(b + 4) << 32);
}

static uint16_t f_get_be16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint16_t)((b[0] << 8) | b[1]);
}

static uint32_t f_get_be32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint32_t)(((uint32_t)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static uint64_t f_get_be64(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return ((uint64_t)f_get_be32(b) << 32) | (uint64_t)f_get_be32(b + 4);
}

static const char *elf_machine_str(uint16_t m)
{
	switch (m) {
	case EM_AARCH64: return "ARM aarch64";
	case EM_ARM:     return "ARM";
	case EM_X86_64:  return "x86-64";
	case EM_386:     return "Intel 80386";
#ifdef EM_RISCV
	case EM_RISCV:   return "RISC-V";
#endif
	case EM_MIPS:    return "MIPS";
	case EM_PPC:     return "PowerPC";
	case EM_PPC64:   return "PowerPC 64-bit";
	case EM_S390:    return "IBM S/390";
#ifdef EM_LOONGARCH
	case EM_LOONGARCH: return "LoongArch";
#endif
	default:         return "unknown architecture";
	}
}

static const char *elf_osabi_str(uint8_t abi)
{
	switch (abi) {
	case ELFOSABI_SYSV:       return "SYSV";
	case ELFOSABI_HPUX:       return "HP-UX";
	case ELFOSABI_NETBSD:     return "NetBSD";
	case ELFOSABI_LINUX:      return "GNU/Linux";
	case ELFOSABI_SOLARIS:    return "Solaris";
	case ELFOSABI_AIX:        return "AIX";
	case ELFOSABI_FREEBSD:    return "FreeBSD";
	case ELFOSABI_OPENBSD:    return "OpenBSD";
	case ELFOSABI_ARM:        return "ARM";
	default:                  return "SYSV";
	}
}

static int is_elf_stripped(int fd, int is64, int islsb, uint64_t shoff, uint16_t shnum, uint16_t shents)
{
	uint16_t i;
	if (shoff == 0 || shnum == 0 || shents == 0)
		return 1; /* no section header table -> stripped */

	for (i = 0; i < shnum; i++) {
		off_t offset = (off_t)shoff + (off_t)i * shents;
		uint32_t type = 0;

		if (is64) {
			Elf64_Shdr sh;
			if (pread(fd, &sh, sizeof(sh), offset) != sizeof(sh))
				break;
			type = islsb ? f_get_le32(&sh.sh_type) : f_get_be32(&sh.sh_type);
		} else {
			Elf32_Shdr sh;
			if (pread(fd, &sh, sizeof(sh), offset) != sizeof(sh))
				break;
			type = islsb ? f_get_le32(&sh.sh_type) : f_get_be32(&sh.sh_type);
		}

		if (type == SHT_SYMTAB)
			return 0; /* found active symbol table -> not stripped */
	}
	return 1;
}

static int parse_elf(int fd, const unsigned char *buf, size_t len, int opt)
{
	int is64 = (buf[EI_CLASS] == ELFCLASS64);
	int islsb = (buf[EI_DATA] == ELFDATA2LSB);
	uint16_t type, machine, phnum, phents, shnum, shents;
	uint64_t phoff, shoff;
	char interp[256];
	char build_id[128];
	int has_interp = 0;
	int stripped = 1;
	uint16_t i;

	interp[0] = '\0';
	build_id[0] = '\0';

	if (is64) {
		Elf64_Ehdr eh;
		if (len < sizeof(eh))
			return 0;
		memcpy(&eh, buf, sizeof(eh));

		type    = islsb ? f_get_le16(&eh.e_type) : f_get_be16(&eh.e_type);
		machine = islsb ? f_get_le16(&eh.e_machine) : f_get_be16(&eh.e_machine);
		phoff   = islsb ? f_get_le64(&eh.e_phoff) : f_get_be64((const uint8_t *)&eh.e_phoff);
		shoff   = islsb ? f_get_le64(&eh.e_shoff) : f_get_be64((const uint8_t *)&eh.e_shoff);
		phnum   = islsb ? f_get_le16(&eh.e_phnum) : f_get_be16(&eh.e_phnum);
		phents  = islsb ? f_get_le16(&eh.e_phentsize) : f_get_be16(&eh.e_phentsize);
		shnum   = islsb ? f_get_le16(&eh.e_shnum) : f_get_be16(&eh.e_shnum);
		shents  = islsb ? f_get_le16(&eh.e_shentsize) : f_get_be16(&eh.e_shentsize);
	} else {
		Elf32_Ehdr eh;
		if (len < sizeof(eh))
			return 0;
		memcpy(&eh, buf, sizeof(eh));

		type    = islsb ? f_get_le16(&eh.e_type) : f_get_be16(&eh.e_type);
		machine = islsb ? f_get_le16(&eh.e_machine) : f_get_be16(&eh.e_machine);
		phoff   = islsb ? f_get_le32(&eh.e_phoff) : f_get_be32(&eh.e_phoff);
		shoff   = islsb ? f_get_le32(&eh.e_shoff) : f_get_be32(&eh.e_shoff);
		phnum   = islsb ? f_get_le16(&eh.e_phnum) : f_get_be16(&eh.e_phnum);
		phents  = islsb ? f_get_le16(&eh.e_phentsize) : f_get_be16(&eh.e_phentsize);
		shnum   = islsb ? f_get_le16(&eh.e_shnum) : f_get_be16(&eh.e_shnum);
		shents  = islsb ? f_get_le16(&eh.e_shentsize) : f_get_be16(&eh.e_shentsize);
	}

	/* Traverse Program Headers */
	if (phoff > 0 && phents > 0) {
		for (i = 0; i < phnum; i++) {
			off_t poff = (off_t)phoff + (off_t)i * phents;
			uint32_t ptype = 0;
			uint64_t fileoff = 0, filesz = 0;

			if (is64) {
				Elf64_Phdr ph;
				if (pread(fd, &ph, sizeof(ph), poff) != sizeof(ph))
					break;
				ptype   = islsb ? f_get_le32(&ph.p_type) : f_get_be32(&ph.p_type);
				fileoff = islsb ? f_get_le64(&ph.p_offset) : f_get_be64((const uint8_t *)&ph.p_offset);
				filesz  = islsb ? f_get_le64(&ph.p_filesz) : f_get_be64((const uint8_t *)&ph.p_filesz);
			} else {
				Elf32_Phdr ph;
				if (pread(fd, &ph, sizeof(ph), poff) != sizeof(ph))
					break;
				ptype   = islsb ? f_get_le32(&ph.p_type) : f_get_be32(&ph.p_type);
				fileoff = islsb ? f_get_le32(&ph.p_offset) : f_get_be32(&ph.p_offset);
				filesz  = islsb ? f_get_le32(&ph.p_filesz) : f_get_be32(&ph.p_filesz);
			}

			if (ptype == PT_INTERP && filesz > 0 && filesz < sizeof(interp)) {
				ssize_t rd = pread(fd, interp, filesz, (off_t)fileoff);
				if (rd > 0) {
					interp[rd] = '\0';
					if (interp[rd - 1] == '\0')
						rd--;
					interp[rd] = '\0';
					has_interp = 1;
				}
			} else if (ptype == PT_NOTE && filesz >= 16 && filesz <= 1024) {
				unsigned char nbuf[1024];
				ssize_t nrd = pread(fd, nbuf, filesz, (off_t)fileoff);
				if (nrd >= 16) {
					uint32_t namesz = islsb ? f_get_le32(nbuf) : f_get_be32(nbuf);
					uint32_t descsz = islsb ? f_get_le32(nbuf + 4) : f_get_be32(nbuf + 4);
					uint32_t ntype  = islsb ? f_get_le32(nbuf + 8) : f_get_be32(nbuf + 8);
					uint32_t noff   = 12 + ((namesz + 3) & ~3);

					if (ntype == 3 && namesz == 4 && memcmp(nbuf + 12, "GNU\0", 4) == 0 &&
					    descsz > 0 && descsz <= 64 && noff + descsz <= (uint32_t)nrd) {
						char *dst = build_id;
						uint32_t b;
						dst += sprintf(dst, ", BuildID[sha1]=");
						for (b = 0; b < descsz && (dst - build_id) < 120; b++)
							dst += sprintf(dst, "%02x", nbuf[noff + b]);
					}
				}
			}
		}
	}

	stripped = is_elf_stripped(fd, is64, islsb, shoff, shnum, shents);

	if (opt & OPT_i) {
		if (type == ET_EXEC || (type == ET_DYN && has_interp))
			puts("application/x-executable; charset=binary");
		else if (type == ET_DYN)
			puts("application/x-sharedlib; charset=binary");
		else if (type == ET_REL)
			puts("application/x-object; charset=binary");
		else if (type == ET_CORE)
			puts("application/x-coredump; charset=binary");
		else
			puts("application/x-pie-executable; charset=binary");
		return 1;
	}

	/* Standard human-readable ELF description */
	printf("ELF %d-bit %s %s, %s, version 1 (%s)",
		is64 ? 64 : 32,
		islsb ? "LSB" : "MSB",
		(type == ET_EXEC) ? "executable" :
		(type == ET_DYN && has_interp) ? "pie executable" :
		(type == ET_DYN) ? "shared object" :
		(type == ET_REL) ? "relocatable" :
		(type == ET_CORE) ? "core dump" : "unknown type",
		elf_machine_str(machine),
		elf_osabi_str(buf[EI_OSABI]));

	if (has_interp)
		printf(", dynamically linked, interpreter %s", interp);
	else if (type == ET_EXEC || type == ET_DYN)
		printf(", statically linked");

	printf("%s", build_id);
	printf(", %s\n", stripped ? "stripped" : "not stripped");

	return 1;
}

static int parse_magic(int fd, const unsigned char *buf, size_t len, int opt)
{
	/* 1. ELF Binaries */
	if (len >= 16 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
		return parse_elf(fd, buf, len, opt);
	}

	/* 2. Android Formats */
	if (len >= 8 && memcmp(buf, "ANDROID!", 8) == 0) {
		if (opt & OPT_i) {
			puts("application/octet-stream; charset=binary");
		} else {
			uint32_t ksz = f_get_le32(buf + 8);
			uint32_t rsz = f_get_le32(buf + 16);
			uint32_t ver = (len >= 44) ? f_get_le32(buf + 40) : 0;
			printf("Android boot image, version %u, kernel size %u, ramdisk size %u\n",
				ver, ksz, rsz);
		}
		return 1;
	}

	if (len >= 4 && f_get_le32(buf) == 0xed26ff3a) {
		if (opt & OPT_i) {
			puts("application/octet-stream; charset=binary");
		} else {
			uint16_t maj = f_get_le16(buf + 4);
			uint16_t min = f_get_le16(buf + 6);
			uint32_t blk = (len >= 20) ? f_get_le32(buf + 16) : 0;
			printf("Android sparse image, version %u.%u, Total Blks %u\n", maj, min, blk);
		}
		return 1;
	}

	if (len >= 4 && f_get_be32(buf) == 0xd00dfeed) {
		if (opt & OPT_i) {
			puts("application/x-dtb; charset=binary");
		} else {
			uint32_t sz = (len >= 8) ? f_get_be32(buf + 4) : 0;
			uint32_t ver = (len >= 20) ? f_get_be32(buf + 16) : 0;
			printf("Device Tree Blob (DTB/DTBO), version %u, size %u bytes\n", ver, sz);
		}
		return 1;
	}

	if (len >= 8 && memcmp(buf, "dex\n", 4) == 0) {
		if (opt & OPT_i) {
			puts("application/x-dex; charset=binary");
		} else {
			printf("Dalvik dex file, version %c%c%c\n", buf[4], buf[5], buf[6]);
		}
		return 1;
	}

	if (len >= 8 && memcmp(buf, "cdex", 4) == 0) {
		if (opt & OPT_i) {
			puts("application/x-cdex; charset=binary");
		} else {
			printf("Compact Dalvik dex file, version %c%c%c\n", buf[4], buf[5], buf[6]);
		}
		return 1;
	}

	if (len >= 8 && memcmp(buf, "art\n", 4) == 0) {
		if (opt & OPT_i)
			puts("application/octet-stream; charset=binary");
		else
			puts("Android ART image file");
		return 1;
	}

	if (len >= 4 && f_get_le32(buf) == 0x616c4430) {
		if (opt & OPT_i)
			puts("application/octet-stream; charset=binary");
		else
			puts("Android Super Image (LP metadata)");
		return 1;
	}

	if (len >= 4 && memcmp(buf, "CrAU", 4) == 0) {
		if (opt & OPT_i)
			puts("application/octet-stream; charset=binary");
		else
			puts("Android OTA update payload image");
		return 1;
	}

	/* 3. Compressed & Archive Formats */
	if (len >= 2 && buf[0] == 0x1f && buf[1] == 0x8b) {
		if (opt & OPT_i) {
			puts("application/gzip; charset=binary");
		} else {
			printf("gzip compressed data, max compression, from Unix");
			if (len >= 10 && (buf[3] & 0x08)) { /* FNAME flag */
				size_t n = 10;
				while (n < len && buf[n]) n++;
				if (n < len)
					printf(", original size name: \"%.*s\"", (int)(n - 10), buf + 10);
			}
			putchar('\n');
		}
		return 1;
	}

	if (len >= 3 && buf[0] == 'B' && buf[1] == 'Z' && buf[2] == 'h') {
		if (opt & OPT_i)
			puts("application/x-bzip2; charset=binary");
		else
			printf("bzip2 compressed data, block size = %c00k\n", (len >= 4) ? buf[3] : '9');
		return 1;
	}

	if (len >= 6 && memcmp(buf, "\xfd""7zXZ\x00", 6) == 0) {
		if (opt & OPT_i)
			puts("application/x-xz; charset=binary");
		else
			puts("XZ compressed data");
		return 1;
	}

	if (len >= 4 && f_get_le32(buf) == 0xfd2fb528) {
		if (opt & OPT_i)
			puts("application/zstd; charset=binary");
		else
			puts("Zstandard compressed data (zstd)");
		return 1;
	}

	if (len >= 4 && (f_get_le32(buf) == 0x184d2204 || f_get_le32(buf) == 0x184c2102)) {
		if (opt & OPT_i)
			puts("application/x-lz4; charset=binary");
		else
			puts("LZ4 compressed data");
		return 1;
	}

	if (len >= 6 && memcmp(buf, "7z\xbc\xaf\x27\x1c", 6) == 0) {
		if (opt & OPT_i)
			puts("application/x-7z-compressed; charset=binary");
		else
			puts("7-zip archive data");
		return 1;
	}

	if (len >= 4 && buf[0] == 'P' && buf[1] == 'K' && (buf[2] == 3 || buf[2] == 5)) {
		if (opt & OPT_i) {
			/* Check if APK */
			if (len >= 60 && memmem(buf, len, "AndroidManifest.xml", 19))
				puts("application/vnd.android.package-archive; charset=binary");
			else if (len >= 60 && memmem(buf, len, "META-INF/", 9))
				puts("application/java-archive; charset=binary");
			else
				puts("application/zip; charset=binary");
		} else {
			if (len >= 60 && memmem(buf, len, "AndroidManifest.xml", 19))
				puts("Android package (APK), Zip archive data");
			else if (len >= 60 && memmem(buf, len, "META-INF/", 9))
				puts("Java archive (JAR), Zip archive data");
			else
				puts("Zip archive data");
		}
		return 1;
	}

	if (len >= 6 && (memcmp(buf, "070701", 6) == 0 || memcmp(buf, "070702", 6) == 0)) {
		if (opt & OPT_i)
			puts("application/x-cpio; charset=binary");
		else
			puts("ASCII cpio archive (SVR4 with/without CRC)");
		return 1;
	}

	if (len >= 6 && memcmp(buf, "070707", 6) == 0) {
		if (opt & OPT_i)
			puts("application/x-cpio; charset=binary");
		else
			puts("ASCII cpio archive (pre-SVR4)");
		return 1;
	}

	if (len >= 512 && (memcmp(buf + 257, "ustar\0", 6) == 0 || memcmp(buf + 257, "ustar  \0", 8) == 0)) {
		if (opt & OPT_i)
			puts("application/x-tar; charset=binary");
		else
			puts("POSIX tar archive (ustar)");
		return 1;
	}

	if (len >= 4 && memcmp(buf, "Rar!\x1a\x07", 4) == 0) {
		if (opt & OPT_i)
			puts("application/x-rar; charset=binary");
		else
			puts("RAR archive data");
		return 1;
	}

	if (len >= 4 && (memcmp(buf, "hsqs", 4) == 0 || memcmp(buf, "sqsh", 4) == 0)) {
		if (opt & OPT_i)
			puts("application/x-squashfs; charset=binary");
		else
			printf("Squashfs filesystem, %s endian\n", (buf[0] == 'h') ? "little" : "big");
		return 1;
	}

	/* 4. Filesystems at secondary offsets */
	{
		unsigned char super[1024];
		ssize_t s_rd = pread(fd, super, sizeof(super), 1024);
		if (s_rd >= 60) {
			/* Ext2/3/4 at 1080 (offset 56 inside superblock) */
			if (f_get_le16(super + 56) == 0xef53) {
				if (opt & OPT_i)
					puts("application/x-ext4; charset=binary");
				else
					puts("Linux rev 1.0 ext2/ext3/ext4 filesystem data");
				return 1;
			}
			/* F2FS at offset 1024 */
			if (f_get_le32(super) == 0xf2f52010) {
				if (opt & OPT_i)
					puts("application/x-f2fs; charset=binary");
				else
					puts("F2FS filesystem data");
				return 1;
			}
			/* EROFS at offset 1024 */
			if (f_get_le32(super) == 0xe0f5e1e2) {
				if (opt & OPT_i)
					puts("application/x-erofs; charset=binary");
				else
					puts("EROFS filesystem data");
				return 1;
			}
		}
	}

	/* 5. Scripts and Text */
	if (len >= 2 && buf[0] == '#' && buf[1] == '!') {
		size_t n = 2;
		while (n < len && buf[n] != '\n' && buf[n] != '\r') n++;

		if (opt & OPT_i) {
			if (memmem(buf, n, "sh", 2))
				puts("text/x-shellscript; charset=us-ascii");
			else if (memmem(buf, n, "python", 6))
				puts("text/x-python; charset=us-ascii");
			else if (memmem(buf, n, "perl", 4))
				puts("text/x-perl; charset=us-ascii");
			else
				puts("text/plain; charset=us-ascii");
		} else {
			if (memmem(buf, n, "sh", 2))
				printf("POSIX shell script, ASCII text executable\n");
			else if (memmem(buf, n, "python", 6))
				printf("Python script, ASCII text executable\n");
			else if (memmem(buf, n, "perl", 4))
				printf("Perl script, ASCII text executable\n");
			else
				printf("script, ASCII text executable\n");
		}
		return 1;
	}

	if (len >= 5 && memcmp(buf, "<?xml", 5) == 0) {
		if (opt & OPT_i)
			puts("text/xml; charset=us-ascii");
		else
			puts("XML 1.0 document, ASCII text");
		return 1;
	}

	if (len >= 14 && (memmem(buf, len, "<!DOCTYPE html", 14) || memmem(buf, len, "<html", 5))) {
		if (opt & OPT_i)
			puts("text/html; charset=us-ascii");
		else
			puts("HTML document, ASCII text");
		return 1;
	}

	if (len >= 11 && memcmp(buf, "-----BEGIN ", 11) == 0) {
		if (opt & OPT_i)
			puts("application/x-pem-file; charset=us-ascii");
		else
			puts("PEM certificate or cryptographic key, ASCII text");
		return 1;
	}

	/* 6. Plain ASCII / UTF-8 Text vs Binary Data Analysis */
	{
		size_t i;
		int is_ascii = 1;
		int is_utf8 = 1;
		int has_cr = 0;
		int has_lf = 0;
		int printable = 0;

		for (i = 0; i < len; i++) {
			unsigned char c = buf[i];
			if (c == 0) {
				is_ascii = 0;
				is_utf8 = 0;
				break;
			}
			if (c == '\r') has_cr = 1;
			if (c == '\n') has_lf = 1;

			if (c >= 0x20 && c <= 0x7e) {
				printable++;
			} else if (c == '\t' || c == '\n' || c == '\r' || c == '\f') {
				printable++;
			} else if (c >= 0x80) {
				is_ascii = 0;
			} else {
				/* Unprintable control characters */
				is_ascii = 0;
				is_utf8 = 0;
				break;
			}
		}

		if (is_ascii && len > 0) {
			if (opt & OPT_i) {
				puts("text/plain; charset=us-ascii");
			} else {
				printf("ASCII text");
				if (has_cr && has_lf)
					printf(", with CRLF line terminators");
				else if (has_cr)
					printf(", with CR line terminators");
				putchar('\n');
			}
			return 1;
		}

		if (is_utf8 && len > 0 && printable > (int)(len / 2)) {
			if (opt & OPT_i) {
				puts("text/plain; charset=utf-8");
			} else {
				printf("UTF-8 Unicode text");
				if (has_cr && has_lf)
					printf(", with CRLF line terminators");
				putchar('\n');
			}
			return 1;
		}
	}

	/* Fallback */
	if (opt & OPT_i)
		puts("application/octet-stream; charset=binary");
	else
		puts("data");

	return 1;
}

static int process_file(const char *path, int opt)
{
	struct stat st;
	int res;
	int fd;
	unsigned char buf[4096];
	ssize_t nread;

	res = (opt & OPT_L) ? stat(path, &st) : lstat(path, &st);
	if (res < 0) {
		bb_perror_msg("%s", path);
		return 1;
	}

	if (!(opt & OPT_b))
		printf("%s: ", path);

	/* File mode classification */
	if (S_ISLNK(st.st_mode)) {
		if (opt & OPT_i) {
			puts("inode/symlink; charset=binary");
		} else {
			char target[PATH_MAX];
			ssize_t len = readlink(path, target, sizeof(target) - 1);
			if (len >= 0) {
				target[len] = '\0';
				printf("symbolic link to %s\n", target);
			} else {
				puts("symbolic link");
			}
		}
		return 0;
	}

	if (S_ISDIR(st.st_mode)) {
		if (opt & OPT_i)
			puts("inode/directory; charset=binary");
		else
			puts("directory");
		return 0;
	}

	if (S_ISCHR(st.st_mode)) {
		if (opt & OPT_i)
			puts("inode/chardevice; charset=binary");
		else
			printf("character special (%u/%u)\n", major(st.st_rdev), minor(st.st_rdev));
		return 0;
	}

	if (S_ISBLK(st.st_mode)) {
		if (opt & OPT_i)
			puts("inode/blockdevice; charset=binary");
		else
			printf("block special (%u/%u)\n", major(st.st_rdev), minor(st.st_rdev));
		return 0;
	}

	if (S_ISFIFO(st.st_mode)) {
		if (opt & OPT_i)
			puts("inode/fifo; charset=binary");
		else
			puts("fifo (named pipe)");
		return 0;
	}

	if (S_ISSOCK(st.st_mode)) {
		if (opt & OPT_i)
			puts("inode/socket; charset=binary");
		else
			puts("socket");
		return 0;
	}

	if (st.st_size == 0) {
		if (opt & OPT_i)
			puts("application/x-empty; charset=binary");
		else
			puts("empty");
		return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		bb_perror_msg("cannot open '%s'", path);
		return 1;
	}

	nread = read(fd, buf, sizeof(buf));
	if (nread < 0) {
		bb_perror_msg("read error on '%s'", path);
		close(fd);
		return 1;
	}

	parse_magic(fd, buf, nread, opt);

	close(fd);
	return 0;
}

int file_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int file_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned opt;
	int status = EXIT_SUCCESS;

	opt = getopt32(argv, "^" "bhiL" "\0" "-1" /* at least 1 file */);
	argv += optind;

	while (*argv) {
		if (process_file(*argv, opt) != 0)
			status = EXIT_FAILURE;
		argv++;
	}

	return status;
}
