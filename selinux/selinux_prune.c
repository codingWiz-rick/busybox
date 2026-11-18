/* vi: set sw=4 ts=4: */
/*
 * selinux_prune.c - libselinux static pruning stubs for BusyBox
 *
 * Eliminates deprecated regex and file labeling subsystems:
 * - matchpathcon.o (deprecated desktop file_contexts parser)
 * - label.o and label_file.o (selabel_file_init)
 * - regex.o (pcre2_compile, pcre2_match)
 * - libpcre2-8.a (drops ~150 KB code + 80 KB _pcre2_ucd_stage2_8 Unicode table)
 *
 * Android uses binary precompiled contexts (/plat_file_contexts) and direct
 * kernel sysfs (/sys/fs/selinux/load), making desktop matchpathcon dead weight.
 *
 * Licensed under GPLv2 or later.
 */

//kbuild:lib-$(CONFIG_SELINUX) += selinux_prune.o

#include "libbb.h"

#if ENABLE_SELINUX

/* Anchor to ensure selinux_prune.o is linked */
void selinux_prune_anchor(void);
void selinux_prune_anchor(void)
{
}

/*
 * Stubs for matchpathcon family (deprecated in upstream libselinux)
 */
int matchpathcon(const char *path, mode_t mode, char **con);
int matchpathcon(const char *path UNUSED_PARAM, mode_t mode UNUSED_PARAM, char **con)
{
	if (con)
		*con = NULL;
	return -1;
}

int matchpathcon_index(const char *path, mode_t mode, char **con);
int matchpathcon_index(const char *path UNUSED_PARAM, mode_t mode UNUSED_PARAM, char **con)
{
	if (con)
		*con = NULL;
	return -1;
}

void matchpathcon_fini(void);
void matchpathcon_fini(void)
{
}

int matchpathcon_init(const char *path);
int matchpathcon_init(const char *path UNUSED_PARAM)
{
	return -1;
}

int matchpathcon_init_prefix(const char *path, const char *prefix);
int matchpathcon_init_prefix(const char *path UNUSED_PARAM, const char *prefix UNUSED_PARAM)
{
	return -1;
}

int matchpathcon_filespec_add(ino_t ino, int specind, const char *con);
int matchpathcon_filespec_add(ino_t ino UNUSED_PARAM, int specind UNUSED_PARAM, const char *con UNUSED_PARAM)
{
	return -1;
}

void matchpathcon_filespec_destroy(void);
void matchpathcon_filespec_destroy(void)
{
}

void matchpathcon_filespec_eval(void);
void matchpathcon_filespec_eval(void)
{
}

void matchpathcon_checkmatches(char *str);
void matchpathcon_checkmatches(char *str UNUSED_PARAM)
{
}

void set_matchpathcon_flags(unsigned int flags);
void set_matchpathcon_flags(unsigned int flags UNUSED_PARAM)
{
}

/*
 * Backend stubs for selabel subsystems to prevent pulling in regex.o and libpcre2-8
 */
int selabel_file_init(void *rec, const void *opts, unsigned nopts);
int selabel_file_init(void *rec UNUSED_PARAM, const void *opts UNUSED_PARAM, unsigned nopts UNUSED_PARAM)
{
	return -1;
}

int selabel_db_init(void *rec, const void *opts, unsigned nopts);
int selabel_db_init(void *rec UNUSED_PARAM, const void *opts UNUSED_PARAM, unsigned nopts UNUSED_PARAM)
{
	return -1;
}

int selabel_media_init(void *rec, const void *opts, unsigned nopts);
int selabel_media_init(void *rec UNUSED_PARAM, const void *opts UNUSED_PARAM, unsigned nopts UNUSED_PARAM)
{
	return -1;
}

int selabel_x_init(void *rec, const void *opts, unsigned nopts);
int selabel_x_init(void *rec UNUSED_PARAM, const void *opts UNUSED_PARAM, unsigned nopts UNUSED_PARAM)
{
	return -1;
}

int compat_validate(void *rec, void *contexts, const char *path, unsigned lineno);
int compat_validate(void *rec UNUSED_PARAM, void *contexts UNUSED_PARAM, const char *path UNUSED_PARAM, unsigned lineno UNUSED_PARAM)
{
	return 0;
}

#endif /* ENABLE_SELINUX */
