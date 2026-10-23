/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * MPQ v1 I/O implementation for file data.
 */
#include "mpq_file_source.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "mpq_platform.h"
#include "mpqfs/mpqfs.h"

/* -----------------------------------------------------------------------
 * I/O implementation for plain file descriptors
 * ----------------------------------------------------------------------- */

typedef struct mpqfs_fp {
	FILE *f;     /* Underlying file handle          */
	int owns_fd; /* Non-zero if we should fclose(f) */
} mpqfs_fp_t;

static size_t mpqfs_fp_read(void *ds, void *buffer, size_t size)
{
	mpqfs_fp_t *fp = (mpqfs_fp_t *)ds;
	return fread(buffer, 1, size, fp->f);
}

static size_t mpqfs_fp_write(void *ds, const void *buffer, size_t size)
{
	mpqfs_fp_t *fp = (mpqfs_fp_t *)ds;
	return fwrite(buffer, 1, size, fp->f);
}

static int mpqfs_fp_seek(void *ds, long offset, int origin)
{
	mpqfs_fp_t *fp = (mpqfs_fp_t *)ds;
	return fseek(fp->f, offset, origin);
}

static int mpqfs_fp_close(void *ds)
{
	mpqfs_fp_t *fp = (mpqfs_fp_t *)ds;
	int result = 0;
	if (fp->f && fp->owns_fd)
		result = fclose(fp->f);
	free(fp);
	return result;
}

mpqfs_error_code mpq_init_file_source(FILE *f, int ownsFd, mpqfs_io_t *io, void **outDs)
{
	*outDs = NULL;

	io->read = mpqfs_fp_read;
	io->write = mpqfs_fp_write;
	io->seek = mpqfs_fp_seek;
	io->close = mpqfs_fp_close;

	mpqfs_fp_t *fp = (mpqfs_fp_t *)calloc(1, sizeof(mpqfs_fp_t));
	if (MPQFS_UNLIKELY(!fp)) {
		fclose(f);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	fp->f = f;
	fp->owns_fd = ownsFd;
	*outDs = (void *)fp;

	return MPQFS_OK;
}
