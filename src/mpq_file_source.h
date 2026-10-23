/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Internal header: MPQ v1 I/O implementation for file data.
 */

#ifndef MPQFS_MPQ_FILE_SOURCE_H
#define MPQFS_MPQ_FILE_SOURCE_H

#include <stdio.h>

#include "mpqfs/mpqfs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create an I/O data source from a file descriptor.
 */
mpqfs_error_code mpq_init_file_source(FILE *f, int ownsFd, mpqfs_io_t *io, void **outDs);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_FILE_SOURCE_H */
