/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Internal header: MPQ v1 writer data structures.
 *
 * The writer creates MPQ v1 archives in the style used by DevilutionX
 * for its save-game files (.sv / .hsv):
 *   - PKWARE DCL implode compression (sector-based, with offset tables)
 *   - Falls back to uncompressed when compression doesn't help
 *   - No file-level encryption
 *   - Hash and block tables encrypted with standard MPQ keys
 *   - Both tables are hash_table_size entries (block table padded with zeros)
 *   - Tables placed before file data
 *
 * Layout produced:
 *   [MPQ Header  — 32 bytes]
 *   [Block table — hash_table_size × 16 bytes, encrypted]
 *   [Hash table  — hash_table_size × 16 bytes, encrypted]
 *   [File data   — PKWARE implode compressed, with sector offset tables]
 */

#ifndef MPQFS_MPQ_WRITER_H
#define MPQFS_MPQ_WRITER_H

#include "mpq_platform.h"
#include "mpq_archive.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Per-file entry stored in the writer before finalisation
 * ----------------------------------------------------------------------- */

typedef struct mpqfs_writer_file {
    char     *filename;   /* Archive-relative path (owned, heap-allocated)   */
    uint8_t  *data;       /* File contents (owned, heap-allocated copy)      */
    uint32_t  size;       /* Uncompressed (= on-disk) size in bytes         */
} mpqfs_writer_file_t;

/* -----------------------------------------------------------------------
 * Writer state
 * ----------------------------------------------------------------------- */

#define MPQFS_WRITER_INITIAL_CAPACITY 16

typedef struct mpqfs_writer {
    FILE     *fp;                /* Destination file handle                   */
    int       owns_fd;           /* Non-zero if we should fclose(fp)         */

    uint32_t  hash_table_size;   /* Number of hash table entries (power of 2)*/
    uint16_t  sector_size_shift; /* Sector size = 512 << shift (default 3)   */

    /* Dynamic array of files to be written. */
    mpqfs_writer_file_t *files;
    uint32_t  file_count;        /* Number of files added so far             */
    uint32_t  file_capacity;     /* Allocated capacity of the files array    */

    char      error[256];        /* Last error message                       */
} mpqfs_writer_t;

/* -----------------------------------------------------------------------
 * Internal helpers (implemented in mpq_writer.c)
 * ----------------------------------------------------------------------- */

/*
 * Set the writer's error string (printf-style).
 * Also mirrors the message to the thread-local g_last_error.
 */
void mpq_writer_set_error(mpqfs_writer_t *writer, const char *fmt, ...)
    MPQFS_PRINTF_ATTR(2, 3);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_WRITER_H */