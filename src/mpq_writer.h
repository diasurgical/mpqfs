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
 *
 * File data is streamed to disk during mpqfs_writer_add_file() so that
 * peak RAM usage does not scale with the total size of all files.  Only
 * per-file metadata (filename, offset, sizes, flags) is kept in memory.
 * The header and tables are written (or rewritten) during
 * mpqfs_writer_close() once all metadata is known.
 */

#ifndef MPQFS_MPQ_WRITER_H
#define MPQFS_MPQ_WRITER_H

#include "mpq_archive.h"
#include "mpq_platform.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Per-file metadata stored in the writer (no file content buffered)
 * ----------------------------------------------------------------------- */

struct mpqfs_writer_file {
	char *filename;           /* Archive-relative path (owned, heap-allocated) */
	uint32_t offset;          /* Offset of file data from archive start       */
	uint32_t compressed_size; /* Total on-disk size (offset table + sectors)   */
	uint32_t file_size;       /* Original uncompressed size                    */
	uint32_t flags;           /* Block flags (EXISTS, IMPLODE, etc.)           */
};
typedef struct mpqfs_writer_file mpqfs_writer_file_t;

/* -----------------------------------------------------------------------
 * Writer state
 * ----------------------------------------------------------------------- */

#define MPQFS_WRITER_INITIAL_CAPACITY 16

struct mpqfs_writer {
	FILE *fp;    /* Destination file handle                   */
	int owns_fd; /* Non-zero if we should fclose(fp)         */

	uint32_t hash_table_size;   /* Number of hash table entries (power of 2)*/
	uint16_t sector_size_shift; /* Sector size = 512 << shift (default 3)   */

	/* Dynamic array of file metadata (no file content stored). */
	mpqfs_writer_file_t *files;
	uint32_t file_count;    /* Number of files added so far             */
	uint32_t file_capacity; /* Allocated capacity of the files array    */

	uint32_t data_start;  /* Offset where file data begins (after hdr+tables) */
	uint32_t data_cursor;  /* Current write offset for next file's data        */

	char error[256]; /* Last error message                       */
};
typedef struct mpqfs_writer mpqfs_writer_t;
#define MPQFS_WRITER_T_DEFINED

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