/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Internal header: per-file stream state for sector-based reads.
 */

#ifndef MPQFS_MPQ_STREAM_H
#define MPQFS_MPQ_STREAM_H

#include "mpq_archive.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An mpq_stream_t represents an open handle to a single file within an MPQ
 * archive.  It manages:
 *   - the current read position (logical offset within the uncompressed file)
 *   - a cached decompressed sector so that sequential reads don't decompress
 *     the same sector repeatedly
 *   - the sector offset table (for compressed files, read from the archive on
 *     open)
 *
 * The stream does NOT own the archive — the caller must keep the archive alive
 * for the lifetime of any stream created from it.
 */
typedef struct mpq_stream {
    /* Back-pointer to the parent archive (not owned). */
    mpqfs_archive_t *archive;

    /* Index into the archive's block table. */
    uint32_t block_index;

    /* Convenience copies from the block table entry. */
    uint32_t file_offset;       /* Byte offset of file data from archive start */
    uint32_t compressed_size;   /* Total compressed size on disk              */
    uint32_t file_size;         /* Uncompressed file size                     */
    uint32_t flags;             /* Block flags (MPQ_FILE_*)                   */

    /* Sector geometry. */
    uint32_t sector_size;       /* Bytes per uncompressed sector              */
    uint32_t sector_count;      /* Number of sectors (including partial last) */

    /*
     * Sector offset table — only present for compressed files.
     * Has (sector_count + 1) entries; entry[i] is the byte offset (relative to
     * file_offset) of sector i's compressed data, and entry[sector_count] marks
     * the end.  NULL for files stored without compression.
     */
    uint32_t *sector_offsets;

    /*
     * Decryption key for this file (0 if not encrypted).
     * Derived from the filename via mpq_file_key() when the stream is
     * opened with mpq_stream_open_named().
     */
    uint32_t file_key;

    /*
     * Cached decompressed sector buffer.
     * Allocated to sector_size bytes.
     */
    uint8_t *sector_buf;

    /* Index of the sector currently held in sector_buf, or (uint32_t)-1. */
    uint32_t cached_sector;

    /* Number of valid bytes in sector_buf (may be < sector_size for last sector). */
    uint32_t cached_sector_len;

    /*
     * Reusable buffer for reading compressed sector data.
     * Allocated on first use and grown as needed, avoiding a malloc/free
     * per sector read.  Freed when the stream is closed.
     */
    uint8_t *comp_buf;
    uint32_t comp_buf_cap;

    /* Current logical read position within the uncompressed file. */
    uint64_t position;
} mpq_stream_t;

/*
 * Open a stream to the file identified by `block_index` inside `archive`.
 * Returns NULL on error (sets mpqfs_last_error).
 *
 * This variant does NOT support encrypted files — use mpq_stream_open_named()
 * instead when the file may be encrypted.
 */
mpq_stream_t *mpq_stream_open(mpqfs_archive_t *archive, uint32_t block_index);

/*
 * Open a stream to the file identified by `block_index`, using `filename`
 * to derive the decryption key if the file is encrypted.
 *
 * `filename` is the archive-internal path (e.g. "ui_art\\title.pcx" or
 * "(listfile)").  If the file is not encrypted, `filename` is ignored and
 * the call is equivalent to mpq_stream_open().
 *
 * Returns NULL on error (sets mpqfs_last_error).
 */
mpq_stream_t *mpq_stream_open_named(mpqfs_archive_t *archive,
                                     uint32_t block_index,
                                     const char *filename);

/*
 * Close a stream and free all associated memory.
 * Does NOT close the parent archive.
 */
void mpq_stream_close(mpq_stream_t *stream);

/*
 * Read up to `count` bytes from the stream at its current position into `buf`.
 * Advances the position by the number of bytes actually read.
 * Returns the number of bytes read, or (size_t)-1 on error.
 */
size_t mpq_stream_read(mpq_stream_t *stream, void *buf, size_t count);

/*
 * Seek to an absolute position within the uncompressed file.
 * Supports SEEK_SET, SEEK_CUR, SEEK_END (same semantics as fseek/lseek).
 * Returns the new absolute position, or -1 on error.
 */
int64_t mpq_stream_seek(mpq_stream_t *stream, int64_t offset, int whence);

/*
 * Return the current read position.
 */
int64_t mpq_stream_tell(mpq_stream_t *stream);

/*
 * Return the total uncompressed size of the file.
 */
size_t mpq_stream_size(mpq_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_STREAM_H */