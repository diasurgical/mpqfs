/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Sector-based file streaming with PKWARE DCL / zlib decompression
 * and optional per-file decryption.
 *
 * MPQ files are divided into sectors of `sector_size` bytes (typically
 * 4096).  Compressed files begin with a sector offset table that gives
 * the byte offset of each sector's compressed data relative to the
 * file's block offset.  The last entry in the table marks the end of
 * the last sector.
 *
 * For each read, we determine which sector(s) the request spans,
 * decompress on demand, cache the most recent sector, and copy into
 * the caller's buffer.
 *
 * Encrypted files (MPQ_FILE_ENCRYPTED) have their sector offset table
 * and sector data encrypted with a key derived from the filename.
 * When MPQ_FILE_FIX_KEY is also set, the key is further adjusted by
 * the block offset and file size.  Each sector is encrypted with
 * (key + sector_index).
 */

#include "mpq_platform.h"
#include "mpq_stream.h"
#include "mpq_crypto.h"
#include "mpq_explode.h"

#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
#include <zlib.h>
#endif
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
#include <bzlib.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Internal: read raw bytes from the archive at an absolute offset
 * ----------------------------------------------------------------------- */

static int mpq_raw_read(mpqfs_archive_t *archive, int64_t offset,
                        void *buf, size_t count)
{
    if (fseek(archive->fp, (long)offset, SEEK_SET) != 0)
        return -1;
    if (fread(buf, 1, count, archive->fp) != count)
        return -1;
    return 0;
}

/* -----------------------------------------------------------------------
 * Internal: load and decompress a single sector into stream->sector_buf
 * ----------------------------------------------------------------------- */

static int mpq_stream_load_sector(mpq_stream_t *stream, uint32_t sector_idx)
{
    /* Already cached? */
    if (stream->cached_sector == sector_idx)
        return 0;

    mpqfs_archive_t *archive = stream->archive;
    uint32_t flags = stream->flags;

    /* Compute the expected decompressed size for this sector. */
    uint32_t remaining = stream->file_size - (sector_idx * stream->sector_size);
    uint32_t expect = (remaining < stream->sector_size) ? remaining : stream->sector_size;

    /* Absolute offset of the file's data block in the underlying file. */
    int64_t file_abs = (int64_t)archive->archive_offset + (int64_t)stream->file_offset;

    if (flags & (MPQ_FILE_IMPLODE | MPQ_FILE_COMPRESS)) {
        /*
         * Compressed file — use the sector offset table to find the
         * compressed data for this sector.
         */
        if (!stream->sector_offsets) {
            mpq_set_error(archive, "mpq_stream: missing sector offset table");
            return -1;
        }

        uint32_t sector_start = stream->sector_offsets[sector_idx];
        uint32_t sector_end   = stream->sector_offsets[sector_idx + 1];

        if (sector_end < sector_start) {
            mpq_set_error(archive, "mpq_stream: corrupt sector offsets "
                          "(sector %u: start=%u end=%u)",
                          sector_idx, sector_start, sector_end);
            return -1;
        }

        uint32_t comp_size = sector_end - sector_start;

        if (comp_size == 0) {
            /* Zero-length sector — treat as all zeros. */
            memset(stream->sector_buf, 0, expect);
            stream->cached_sector     = sector_idx;
            stream->cached_sector_len = expect;
            return 0;
        }

        /*
         * If the compressed size equals the expected uncompressed size,
         * the sector is stored uncompressed (the compressor gave up).
         */
        if (comp_size == expect) {
            if (mpq_raw_read(archive, file_abs + sector_start,
                             stream->sector_buf, expect) != 0) {
                mpq_set_error(archive, "mpq_stream: read error on "
                              "uncompressed sector %u", sector_idx);
                return -1;
            }
            /* Decrypt in-place if needed. */
            if (stream->file_key != 0) {
                /* Truncate to complete uint32_t words (matching StormLib). */
                size_t dwords = expect / 4;
                mpq_decrypt_block((uint32_t *)stream->sector_buf,
                                  dwords, stream->file_key + sector_idx);
            }
            stream->cached_sector     = sector_idx;
            stream->cached_sector_len = expect;
            return 0;
        }

        /* Ensure the reusable compressed-data buffer is large enough. */
        if (comp_size > stream->comp_buf_cap) {
            uint8_t *new_buf = (uint8_t *)realloc(stream->comp_buf, comp_size);
            if (!new_buf) {
                mpq_set_error(archive, "mpq_stream: out of memory for "
                              "compressed sector (%u bytes)", comp_size);
                return -1;
            }
            stream->comp_buf = new_buf;
            stream->comp_buf_cap = comp_size;
        }
        uint8_t *comp_buf = stream->comp_buf;

        if (mpq_raw_read(archive, file_abs + sector_start,
                         comp_buf, comp_size) != 0) {
            mpq_set_error(archive, "mpq_stream: read error on "
                          "compressed sector %u", sector_idx);
            return -1;
        }

        /* Decrypt the compressed data before decompression. */
        if (stream->file_key != 0) {
            size_t dwords = comp_size / 4;
            mpq_decrypt_block((uint32_t *)comp_buf,
                              dwords, stream->file_key + sector_idx);
        }

        int rc;

        if (flags & MPQ_FILE_IMPLODE) {
            /*
             * PKWARE DCL implode — the entire sector payload is the
             * imploded stream (no extra compression-type byte).
             */
            rc = pk_explode_sector(comp_buf, comp_size,
                                   stream->sector_buf, expect);
            if (rc != PK_OK) {
                mpq_set_error(archive, "mpq_stream: PKWARE explode failed "
                              "on sector %u (rc=%d)", sector_idx, rc);
                return -1;
            }
        } else if (flags & MPQ_FILE_COMPRESS) {
            /*
             * Multi-method compression — the first byte of the sector
             * indicates the compression method(s) used.
             */
            if (comp_size < 1) {
                mpq_set_error(archive, "mpq_stream: zero-length compressed "
                              "sector %u", sector_idx);
                return -1;
            }

            uint8_t comp_method = comp_buf[0];
            const uint8_t *src_data = comp_buf + 1;
            uint32_t       src_len  = comp_size - 1;

            /*
             * MPQ multi-compression can layer multiple methods.
             * They are applied in a fixed order during compression;
             * we undo them in reverse order.  In practice Diablo 1
             * spawn.mpq only uses a single method per sector.
             *
             * We handle them from innermost (applied last during
             * compression = undone first) to outermost.
             */

            /* --- PKWARE DCL (0x08) --- */
            if (comp_method & MPQ_COMP_PKWARE) {
                rc = pk_explode_sector(src_data, src_len,
                                       stream->sector_buf, expect);
                if (rc != PK_OK) {
                    mpq_set_error(archive, "mpq_stream: PKWARE explode "
                                  "(multi) failed on sector %u (rc=%d)",
                                  sector_idx, rc);
                    return -1;
                }
                /* Output is now in sector_buf; if another method needs
                 * to run after this, it would read from sector_buf.
                 * For single-method (common case), we're done. */
            }

            /* --- zlib / deflate (0x02) --- */
            if (comp_method & MPQ_COMP_ZLIB) {
#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
                uLongf dest_len = (uLongf)expect;
                int zrc = uncompress(stream->sector_buf, &dest_len,
                                     src_data, (uLong)src_len);
                if (zrc != Z_OK) {
                    mpq_set_error(archive, "mpq_stream: zlib uncompress "
                                  "failed on sector %u (zrc=%d)",
                                  sector_idx, zrc);
                    return -1;
                }
#else
                mpq_set_error(archive, "mpq_stream: zlib decompression "
                              "required but mpqfs was built without zlib "
                              "support (sector %u)", sector_idx);
                return -1;
#endif
            }

            /* --- bzip2 (0x10) --- */
            if (comp_method & MPQ_COMP_BZIP2) {
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
                unsigned int dest_len = (unsigned int)expect;
                int brc = BZ2_bzBuffToBuffDecompress(
                              (char *)stream->sector_buf, &dest_len,
                              (char *)src_data, (unsigned int)src_len,
                              0, 0);
                if (brc != BZ_OK) {
                    mpq_set_error(archive, "mpq_stream: bzip2 decompress "
                                  "failed on sector %u (brc=%d)",
                                  sector_idx, brc);
                    return -1;
                }
#else
                mpq_set_error(archive, "mpq_stream: bzip2 decompression "
                              "required but mpqfs was built without bzip2 "
                              "support (sector %u)", sector_idx);
                return -1;
#endif
            }

            /* --- Unsupported methods --- */
            {
                uint8_t supported = MPQ_COMP_PKWARE;
#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
                supported |= MPQ_COMP_ZLIB;
#endif
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
                supported |= MPQ_COMP_BZIP2;
#endif
                if (comp_method & ~supported) {
                    mpq_set_error(archive, "mpq_stream: unsupported compression "
                                  "method 0x%02X on sector %u",
                                  (unsigned)comp_method, sector_idx);
                    return -1;
                }
            }
        }

        stream->cached_sector     = sector_idx;
        stream->cached_sector_len = expect;
        return 0;

    } else {
        /*
         * Uncompressed file — read directly from the archive.
         *
         * For single-unit files or uncompressed multi-sector files, the
         * data starts right after the file data offset.
         */
        int64_t sector_abs = file_abs + (int64_t)sector_idx * (int64_t)stream->sector_size;

        if (mpq_raw_read(archive, sector_abs, stream->sector_buf, expect) != 0) {
            mpq_set_error(archive, "mpq_stream: read error on raw sector %u",
                          sector_idx);
            return -1;
        }

        /* Decrypt in-place if needed. */
        if (stream->file_key != 0) {
            size_t dwords = expect / 4;
            mpq_decrypt_block((uint32_t *)stream->sector_buf,
                              dwords, stream->file_key + sector_idx);
        }

        stream->cached_sector     = sector_idx;
        stream->cached_sector_len = expect;
        return 0;
    }
}

/* -----------------------------------------------------------------------
 * Public API: open
 * ----------------------------------------------------------------------- */

mpq_stream_t *mpq_stream_open(mpqfs_archive_t *archive, uint32_t block_index)
{
    return mpq_stream_open_named(archive, block_index, NULL);
}

mpq_stream_t *mpq_stream_open_named(mpqfs_archive_t *archive,
                                     uint32_t block_index,
                                     const char *filename)
{
    if (!archive) {
        mpq_set_error(NULL, "mpq_stream_open: archive is NULL");
        return NULL;
    }

    if (block_index >= archive->header.block_table_count) {
        mpq_set_error(archive, "mpq_stream_open: block index %u out of range",
                      block_index);
        return NULL;
    }

    const mpq_block_entry_t *block = &archive->block_table[block_index];

    if (!(block->flags & MPQ_FILE_EXISTS)) {
        mpq_set_error(archive, "mpq_stream_open: block %u does not exist",
                      block_index);
        return NULL;
    }

    /* If the file is encrypted, we MUST have the filename to derive the key. */
    if ((block->flags & MPQ_FILE_ENCRYPTED) && !filename) {
        mpq_set_error(archive, "mpq_stream_open: block %u is encrypted but "
                      "no filename provided for key derivation", block_index);
        return NULL;
    }

    mpq_stream_t *stream = (mpq_stream_t *)calloc(1, sizeof(*stream));
    if (!stream) {
        mpq_set_error(archive, "mpq_stream_open: out of memory");
        return NULL;
    }

    stream->archive         = archive;
    stream->block_index     = block_index;
    stream->file_offset     = block->offset;
    stream->compressed_size = block->compressed_size;
    stream->file_size       = block->file_size;
    stream->flags           = block->flags;
    stream->sector_size     = archive->sector_size;
    stream->position        = 0;
    stream->cached_sector   = (uint32_t)-1;
    stream->cached_sector_len = 0;

    /* Derive the file decryption key if the file is encrypted. */
    if (block->flags & MPQ_FILE_ENCRYPTED) {
        int adjust = (block->flags & MPQ_FILE_FIX_KEY) != 0;
        stream->file_key = mpq_file_key(filename, block->offset,
                                        block->file_size, adjust);
    } else {
        stream->file_key = 0;
    }

    /* Zero-length file — nothing else to set up. */
    if (stream->file_size == 0) {
        stream->sector_count   = 0;
        stream->sector_offsets = NULL;
        stream->sector_buf     = NULL;
        return stream;
    }

    /* Compute sector count. */
    stream->sector_count = (stream->file_size + stream->sector_size - 1)
                           / stream->sector_size;

    /* Allocate the sector cache buffer. */
    stream->sector_buf = (uint8_t *)malloc(stream->sector_size);
    if (!stream->sector_buf) {
        mpq_set_error(archive, "mpq_stream_open: out of memory for sector buf");
        free(stream);
        return NULL;
    }

    /*
     * For compressed files (not single-unit), the block data begins with
     * a sector offset table: (sector_count + 1) uint32_t values giving
     * the byte offsets of each sector's compressed data relative to the
     * start of the block data.
     */
    if ((stream->flags & (MPQ_FILE_IMPLODE | MPQ_FILE_COMPRESS)) &&
        !(stream->flags & MPQ_FILE_SINGLE_UNIT))
    {
        uint32_t table_entries = stream->sector_count + 1;
        size_t   table_bytes   = (size_t)table_entries * sizeof(uint32_t);

        stream->sector_offsets = (uint32_t *)malloc(table_bytes);
        if (!stream->sector_offsets) {
            mpq_set_error(archive, "mpq_stream_open: out of memory for "
                          "sector offset table");
            free(stream->sector_buf);
            free(stream);
            return NULL;
        }

        int64_t abs_offset = (int64_t)archive->archive_offset
                           + (int64_t)stream->file_offset;

        /* Read the raw sector offset table from the archive. */
        uint8_t *raw_table = (uint8_t *)malloc(table_bytes);
        if (!raw_table) {
            mpq_set_error(archive, "mpq_stream_open: out of memory");
            free(stream->sector_offsets);
            free(stream->sector_buf);
            free(stream);
            return NULL;
        }

        if (mpq_raw_read(archive, abs_offset, raw_table, table_bytes) != 0) {
            mpq_set_error(archive, "mpq_stream_open: failed to read sector "
                          "offset table for block %u", block_index);
            free(raw_table);
            free(stream->sector_offsets);
            free(stream->sector_buf);
            free(stream);
            return NULL;
        }

        /* Convert from little-endian to native. */
        for (uint32_t i = 0; i < table_entries; i++) {
            stream->sector_offsets[i] = mpqfs_read_le32(raw_table + i * 4);
        }

        free(raw_table);

        /* If the file is encrypted, the sector offset table is encrypted
         * with the base file key (no sector index added). */
        if (stream->file_key != 0) {
            mpq_decrypt_block(stream->sector_offsets, table_entries,
                              stream->file_key - 1);
        }

        /* Basic sanity check on the offset table. */
        if (stream->sector_offsets[0] != table_bytes) {
            mpq_set_error(archive, "mpq_stream_open: sector offset table "
                          "validation failed for block %u (expected first "
                          "entry %u, got %u — table may be encrypted or "
                          "corrupt)", block_index,
                          (unsigned)table_bytes,
                          stream->sector_offsets[0]);
            free(stream->sector_offsets);
            free(stream->sector_buf);
            free(stream);
            return NULL;
        }
    } else if (stream->flags & MPQ_FILE_SINGLE_UNIT) {
        /*
         * Single-unit files store all data as one blob (no sector
         * offset table).  We treat the entire file as one big sector.
         */
        stream->sector_count = 1;
        stream->sector_offsets = NULL;

        /* Re-allocate sector buffer to the full file size if it's
         * larger than the default sector size. */
        if (stream->file_size > stream->sector_size) {
            free(stream->sector_buf);
            stream->sector_buf = (uint8_t *)malloc(stream->file_size);
            if (!stream->sector_buf) {
                mpq_set_error(archive, "mpq_stream_open: out of memory "
                              "for single-unit file (%u bytes)",
                              stream->file_size);
                free(stream);
                return NULL;
            }
            stream->sector_size = stream->file_size;
        }
    } else {
        /* Uncompressed, multi-sector. No offset table needed. */
        stream->sector_offsets = NULL;
    }

    return stream;
}

/* -----------------------------------------------------------------------
 * Public API: close
 * ----------------------------------------------------------------------- */

void mpq_stream_close(mpq_stream_t *stream)
{
    if (!stream)
        return;

    free(stream->sector_offsets);
    free(stream->sector_buf);
    free(stream->comp_buf);
    free(stream);
}

/* -----------------------------------------------------------------------
 * Public API: read
 * ----------------------------------------------------------------------- */

size_t mpq_stream_read(mpq_stream_t *stream, void *buf, size_t count)
{
    if (!stream || !buf)
        return (size_t)-1;

    /* Clamp to remaining bytes. */
    uint64_t remaining = 0;
    if (stream->position < (uint64_t)stream->file_size)
        remaining = (uint64_t)stream->file_size - stream->position;

    if (count > remaining)
        count = (size_t)remaining;

    if (count == 0)
        return 0;

    uint8_t *dst    = (uint8_t *)buf;
    size_t   copied = 0;

    while (copied < count) {
        /* Determine which sector the current position falls in. */
        uint32_t sector_idx  = (uint32_t)(stream->position / stream->sector_size);
        uint32_t offset_in   = (uint32_t)(stream->position % stream->sector_size);

        /* Load the sector (decompressing if necessary). */
        if (mpq_stream_load_sector(stream, sector_idx) != 0)
            return (copied > 0) ? copied : (size_t)-1;

        /* How many bytes can we copy from this sector? */
        uint32_t avail = stream->cached_sector_len - offset_in;
        size_t   want  = count - copied;
        size_t   chunk = (want < (size_t)avail) ? want : (size_t)avail;

        memcpy(dst + copied, stream->sector_buf + offset_in, chunk);

        copied           += chunk;
        stream->position += chunk;
    }

    return copied;
}

/* -----------------------------------------------------------------------
 * Public API: seek
 * ----------------------------------------------------------------------- */

int64_t mpq_stream_seek(mpq_stream_t *stream, int64_t offset, int whence)
{
    if (!stream)
        return -1;

    int64_t new_pos;

    switch (whence) {
    case SEEK_SET:
        new_pos = offset;
        break;
    case SEEK_CUR:
        new_pos = (int64_t)stream->position + offset;
        break;
    case SEEK_END:
        new_pos = (int64_t)stream->file_size + offset;
        break;
    default:
        mpq_set_error(stream->archive, "mpq_stream_seek: invalid whence %d",
                      whence);
        return -1;
    }

    if (new_pos < 0)
        new_pos = 0;

    if (new_pos > (int64_t)stream->file_size)
        new_pos = (int64_t)stream->file_size;

    stream->position = (uint64_t)new_pos;
    return new_pos;
}

/* -----------------------------------------------------------------------
 * Public API: tell / size
 * ----------------------------------------------------------------------- */

int64_t mpq_stream_tell(mpq_stream_t *stream)
{
    if (!stream)
        return -1;
    return (int64_t)stream->position;
}

size_t mpq_stream_size(mpq_stream_t *stream)
{
    if (!stream)
        return 0;
    return (size_t)stream->file_size;
}