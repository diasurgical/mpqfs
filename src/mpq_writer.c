/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * MPQ v1 writer: creates archives in the basic style used by the
 * original Diablo 1 for its save-game files.
 *
 * The produced archive layout is:
 *
 *   Offset 0x0000:  MPQ Header (32 bytes)
 *   Offset 0x0020:  File data (concatenated, uncompressed, no encryption)
 *   Offset varies:   Hash table (encrypted with standard key)
 *   Offset varies:   Block table (encrypted with standard key)
 *
 * All files are stored uncompressed and without file-level encryption.
 * Hash and block tables are encrypted with the standard MPQ keys
 * "(hash table)" and "(block table)" respectively, exactly as the
 * original game does.
 */

/* Feature-test macro: must appear before any system headers so that
 * fdopen() and friends are declared in strict C99 mode on POSIX hosts. */
#if !defined(_POSIX_C_SOURCE) && !defined(_WIN32) && !defined(__DJGPP__)
#  define _POSIX_C_SOURCE 200112L
#endif

#include "mpq_platform.h"
#include "mpq_writer.h"
#include "mpq_crypto.h"
#include "mpq_archive.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

/* -----------------------------------------------------------------------
 * Error helpers
 * ----------------------------------------------------------------------- */

/* Defined in mpq_archive.c — we use it to mirror errors to the
 * thread-local g_last_error. */
extern void mpq_set_error(mpqfs_archive_t *archive, const char *fmt, ...);

void mpq_writer_set_error(mpqfs_writer_t *writer, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (writer) {
        vsnprintf(writer->error, sizeof(writer->error), fmt, ap);
    }

    va_end(ap);

    /* Also mirror into the thread-local last-error so
     * mpqfs_last_error() picks it up. */
    va_start(ap, fmt);
    /* We can't easily call mpq_set_error with a va_list, so we
     * just format directly into the writer and then copy via
     * mpq_set_error with the pre-formatted string. */
    va_end(ap);

    if (writer) {
        mpq_set_error(NULL, "%s", writer->error);
    }
}

/* -----------------------------------------------------------------------
 * Internal: round up to the next power of two (minimum 1)
 * ----------------------------------------------------------------------- */

static uint32_t mpq_round_up_pow2(uint32_t v)
{
    if (v == 0)
        return 1;

    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

/* -----------------------------------------------------------------------
 * Internal: duplicate a string (C99 doesn't have strdup portably)
 * ----------------------------------------------------------------------- */

static char *mpq_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *dup = (char *)malloc(len);
    if (dup)
        memcpy(dup, s, len);
    return dup;
}

/* -----------------------------------------------------------------------
 * Internal: shared writer init after the FILE* is obtained
 * ----------------------------------------------------------------------- */

static mpqfs_writer_t *mpq_writer_init(FILE *fp, int owns_fd,
                                       uint32_t hash_table_size,
                                       const char *source_name)
{
    mpqfs_writer_t *writer = (mpqfs_writer_t *)calloc(1, sizeof(*writer));
    if (!writer) {
        mpq_set_error(NULL, "%s: out of memory", source_name);
        if (owns_fd && fp)
            fclose(fp);
        return NULL;
    }

    writer->fp      = fp;
    writer->owns_fd = owns_fd;

    /* Ensure hash_table_size is at least 4 and a power of 2. */
    if (hash_table_size < 4)
        hash_table_size = 4;
    writer->hash_table_size = mpq_round_up_pow2(hash_table_size);

    /* Default sector size shift of 3: 512 << 3 = 4096 bytes per sector.
     * This matches Diablo 1's typical settings. */
    writer->sector_size_shift = 3;

    /* Pre-allocate file list. */
    writer->file_capacity = MPQFS_WRITER_INITIAL_CAPACITY;
    writer->file_count    = 0;
    writer->files = (mpqfs_writer_file_t *)calloc(writer->file_capacity,
                                                  sizeof(mpqfs_writer_file_t));
    if (!writer->files) {
        mpq_writer_set_error(writer, "%s: out of memory for file list",
                             source_name);
        if (owns_fd && fp)
            fclose(fp);
        free(writer);
        return NULL;
    }

    return writer;
}

/* -----------------------------------------------------------------------
 * Public API: create
 * ----------------------------------------------------------------------- */

mpqfs_writer_t *mpqfs_writer_create(const char *path,
                                    uint32_t hash_table_size)
{
    mpq_crypto_init();

    if (!path) {
        mpq_set_error(NULL, "mpqfs_writer_create: path is NULL");
        return NULL;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        mpq_set_error(NULL, "mpqfs_writer_create: cannot open '%s': %s",
                      path, strerror(errno));
        return NULL;
    }

    return mpq_writer_init(fp, 1, hash_table_size, "mpqfs_writer_create");
}

mpqfs_writer_t *mpqfs_writer_create_fp(FILE *fp, uint32_t hash_table_size)
{
    mpq_crypto_init();

    if (!fp) {
        mpq_set_error(NULL, "mpqfs_writer_create_fp: fp is NULL");
        return NULL;
    }

    return mpq_writer_init(fp, 0, hash_table_size, "mpqfs_writer_create_fp");
}

#if MPQFS_HAS_FDOPEN

mpqfs_writer_t *mpqfs_writer_create_fd(int fd, uint32_t hash_table_size)
{
    mpq_crypto_init();

    if (fd < 0) {
        mpq_set_error(NULL, "mpqfs_writer_create_fd: invalid file descriptor");
        return NULL;
    }

    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        mpq_set_error(NULL, "mpqfs_writer_create_fd: fdopen failed: %s",
                      strerror(errno));
        return NULL;
    }

    return mpq_writer_init(fp, 1, hash_table_size, "mpqfs_writer_create_fd");
}

#endif /* MPQFS_HAS_FDOPEN */

/* -----------------------------------------------------------------------
 * Public API: add file
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_add_file(mpqfs_writer_t *writer, const char *filename,
                           const void *data, size_t size)
{
    if (!writer || !filename) {
        if (writer)
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_add_file: invalid arguments");
        else
            mpq_set_error(NULL, "mpqfs_writer_add_file: writer is NULL");
        return false;
    }

    if (!data && size > 0) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_add_file: data is NULL with "
                             "non-zero size");
        return false;
    }

    /* Check that we haven't exceeded the hash table capacity.
     * We need at least one empty slot for the hash table probe chain
     * to terminate, so limit to (hash_table_size - 1) files. */
    if (writer->file_count >= writer->hash_table_size - 1) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_add_file: hash table full "
                             "(%u files, table size %u)",
                             writer->file_count, writer->hash_table_size);
        return false;
    }

    /* Grow the files array if needed. */
    if (writer->file_count >= writer->file_capacity) {
        uint32_t new_cap = writer->file_capacity * 2;
        mpqfs_writer_file_t *new_files =
            (mpqfs_writer_file_t *)realloc(writer->files,
                                           new_cap * sizeof(mpqfs_writer_file_t));
        if (!new_files) {
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_add_file: out of memory");
            return false;
        }
        /* Zero out the newly allocated portion. */
        memset(new_files + writer->file_capacity, 0,
               (new_cap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
        writer->files         = new_files;
        writer->file_capacity = new_cap;
    }

    /* Make owned copies of the filename and data. */
    char *name_copy = mpq_strdup(filename);
    if (!name_copy) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_add_file: out of memory for name");
        return false;
    }

    uint8_t *data_copy = NULL;
    if (size > 0) {
        data_copy = (uint8_t *)malloc(size);
        if (!data_copy) {
            free(name_copy);
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_add_file: out of memory for "
                                 "data (%zu bytes)", size);
            return false;
        }
        memcpy(data_copy, data, size);
    }

    mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
    entry->filename = name_copy;
    entry->data     = data_copy;
    entry->size     = (uint32_t)size;

    writer->file_count++;
    return true;
}

/* -----------------------------------------------------------------------
 * Internal: write raw bytes at the current file position
 * ----------------------------------------------------------------------- */

static int mpq_raw_write(FILE *fp, const void *buf, size_t count)
{
    if (count == 0)
        return 0;
    if (fwrite(buf, 1, count, fp) != count)
        return -1;
    return 0;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the hash table
 *
 * Returns a heap-allocated buffer of (hash_table_size * 16) bytes
 * containing the encrypted hash table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *mpq_build_hash_table(mpqfs_writer_t *writer)
{
    uint32_t count = writer->hash_table_size;
    size_t   dword_count = (size_t)count * 4;  /* 16 bytes = 4 dwords per entry */
    size_t   total_bytes = dword_count * sizeof(uint32_t);

    uint32_t *table = (uint32_t *)malloc(total_bytes);
    if (!table)
        return NULL;

    /* Initialise all entries to "empty" (0xFFFFFFFF for all fields). */
    memset(table, 0xFF, total_bytes);

    /* Insert each file. */
    for (uint32_t f = 0; f < writer->file_count; f++) {
        const char *filename = writer->files[f].filename;

        uint32_t bucket = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX) % count;
        uint32_t name_a = mpq_hash_string(filename, MPQ_HASH_NAME_A);
        uint32_t name_b = mpq_hash_string(filename, MPQ_HASH_NAME_B);

        /* Linear probe to find an empty slot. */
        uint32_t idx = bucket;
        for (;;) {
            uint32_t base = idx * 4;
            if (table[base + 3] == MPQ_HASH_ENTRY_EMPTY ||
                table[base + 3] == MPQ_HASH_ENTRY_DELETED) {
                /* Found an empty slot — fill it in. */
                table[base + 0] = name_a;       /* hash_a   */
                table[base + 1] = name_b;       /* hash_b   */
                table[base + 2] = 0x00000000;   /* locale=0, platform=0 */
                table[base + 3] = f;            /* block_index = file index */
                break;
            }
            idx = (idx + 1) % count;
            /* We already checked capacity in add_file, so this can't loop forever. */
        }
    }

    /* Encrypt the hash table in-place. */
    uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(table, dword_count, key);

    return table;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the block table
 *
 * |file_offsets| is an array of file_count offsets (relative to the
 * archive start) where each file's data was written.
 *
 * Returns a heap-allocated buffer of (file_count * 16) bytes
 * containing the encrypted block table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *mpq_build_block_table(mpqfs_writer_t *writer,
                                       const uint32_t *file_offsets)
{
    uint32_t count = writer->file_count;
    if (count == 0)
        return NULL;

    size_t   dword_count = (size_t)count * 4;
    size_t   total_bytes = dword_count * sizeof(uint32_t);

    uint32_t *table = (uint32_t *)malloc(total_bytes);
    if (!table)
        return NULL;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t base = i * 4;
        uint32_t file_size = writer->files[i].size;

        table[base + 0] = file_offsets[i];  /* offset (relative to archive start) */
        table[base + 1] = file_size;        /* compressed_size = file_size (uncompressed) */
        table[base + 2] = file_size;        /* file_size */
        table[base + 3] = MPQ_FILE_EXISTS;  /* flags: only MPQ_FILE_EXISTS */
    }

    /* Encrypt the block table in-place. */
    uint32_t key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(table, dword_count, key);

    return table;
}

/* -----------------------------------------------------------------------
 * Public API: close (finalize and write the archive)
 *
 * The archive is laid out as:
 *
 *   Offset 0x0000:  MPQ Header       (32 bytes)
 *   Offset 0x0020:  File 0 data      (files[0].size bytes)
 *                    File 1 data      (files[1].size bytes)
 *                    ...
 *   Offset varies:  Hash table       (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  Block table      (file_count * 16 bytes, encrypted)
 *
 * The header is written last (seeking back to offset 0) so that all
 * sizes and offsets are known.
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_close(mpqfs_writer_t *writer)
{
    if (!writer) {
        mpq_set_error(NULL, "mpqfs_writer_close: writer is NULL");
        return false;
    }

    FILE *fp = writer->fp;
    bool success = true;

    if (!fp) {
        mpq_writer_set_error(writer, "mpqfs_writer_close: no file handle");
        success = false;
        goto cleanup;
    }

    /* ---- Phase 1: compute layout ---- */

    uint32_t header_size = MPQ_HEADER_SIZE_V1;  /* 32 */
    uint32_t hash_table_size  = writer->hash_table_size;
    uint32_t block_table_size = writer->file_count;

    uint32_t hash_table_bytes  = hash_table_size  * 16;
    uint32_t block_table_bytes = block_table_size * 16;

    /* Compute file data offsets (relative to archive start = 0). */
    uint32_t *file_offsets = NULL;
    if (writer->file_count > 0) {
        file_offsets = (uint32_t *)malloc(writer->file_count * sizeof(uint32_t));
        if (!file_offsets) {
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_close: out of memory");
            success = false;
            goto cleanup;
        }
    }

    uint32_t data_cursor = header_size;
    for (uint32_t i = 0; i < writer->file_count; i++) {
        file_offsets[i] = data_cursor;
        data_cursor += writer->files[i].size;
    }

    uint32_t hash_table_offset  = data_cursor;
    uint32_t block_table_offset = hash_table_offset + hash_table_bytes;
    uint32_t archive_size       = block_table_offset + block_table_bytes;

    /* ---- Phase 2: build encrypted tables ---- */

    uint32_t *hash_table = mpq_build_hash_table(writer);
    if (!hash_table) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_close: failed to build hash table");
        free(file_offsets);
        success = false;
        goto cleanup;
    }

    uint32_t *block_table = NULL;
    if (writer->file_count > 0) {
        block_table = mpq_build_block_table(writer, file_offsets);
        if (!block_table) {
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_close: failed to build block table");
            free(hash_table);
            free(file_offsets);
            success = false;
            goto cleanup;
        }
    }

    free(file_offsets);
    file_offsets = NULL;

    /* ---- Phase 3: write the archive ---- */

    /* Seek to the beginning. */
    if (fseek(fp, 0, SEEK_SET) != 0) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_close: seek failed: %s",
                             strerror(errno));
        free(hash_table);
        free(block_table);
        success = false;
        goto cleanup;
    }

    /* Write the MPQ header. */
    {
        uint8_t hdr[MPQ_HEADER_SIZE_V1];
        memset(hdr, 0, sizeof(hdr));

        mpqfs_write_le32(hdr +  0, MPQ_SIGNATURE);
        mpqfs_write_le32(hdr +  4, header_size);
        mpqfs_write_le32(hdr +  8, archive_size);
        mpqfs_write_le16(hdr + 12, 0);                          /* format_version = 0 (v1) */
        mpqfs_write_le16(hdr + 14, writer->sector_size_shift);  /* sector_size_shift */
        mpqfs_write_le32(hdr + 16, hash_table_offset);
        mpqfs_write_le32(hdr + 20, block_table_offset);
        mpqfs_write_le32(hdr + 24, hash_table_size);
        mpqfs_write_le32(hdr + 28, block_table_size);

        if (mpq_raw_write(fp, hdr, sizeof(hdr)) != 0) {
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_close: failed to write header");
            free(hash_table);
            free(block_table);
            success = false;
            goto cleanup;
        }
    }

    /* Write file data. */
    for (uint32_t i = 0; i < writer->file_count; i++) {
        if (writer->files[i].size > 0) {
            if (mpq_raw_write(fp, writer->files[i].data,
                              writer->files[i].size) != 0) {
                mpq_writer_set_error(writer,
                                     "mpqfs_writer_close: failed to write "
                                     "file data for '%s'",
                                     writer->files[i].filename);
                free(hash_table);
                free(block_table);
                success = false;
                goto cleanup;
            }
        }
    }

    /* Write the hash table (already encrypted). */
    if (mpq_raw_write(fp, hash_table, hash_table_bytes) != 0) {
        mpq_writer_set_error(writer,
                             "mpqfs_writer_close: failed to write hash table");
        free(hash_table);
        free(block_table);
        success = false;
        goto cleanup;
    }
    free(hash_table);

    /* Write the block table (already encrypted). */
    if (block_table_bytes > 0) {
        if (mpq_raw_write(fp, block_table, block_table_bytes) != 0) {
            mpq_writer_set_error(writer,
                                 "mpqfs_writer_close: failed to write "
                                 "block table");
            free(block_table);
            success = false;
            goto cleanup;
        }
    }
    free(block_table);

    /* Flush to ensure everything is on disk. */
    fflush(fp);

cleanup:
    /* Free all file entries. */
    for (uint32_t i = 0; i < writer->file_count; i++) {
        free(writer->files[i].filename);
        free(writer->files[i].data);
    }
    free(writer->files);

    /* Close the file if we own it. */
    if (writer->fp && writer->owns_fd)
        fclose(writer->fp);

    free(writer);
    return success;
}

/* -----------------------------------------------------------------------
 * Public API: discard (close without writing)
 * ----------------------------------------------------------------------- */

void mpqfs_writer_discard(mpqfs_writer_t *writer)
{
    if (!writer)
        return;

    /* Free all file entries. */
    for (uint32_t i = 0; i < writer->file_count; i++) {
        free(writer->files[i].filename);
        free(writer->files[i].data);
    }
    free(writer->files);

    /* Close the file if we own it. */
    if (writer->fp && writer->owns_fd)
        fclose(writer->fp);

    free(writer);
}