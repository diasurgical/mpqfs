/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Archive lifecycle: open, close, file lookup, and whole-file reads.
 */

/* Feature-test macro: must appear before any system headers so that
 * fdopen() and friends are declared in strict C99 mode on POSIX hosts. */
#if !defined(_POSIX_C_SOURCE) && !defined(_WIN32) && !defined(__DJGPP__)
#  define _POSIX_C_SOURCE 200112L
#endif

#include "mpq_platform.h"
#include "mpq_archive.h"
#include "mpq_crypto.h"
#include "mpq_stream.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

/* Thread-local last-error for the public API (used when no archive context).
 * On single-threaded platforms (DOS, PS2, ...) MPQFS_THREAD_LOCAL expands to
 * nothing, giving a plain process-global — which is correct. */
static MPQFS_THREAD_LOCAL char g_last_error[256] = {0};

/* -----------------------------------------------------------------------
 * Error helpers
 * ----------------------------------------------------------------------- */

void mpq_set_error(mpqfs_archive_t *archive, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (archive) {
        vsnprintf(archive->error, sizeof(archive->error), fmt, ap);
        /* Mirror into thread-local so mpqfs_last_error() works too. */
        memcpy(g_last_error, archive->error, sizeof(g_last_error));
    } else {
        vsnprintf(g_last_error, sizeof(g_last_error), fmt, ap);
    }

    va_end(ap);
}

const char *mpqfs_last_error(void)
{
    return g_last_error[0] ? g_last_error : NULL;
}

/* -----------------------------------------------------------------------
 * Header parsing
 * ----------------------------------------------------------------------- */

/*
 * Scan for the MPQ signature.  The archive may be embedded in another
 * file (e.g. an exe stub) — the header always appears on a 512-byte
 * boundary.  We scan up to 128 MiB.
 */
static int mpq_find_header(FILE *fp, int64_t *out_offset)
{
    uint8_t buf[4];
    const int64_t max_search = 128LL * 1024 * 1024;

    for (int64_t off = 0; off < max_search; off += 512) {
        if (fseek(fp, (long)off, SEEK_SET) != 0)
            return -1;
        if (fread(buf, 1, 4, fp) != 4)
            return -1;
        if (mpqfs_read_le32(buf) == MPQ_SIGNATURE) {
            *out_offset = off;
            return 0;
        }
    }

    return -1;
}

static int mpq_read_header(FILE *fp, int64_t archive_offset,
                           mpq_header_t *hdr)
{
    uint8_t raw[MPQ_HEADER_SIZE_V1];

    if (fseek(fp, (long)archive_offset, SEEK_SET) != 0)
        return -1;
    if (fread(raw, 1, MPQ_HEADER_SIZE_V1, fp) != MPQ_HEADER_SIZE_V1)
        return -1;

    hdr->signature          = mpqfs_read_le32(raw +  0);
    hdr->header_size        = mpqfs_read_le32(raw +  4);
    hdr->archive_size       = mpqfs_read_le32(raw +  8);
    hdr->format_version     = mpqfs_read_le16(raw + 12);
    hdr->sector_size_shift  = mpqfs_read_le16(raw + 14);
    hdr->hash_table_offset  = mpqfs_read_le32(raw + 16);
    hdr->block_table_offset = mpqfs_read_le32(raw + 20);
    hdr->hash_table_count   = mpqfs_read_le32(raw + 24);
    hdr->block_table_count  = mpqfs_read_le32(raw + 28);

    if (hdr->signature != MPQ_SIGNATURE)
        return -1;

    return 0;
}

/* -----------------------------------------------------------------------
 * Table loading
 *
 * Hash and block tables are stored as arrays of little-endian uint32_t
 * values and encrypted with a known key.  The load sequence is:
 *
 *   1. Read raw bytes from disk.
 *   2. On big-endian hosts, byte-swap each uint32_t so the decryption
 *      algorithm (which operates on native uint32_t) sees the correct
 *      values.
 *   3. Decrypt the uint32_t array in-place.
 *   4. On big-endian hosts, byte-swap each uint32_t back so the struct
 *      fields are in the correct native byte order.
 *
 * On little-endian hosts steps 2 and 4 are identity operations.
 * ----------------------------------------------------------------------- */

static void mpq_fixup_le32_array(uint32_t *data, size_t count)
{
#if MPQFS_BIG_ENDIAN
    for (size_t i = 0; i < count; i++)
        data[i] = mpqfs_le32(data[i]);
#else
    MPQFS_UNUSED(data);
    MPQFS_UNUSED(count);
#endif
}

static mpq_hash_entry_t *mpq_load_hash_table(FILE *fp,
                                              int64_t archive_offset,
                                              const mpq_header_t *hdr)
{
    uint32_t count = hdr->hash_table_count;
    size_t   bytes = (size_t)count * sizeof(mpq_hash_entry_t);

    mpq_hash_entry_t *table = (mpq_hash_entry_t *)malloc(bytes);
    if (!table)
        return NULL;

    int64_t abs_offset = archive_offset + (int64_t)hdr->hash_table_offset;
    if (fseek(fp, (long)abs_offset, SEEK_SET) != 0) {
        free(table);
        return NULL;
    }
    if (fread(table, 1, bytes, fp) != bytes) {
        free(table);
        return NULL;
    }

    /* Byte-swap from LE on disk to native for decryption. */
    uint32_t dword_count = count * 4; /* 16 bytes per entry = 4 dwords */
    mpq_fixup_le32_array((uint32_t *)table, dword_count);

    /* Decrypt in-place. */
    uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    mpq_decrypt_block((uint32_t *)table, dword_count, key);

    /* On BE, the decrypted values are now in native order — which is
     * what we want for direct struct field access.  On LE they were
     * already native.  No further swap needed. */

    return table;
}

static mpq_block_entry_t *mpq_load_block_table(FILE *fp,
                                                int64_t archive_offset,
                                                const mpq_header_t *hdr)
{
    uint32_t count = hdr->block_table_count;
    size_t   bytes = (size_t)count * sizeof(mpq_block_entry_t);

    mpq_block_entry_t *table = (mpq_block_entry_t *)malloc(bytes);
    if (!table)
        return NULL;

    int64_t abs_offset = archive_offset + (int64_t)hdr->block_table_offset;
    if (fseek(fp, (long)abs_offset, SEEK_SET) != 0) {
        free(table);
        return NULL;
    }
    if (fread(table, 1, bytes, fp) != bytes) {
        free(table);
        return NULL;
    }

    uint32_t dword_count = count * 4;
    mpq_fixup_le32_array((uint32_t *)table, dword_count);

    uint32_t key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    mpq_decrypt_block((uint32_t *)table, dword_count, key);

    return table;
}

/* -----------------------------------------------------------------------
 * File lookup
 * ----------------------------------------------------------------------- */

uint32_t mpq_lookup_file(const mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return UINT32_MAX;

    uint32_t hash_count = archive->header.hash_table_count;
    if (hash_count == 0)
        return UINT32_MAX;

    uint32_t index  = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX) % hash_count;
    uint32_t name_a = mpq_hash_string(filename, MPQ_HASH_NAME_A);
    uint32_t name_b = mpq_hash_string(filename, MPQ_HASH_NAME_B);

    uint32_t start = index;

    for (;;) {
        const mpq_hash_entry_t *entry = &archive->hash_table[index];

        if (entry->block_index == MPQ_HASH_ENTRY_EMPTY) {
            /* End of probe chain — file does not exist. */
            return UINT32_MAX;
        }

        if (entry->block_index != MPQ_HASH_ENTRY_DELETED &&
            entry->hash_a == name_a &&
            entry->hash_b == name_b)
        {
            /* Match — validate block index range. */
            if (entry->block_index < archive->header.block_table_count)
                return entry->block_index;

            return UINT32_MAX;
        }

        index = (index + 1) % hash_count;
        if (index == start) {
            /* Wrapped around — not found. */
            return UINT32_MAX;
        }
    }
}

/* -----------------------------------------------------------------------
 * Internal: shared archive init after the FILE* is obtained
 * ----------------------------------------------------------------------- */

static mpqfs_archive_t *mpq_init_archive(FILE *fp, int owns_fd,
                                         const char *source_name)
{
    mpqfs_archive_t *archive = (mpqfs_archive_t *)calloc(1, sizeof(*archive));
    if (!archive) {
        fclose(fp);
        mpq_set_error(NULL, "%s: out of memory", source_name);
        return NULL;
    }

    archive->fp      = fp;
    archive->owns_fd = owns_fd;

    /* Locate the MPQ header. */
    if (mpq_find_header(fp, &archive->archive_offset) != 0) {
        mpq_set_error(archive, "%s: MPQ signature not found", source_name);
        fclose(fp);
        free(archive);
        return NULL;
    }

    /* Read & validate header. */
    if (mpq_read_header(fp, archive->archive_offset, &archive->header) != 0) {
        mpq_set_error(archive, "%s: failed to read MPQ header", source_name);
        fclose(fp);
        free(archive);
        return NULL;
    }

    if (archive->header.format_version != 0) {
        mpq_set_error(archive, "%s: unsupported format version %u "
                      "(only v1 / version 0 is supported)",
                      source_name, (unsigned)archive->header.format_version);
        fclose(fp);
        free(archive);
        return NULL;
    }

    archive->sector_size = 512u << archive->header.sector_size_shift;

    /* Load tables. */
    archive->hash_table = mpq_load_hash_table(fp, archive->archive_offset,
                                              &archive->header);
    if (!archive->hash_table) {
        mpq_set_error(archive, "%s: failed to load hash table", source_name);
        fclose(fp);
        free(archive);
        return NULL;
    }

    archive->block_table = mpq_load_block_table(fp, archive->archive_offset,
                                                &archive->header);
    if (!archive->block_table) {
        mpq_set_error(archive, "%s: failed to load block table", source_name);
        free(archive->hash_table);
        fclose(fp);
        free(archive);
        return NULL;
    }

    return archive;
}

/* -----------------------------------------------------------------------
 * Public API: open / close
 * ----------------------------------------------------------------------- */

mpqfs_archive_t *mpqfs_open(const char *path)
{
    mpq_crypto_init();

    if (!path) {
        mpq_set_error(NULL, "mpqfs_open: path is NULL");
        return NULL;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        mpq_set_error(NULL, "mpqfs_open: cannot open '%s': %s",
                      path, strerror(errno));
        return NULL;
    }

    return mpq_init_archive(fp, 1, "mpqfs_open");
}

#if MPQFS_HAS_FDOPEN

mpqfs_archive_t *mpqfs_open_fd(int fd)
{
    mpq_crypto_init();

    if (fd < 0) {
        mpq_set_error(NULL, "mpqfs_open_fd: invalid file descriptor");
        return NULL;
    }

    FILE *fp = fdopen(fd, "rb");
    if (!fp) {
        mpq_set_error(NULL, "mpqfs_open_fd: fdopen failed: %s",
                      strerror(errno));
        return NULL;
    }

    return mpq_init_archive(fp, 1, "mpqfs_open_fd");
}

#endif /* MPQFS_HAS_FDOPEN */

mpqfs_archive_t *mpqfs_open_fp(FILE *fp)
{
    mpq_crypto_init();

    if (!fp) {
        mpq_set_error(NULL, "mpqfs_open_fp: fp is NULL");
        return NULL;
    }

    return mpq_init_archive(fp, 0, "mpqfs_open_fp");
}

void mpqfs_close(mpqfs_archive_t *archive)
{
    if (!archive)
        return;

    free(archive->block_table);
    free(archive->hash_table);

    if (archive->fp && archive->owns_fd)
        fclose(archive->fp);

    free(archive);
}

/* -----------------------------------------------------------------------
 * Public API: queries
 * ----------------------------------------------------------------------- */

bool mpqfs_has_file(mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return false;

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX)
        return false;

    return (archive->block_table[bi].flags & MPQ_FILE_EXISTS) != 0;
}

size_t mpqfs_file_size(mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return 0;

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX)
        return 0;

    const mpq_block_entry_t *block = &archive->block_table[bi];
    if (!(block->flags & MPQ_FILE_EXISTS))
        return 0;

    return (size_t)block->file_size;
}

/* -----------------------------------------------------------------------
 * Public API: whole-file read
 * ----------------------------------------------------------------------- */

void *mpqfs_read_file(mpqfs_archive_t *archive, const char *filename,
                      size_t *out_size)
{
    if (out_size)
        *out_size = 0;

    if (!archive || !filename) {
        mpq_set_error(archive, "mpqfs_read_file: invalid arguments");
        return NULL;
    }

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_read_file: file '%s' not found", filename);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(archive, bi, filename);
    if (!stream)
        return NULL;  /* error already set */

    size_t total = mpq_stream_size(stream);
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        mpq_set_error(archive, "mpqfs_read_file: out of memory (%zu bytes)", total);
        mpq_stream_close(stream);
        return NULL;
    }

    size_t offset = 0;
    while (offset < total) {
        size_t n = mpq_stream_read(stream, buf + offset, total - offset);
        if (n == (size_t)-1) {
            free(buf);
            mpq_stream_close(stream);
            return NULL;
        }
        if (n == 0)
            break;  /* shouldn't happen, but guard against infinite loops */
        offset += n;
    }

    mpq_stream_close(stream);

    if (out_size)
        *out_size = offset;

    return buf;
}

/* -----------------------------------------------------------------------
 * Public API: whole-file read into caller-supplied buffer
 * ----------------------------------------------------------------------- */

size_t mpqfs_read_file_into(mpqfs_archive_t *archive, const char *filename,
                            void *buffer, size_t buffer_size)
{
    if (!archive || !filename || !buffer || buffer_size == 0) {
        mpq_set_error(archive, "mpqfs_read_file_into: invalid arguments");
        return 0;
    }

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_read_file_into: file '%s' not found",
                      filename);
        return 0;
    }

    mpq_stream_t *stream = mpq_stream_open_named(archive, bi, filename);
    if (!stream)
        return 0;  /* error already set */

    size_t total = mpq_stream_size(stream);
    if (total > buffer_size) {
        mpq_set_error(archive, "mpqfs_read_file_into: buffer too small "
                      "(%zu bytes available, %zu needed)", buffer_size, total);
        mpq_stream_close(stream);
        return 0;
    }

    uint8_t *dst = (uint8_t *)buffer;
    size_t offset = 0;
    while (offset < total) {
        size_t n = mpq_stream_read(stream, dst + offset, total - offset);
        if (n == (size_t)-1) {
            mpq_stream_close(stream);
            return 0;
        }
        if (n == 0)
            break;
        offset += n;
    }

    mpq_stream_close(stream);
    return offset;
}