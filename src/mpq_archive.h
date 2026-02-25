/*
 * mpqfs — Minimal MPQ v1 archive reader
 * SPDX-License-Identifier: MIT
 *
 * Internal header: on-disk MPQ v1 structures and runtime archive state.
 */

#ifndef MPQFS_MPQ_ARCHIVE_H
#define MPQFS_MPQ_ARCHIVE_H

#include "mpq_platform.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * On-disk structures (MPQ v1 / format version 0)
 * All multi-byte fields are little-endian.
 * -------------------------------------------------------------------------- */

#define MPQ_SIGNATURE       0x1A51504DU  /* "MPQ\x1a" as little-endian uint32 */
#define MPQ_HEADER_SIZE_V1  32

/* Sentinel values in the hash table */
#define MPQ_HASH_ENTRY_EMPTY   0xFFFFFFFFU
#define MPQ_HASH_ENTRY_DELETED 0xFFFFFFFEU

/* Block table flags */
#define MPQ_FILE_IMPLODE       0x00000100U  /* PKWARE DCL implode             */
#define MPQ_FILE_COMPRESS      0x00000200U  /* Multi-method compression       */
#define MPQ_FILE_ENCRYPTED     0x00010000U  /* File is encrypted              */
#define MPQ_FILE_FIX_KEY       0x00020000U  /* Encryption key adjusted by ofs */
#define MPQ_FILE_SINGLE_UNIT   0x01000000U  /* File stored as single unit     */
#define MPQ_FILE_EXISTS        0x80000000U  /* Block table entry is in use    */

/* Compression sub-type IDs (first byte of a compressed sector when
 * MPQ_FILE_COMPRESS is set).  Diablo 1 only uses PKWARE implode via the
 * MPQ_FILE_IMPLODE flag, but we list the byte IDs here for completeness. */
#define MPQ_COMP_HUFFMAN       0x01U
#define MPQ_COMP_ZLIB          0x02U
#define MPQ_COMP_PKWARE        0x08U
#define MPQ_COMP_BZIP2         0x10U
#define MPQ_COMP_ADPCM_MONO   0x40U
#define MPQ_COMP_ADPCM_STEREO 0x80U

/* --------------------------------------------------------------------------
 * On-disk structure definitions
 *
 * These structs are packed to match the binary layout on disk.  The header
 * is parsed field-by-field from a raw byte buffer (via mpqfs_read_le*),
 * but the hash and block tables are decrypted in-place as uint32_t arrays
 * and then accessed through these structs, so their layout MUST match the
 * on-disk format exactly.
 * -------------------------------------------------------------------------- */

MPQFS_PACK_BEGIN

typedef struct mpq_header {
    uint32_t signature;          /* MPQ_SIGNATURE                              */
    uint32_t header_size;        /* 0x20 for v1                                */
    uint32_t archive_size;       /* Total archive size in bytes                */
    uint16_t format_version;     /* 0 = v1                                     */
    uint16_t sector_size_shift;  /* Sector size = 512 << sector_size_shift     */
    uint32_t hash_table_offset;  /* Offset of hash table relative to archive   */
    uint32_t block_table_offset; /* Offset of block table relative to archive  */
    uint32_t hash_table_count;   /* Number of entries in the hash table        */
    uint32_t block_table_count;  /* Number of entries in the block table       */
} MPQFS_PACKED mpq_header_t;

typedef struct mpq_hash_entry {
    uint32_t hash_a;             /* First name hash                            */
    uint32_t hash_b;             /* Second name hash                           */
    uint16_t locale;             /* File language (0 = neutral)                */
    uint8_t  platform;           /* Platform (0 = default)                     */
    uint8_t  flags;              /* Entry flags (0 in practice)                */
    uint32_t block_index;        /* Index into the block table, or sentinel    */
} MPQFS_PACKED mpq_hash_entry_t;

typedef struct mpq_block_entry {
    uint32_t offset;             /* Offset of file data, relative to archive   */
    uint32_t compressed_size;    /* Compressed size (on disk)                   */
    uint32_t file_size;          /* Uncompressed size                          */
    uint32_t flags;              /* MPQ_FILE_* flags                           */
} MPQFS_PACKED mpq_block_entry_t;

MPQFS_PACK_END

/* Compile-time layout verification — if any of these fire, the struct
 * packing is wrong for this compiler/platform and the table decryption
 * will produce garbage. */
MPQFS_STATIC_ASSERT(sizeof(mpq_header_t)      == 32, "mpq_header_t must be 32 bytes");
MPQFS_STATIC_ASSERT(sizeof(mpq_hash_entry_t)  == 16, "mpq_hash_entry_t must be 16 bytes");
MPQFS_STATIC_ASSERT(sizeof(mpq_block_entry_t) == 16, "mpq_block_entry_t must be 16 bytes");

/* --------------------------------------------------------------------------
 * Runtime archive state
 * -------------------------------------------------------------------------- */

typedef struct mpqfs_archive {
    FILE              *fp;               /* Underlying file handle             */
    int                owns_fd;          /* Non-zero if we should fclose(fp)   */

    int64_t            archive_offset;   /* Byte offset of MPQ header in file  */
    mpq_header_t       header;           /* Parsed archive header              */
    uint32_t           sector_size;      /* Computed: 512 << sector_size_shift */

    mpq_hash_entry_t  *hash_table;       /* Decrypted hash table (heap alloc)  */
    mpq_block_entry_t *block_table;      /* Decrypted block table (heap alloc) */

    char               error[256];       /* Last error message                 */
} mpqfs_archive_t;

/* --------------------------------------------------------------------------
 * Internal helpers (implemented in mpq_archive.c)
 * -------------------------------------------------------------------------- */

/*
 * Look up a filename in the archive's hash table.
 * Returns the block_index on success, or UINT32_MAX if not found.
 */
uint32_t mpq_lookup_file(const mpqfs_archive_t *archive, const char *filename);

/*
 * Set the archive's error string (printf-style).
 */
void mpq_set_error(mpqfs_archive_t *archive, const char *fmt, ...)
    MPQFS_PRINTF_ATTR(2, 3);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_ARCHIVE_H */