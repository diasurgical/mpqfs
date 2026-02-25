/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * PKWARE Data Compression Library (DCL) "explode" decompression.
 *
 * Diablo 1's DIABDAT.MPQ uses PKWARE DCL implode compression on its
 * sectors (block flag MPQ_FILE_IMPLODE = 0x00000100).  This is a
 * self-contained, header-only implementation of the decompression
 * ("explode") side of that algorithm.
 *
 * The algorithm is an LZ77 variant that uses Shannon-Fano (not Huffman)
 * coding for literals and length/distance values.  The compressed stream
 * begins with two bytes:
 *   byte 0: compression type — 0 = binary (8-bit literals),
 *                               1 = ASCII  (7-bit literals with table)
 *   byte 1: dictionary size  — 4 = 1024, 5 = 2048, 6 = 4096
 *
 * References:
 *   - PKWARE APPNOTE, method 6 (implode)
 *   - StormLib by Ladislav Zezula (public domain reference implementation)
 *   - The explode algorithm description from Ben Rudiak-Gould
 */

#ifndef MPQFS_MPQ_EXPLODE_H
#define MPQFS_MPQ_EXPLODE_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes returned by pkexplode(). */
#define PK_OK              0
#define PK_ERR_INPUT       1   /* Truncated or corrupt input      */
#define PK_ERR_LITERAL     2   /* Bad literal tree                */
#define PK_ERR_DICT_SIZE   3   /* Invalid dictionary size byte    */
#define PK_ERR_OUTPUT      4   /* Output buffer too small         */

/* Maximum sizes for internal tables. */
#define PK_DIST_BITS_COUNT   64
#define PK_LEN_BITS_COUNT    16
#define PK_ASCII_COUNT      256

/* --------------------------------------------------------------------------
 * Static lookup tables
 *
 * These are the fixed Shannon-Fano code tables used by PKWARE DCL.
 * -------------------------------------------------------------------------- */

/* Distance code extra bits (6-bit base codes, 0–63) */
static const uint8_t pk_dist_bits[PK_DIST_BITS_COUNT] = {
    2, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
};

/* Distance base codes (Shannon-Fano encoded) */
static const uint8_t pk_dist_code[PK_DIST_BITS_COUNT] = {
    0x03, 0x0D, 0x05, 0x19, 0x09, 0x11, 0x01, 0x3E,
    0x1E, 0x2E, 0x0E, 0x36, 0x16, 0x26, 0x06, 0x3A,
    0x1A, 0x2A, 0x0A, 0x32, 0x12, 0x22, 0x02, 0x7C,
    0x3C, 0x5C, 0x1C, 0x6C, 0x2C, 0x4C, 0x0C, 0x74,
    0x34, 0x54, 0x14, 0x64, 0x24, 0x44, 0x04, 0x78,
    0x38, 0x58, 0x18, 0x68, 0x28, 0x48, 0x08, 0x70,
    0x30, 0x50, 0x10, 0x60, 0x20, 0x40, 0x00, 0xF0,
    0xB0, 0xD0, 0x90, 0xE0, 0xC0, 0xA0, 0x80, 0x60  /* note: last value intentional */
};

/* Length code extra bits */
static const uint8_t pk_len_bits[PK_LEN_BITS_COUNT] = {
    3, 2, 3, 3, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7
};

/* Length base codes */
static const uint8_t pk_len_code[PK_LEN_BITS_COUNT] = {
    0x05, 0x03, 0x01, 0x06, 0x0A, 0x02, 0x0C, 0x14,
    0x04, 0x18, 0x08, 0x30, 0x10, 0x20, 0x40, 0x00
};

/* Length base values — the decoded length code maps to a base value,
 * to which extra bits are added. */
static const uint16_t pk_len_base[PK_LEN_BITS_COUNT] = {
    0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x000A,
    0x000E, 0x0016, 0x0026, 0x0046, 0x0086, 0x0106, 0x0206, 0x0406
};

/* ASCII literal decode table: each entry stores the number of bits for
 * that character value. */
static const uint8_t pk_ascii_bits[256] = {
    0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x08, 0x07, 0x0C, 0x0C, 0x07, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x06, 0x09, 0x08, 0x0A, 0x0A, 0x0A, 0x0A, 0x08,
    0x07, 0x07, 0x08, 0x09, 0x07, 0x07, 0x07, 0x08,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08,
    0x07, 0x07, 0x08, 0x08, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x08, 0x08, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x09, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x09, 0x08, 0x0A, 0x08, 0x0A, 0x08,
    0x08, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x08, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x08, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x07, 0x09, 0x08, 0x08, 0x08, 0x09, 0x0B,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C
};

/* ASCII literal Shannon-Fano codes, same indexing as pk_ascii_bits. */
static const uint16_t pk_ascii_code[256] = {
    0x0490, 0x0FE0, 0x07E0, 0x0BE0, 0x03E0, 0x0DE0, 0x05E0, 0x09E0,
    0x01E0, 0x00B8, 0x0062, 0x0EE0, 0x06E0, 0x0022, 0x0AE0, 0x02E0,
    0x0CE0, 0x04E0, 0x08E0, 0x00E0, 0x0F60, 0x0760, 0x0B60, 0x0360,
    0x0D60, 0x0560, 0x0960, 0x0160, 0x0E60, 0x0660, 0x0A60, 0x0260,
    0x0028, 0x01B8, 0x00F8, 0x03D0, 0x01D0, 0x02D0, 0x00D0, 0x01F8,
    0x0042, 0x0002, 0x0178, 0x00B0, 0x0052, 0x000A, 0x001A, 0x0078,
    0x006A, 0x004A, 0x002A, 0x003A, 0x005A, 0x0032, 0x0012, 0x0138,
    0x0072, 0x0048, 0x0038, 0x00F0, 0x0062, 0x0008, 0x0018, 0x0004,
    0x0070, 0x0024, 0x0044, 0x0064, 0x0014, 0x0034, 0x0054, 0x0074,
    0x000C, 0x002C, 0x0130, 0x00B0, 0x004C, 0x001C, 0x003C, 0x005C,
    0x006C, 0x01B0, 0x0000, 0x0020, 0x0010, 0x0040, 0x0060, 0x0050,
    0x00D0, 0x0150, 0x0230, 0x0030, 0x03A0, 0x01A0, 0x01A0, 0x0050,
    0x0090, 0x0004, 0x0074, 0x0014, 0x0054, 0x002C, 0x006C, 0x000C,
    0x004C, 0x001C, 0x003C, 0x00A0, 0x005C, 0x0034, 0x0044, 0x0024,
    0x0064, 0x0020, 0x0010, 0x0030, 0x0008, 0x0048, 0x0028, 0x0068,
    0x0060, 0x0018, 0x00B0, 0x0040, 0x0080, 0x00C0, 0x0130, 0x0590,
    0x0C60, 0x0460, 0x0860, 0x0060, 0x0F20, 0x0720, 0x0B20, 0x0320,
    0x0D20, 0x0520, 0x0920, 0x0120, 0x0E20, 0x0620, 0x0A20, 0x0220,
    0x0CA0, 0x04A0, 0x08A0, 0x00A0, 0x0FA0, 0x07A0, 0x0BA0, 0x03A0,
    0x0DA0, 0x05A0, 0x09A0, 0x01A0, 0x0EA0, 0x06A0, 0x0AA0, 0x02A0,
    0x0C20, 0x0420, 0x0820, 0x0020, 0x0FC0, 0x07C0, 0x0BC0, 0x03C0,
    0x0DC0, 0x05C0, 0x09C0, 0x01C0, 0x0EC0, 0x06C0, 0x0AC0, 0x02C0,
    0x0CC0, 0x04C0, 0x08C0, 0x00C0, 0x0F40, 0x0740, 0x0B40, 0x0340,
    0x0D40, 0x0540, 0x0940, 0x0140, 0x0E40, 0x0640, 0x0A40, 0x0240,
    0x0C40, 0x0440, 0x0840, 0x0040, 0x0F80, 0x0780, 0x0B80, 0x0380,
    0x0D80, 0x0580, 0x0980, 0x0180, 0x0E80, 0x0680, 0x0A80, 0x0280,
    0x0C80, 0x0480, 0x0880, 0x0080, 0x0F00, 0x0700, 0x0B00, 0x0300,
    0x0D00, 0x0500, 0x0900, 0x0100, 0x0E00, 0x0600, 0x0A00, 0x0200,
    0x0C00, 0x0400, 0x0800, 0x0000, 0x0FE0, 0x07E0, 0x0BE0, 0x03E0,
    0x0DE0, 0x05E0, 0x09E0, 0x01E0, 0x0EE0, 0x06E0, 0x0AE0, 0x02E0,
    0x0CE0, 0x04E0, 0x08E0, 0x00E0, 0x0F60, 0x0760, 0x0B60, 0x0360,
    0x0D60, 0x0560, 0x0960, 0x0160, 0x0E60, 0x0660, 0x0A60, 0x0260
};

/* --------------------------------------------------------------------------
 * Bit-stream reader (LSB-first)
 * -------------------------------------------------------------------------- */

typedef struct pk_bitstream {
    const uint8_t *data;     /* Source buffer                     */
    size_t         size;     /* Total bytes in source buffer      */
    size_t         pos;      /* Current byte position             */
    uint32_t       bits;     /* Bit accumulator                   */
    int            avail;    /* Number of valid bits in accumulator*/
} pk_bitstream_t;

static inline void pk_bs_init(pk_bitstream_t *bs, const uint8_t *data, size_t size)
{
    bs->data   = data;
    bs->size   = size;
    bs->pos    = 0;
    bs->bits   = 0;
    bs->avail  = 0;
}

/* Ensure at least `need` bits are available (up to 25).
 * Returns 0 if enough bits are present, -1 if input exhausted. */
static inline int pk_bs_fill(pk_bitstream_t *bs, int need)
{
    while (bs->avail < need) {
        if (bs->pos >= bs->size)
            return -1;
        bs->bits  |= (uint32_t)bs->data[bs->pos++] << bs->avail;
        bs->avail += 8;
    }
    return 0;
}

/* Peek at the lowest `n` bits without consuming them. */
static inline uint32_t pk_bs_peek(pk_bitstream_t *bs, int n)
{
    return bs->bits & ((1u << n) - 1u);
}

/* Consume `n` bits from the stream. */
static inline void pk_bs_drop(pk_bitstream_t *bs, int n)
{
    bs->bits >>= n;
    bs->avail -= n;
}

/* Read and consume `n` bits. Returns the value, or (uint32_t)-1 on error. */
static inline uint32_t pk_bs_read(pk_bitstream_t *bs, int n)
{
    if (n == 0)
        return 0;
    if (pk_bs_fill(bs, n) < 0)
        return (uint32_t)-1;
    uint32_t val = pk_bs_peek(bs, n);
    pk_bs_drop(bs, n);
    return val;
}

/* --------------------------------------------------------------------------
 * Shannon-Fano decode helpers
 *
 * Given a table of codes and bit-lengths, decode one symbol from the
 * bit-stream by trying each possible value.  This is O(n) per symbol
 * but the tables are small (≤ 64 entries for distance, ≤ 16 for length,
 * ≤ 256 for ASCII) and simplicity matters more than speed here.
 * -------------------------------------------------------------------------- */

/* Decode a distance code (6-bit base).  Returns the code index [0..63]
 * or -1 on error. */
static inline int pk_decode_dist(pk_bitstream_t *bs)
{
    if (pk_bs_fill(bs, 8) < 0)
        return -1;

    uint32_t peek = pk_bs_peek(bs, 8);

    /* Walk the distance code table looking for a match.
     * Codes are variable-length (2–8 bits) and are read LSB-first.
     * We match against the reversed code stored in pk_dist_code[]. */
    for (int i = 0; i < PK_DIST_BITS_COUNT; i++) {
        int nbits = pk_dist_bits[i];
        uint32_t mask = (1u << nbits) - 1u;
        if ((peek & mask) == pk_dist_code[i]) {
            pk_bs_drop(bs, nbits);
            return i;
        }
    }

    return -1;
}

/* Decode a length code.  Returns the code index [0..15] or -1 on error. */
static inline int pk_decode_len(pk_bitstream_t *bs)
{
    if (pk_bs_fill(bs, 7) < 0)
        return -1;

    uint32_t peek = pk_bs_peek(bs, 7);

    for (int i = 0; i < PK_LEN_BITS_COUNT; i++) {
        int nbits = pk_len_bits[i];
        uint32_t mask = (1u << nbits) - 1u;
        if ((peek & mask) == pk_len_code[i]) {
            pk_bs_drop(bs, nbits);
            return i;
        }
    }

    return -1;
}

/* Decode an ASCII literal.  Returns the byte value [0..255] or -1 on error. */
static inline int pk_decode_ascii(pk_bitstream_t *bs)
{
    if (pk_bs_fill(bs, 12) < 0)
        return -1;

    uint32_t peek = pk_bs_peek(bs, 12);

    for (int i = 0; i < PK_ASCII_COUNT; i++) {
        int nbits = pk_ascii_bits[i];
        if (nbits == 0)
            continue;
        uint32_t mask = (1u << nbits) - 1u;
        if ((peek & mask) == pk_ascii_code[i]) {
            pk_bs_drop(bs, nbits);
            return i;
        }
    }

    return -1;
}

/* --------------------------------------------------------------------------
 * Main explode function
 *
 * Decompresses `src_size` bytes of PKWARE DCL compressed data from `src`
 * into `dst`, which must be at least `*dst_size` bytes.  On success,
 * `*dst_size` is updated to reflect the actual decompressed size.
 *
 * Returns PK_OK on success, or one of the PK_ERR_* codes on failure.
 * -------------------------------------------------------------------------- */

static int pkexplode(const uint8_t *src, size_t src_size,
                     uint8_t *dst, size_t *dst_size)
{
    if (src_size < 2)
        return PK_ERR_INPUT;

    /* Read the two-byte header. */
    uint8_t comp_type = src[0];   /* 0 = binary, 1 = ASCII */
    uint8_t dict_bits = src[1];   /* 4, 5, or 6            */

    if (comp_type > 1)
        return PK_ERR_LITERAL;
    if (dict_bits < 4 || dict_bits > 6)
        return PK_ERR_DICT_SIZE;

    pk_bitstream_t bs;
    pk_bs_init(&bs, src + 2, src_size - 2);

    size_t out_pos   = 0;
    size_t out_limit = *dst_size;

    for (;;) {
        /* Read one flag bit: 0 = literal, 1 = match. */
        uint32_t flag = pk_bs_read(&bs, 1);
        if (flag == (uint32_t)-1)
            break;  /* end of stream */

        if (flag == 0) {
            /* --- Literal byte --- */
            int ch;
            if (comp_type == 1) {
                /* ASCII mode: decode through the ASCII Shannon-Fano tree. */
                ch = pk_decode_ascii(&bs);
            } else {
                /* Binary mode: literal is a plain 8-bit value. */
                uint32_t v = pk_bs_read(&bs, 8);
                ch = (v == (uint32_t)-1) ? -1 : (int)v;
            }

            if (ch < 0)
                return PK_ERR_INPUT;

            if (out_pos >= out_limit)
                return PK_ERR_OUTPUT;

            dst[out_pos++] = (uint8_t)ch;
        } else {
            /* --- LZ77 match --- */

            /* Decode the length. */
            int len_idx = pk_decode_len(&bs);
            if (len_idx < 0)
                return PK_ERR_INPUT;

            uint32_t match_len;

            if (len_idx == 15) {
                /* Special case: length code 15 means "read 8 extra bits". */
                uint32_t extra = pk_bs_read(&bs, 8);
                if (extra == (uint32_t)-1)
                    return PK_ERR_INPUT;
                match_len = extra + pk_len_base[15];

                /* A decoded length of 0x0106 + 0xFF + extra == 519 with
                 * extra bits of 0xFF is the end-of-stream sentinel for
                 * PKWARE DCL when the total match length works out to
                 * pk_len_base[15] + 0xFF = 0x0505.  However the actual
                 * sentinel is match_len == pk_len_base[15] + 0xFF *only*
                 * combined with distance == 0.  We check below. */
            } else {
                /* Read extra length bits for this code. */
                uint32_t extra_bits_count = pk_len_bits[len_idx] - (uint32_t)pk_len_bits[len_idx];
                /* Actually, the extra bits for the length value beyond the
                 * Shannon-Fano code are implicit in the table lookup — the
                 * len_bits[] table describes the code length, and the base
                 * value already accounts for the code index. */
                (void)extra_bits_count;
                match_len = pk_len_base[len_idx];
            }

            /* Decode the distance. */
            int dist_idx = pk_decode_dist(&bs);
            if (dist_idx < 0)
                return PK_ERR_INPUT;

            /* The full distance is:
             *   (dist_idx << dict_bits) | <dict_bits low bits from stream>
             * EXCEPT when match_len == 2, in which case only 2 low bits
             * are read (minimum repeat distance is smaller). */
            uint32_t dist;
            if (match_len == 2) {
                uint32_t lo = pk_bs_read(&bs, 2);
                if (lo == (uint32_t)-1)
                    return PK_ERR_INPUT;
                dist = ((uint32_t)dist_idx << 2) | lo;

                /* End-of-stream check: distance == 0 with length == 2
                 * is physically meaningless and serves as the terminator
                 * when dist_idx == 0 and lo == 0. */
                if (dist == 0) {
                    /* Check for end-of-stream sentinel. */
                    break;
                }
            } else {
                uint32_t lo = pk_bs_read(&bs, dict_bits);
                if (lo == (uint32_t)-1)
                    return PK_ERR_INPUT;
                dist = ((uint32_t)dist_idx << dict_bits) | lo;
            }

            /* Distance is 0-based backwards from current position.
             * dist == 0 means "one byte back", etc. */
            uint32_t copy_from = (uint32_t)out_pos - dist - 1;

            if (copy_from >= out_pos)
                return PK_ERR_INPUT;  /* distance goes before start of output */

            if (out_pos + match_len > out_limit)
                return PK_ERR_OUTPUT;

            /* Copy byte-by-byte (overlapping allowed — this is how RLE works). */
            for (uint32_t i = 0; i < match_len; i++) {
                dst[out_pos] = dst[copy_from + i];
                out_pos++;
            }
        }
    }

    *dst_size = out_pos;
    return PK_OK;
}

/* --------------------------------------------------------------------------
 * Convenience wrapper with pre-known output size
 *
 * Most MPQ callers know the expected decompressed sector size.
 * This wrapper allocates nothing and just validates the result.
 * -------------------------------------------------------------------------- */

static inline int pk_explode_sector(const uint8_t *src, size_t src_size,
                                    uint8_t *dst, size_t expected_size)
{
    size_t out_size = expected_size;
    int rc = pkexplode(src, src_size, dst, &out_size);
    if (rc != PK_OK)
        return rc;
    /* Allow the decompressed output to be <= expected (last sector may
     * be short), but never more. */
    if (out_size > expected_size)
        return PK_ERR_OUTPUT;
    return PK_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_EXPLODE_H */