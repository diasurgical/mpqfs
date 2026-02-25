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
 *
 * All lookup tables are taken verbatim from StormLib's explode.c to
 * ensure correctness.
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
 * Static lookup tables — taken directly from StormLib's explode.c
 * -------------------------------------------------------------------------- */

/* Distance position code bit lengths (DistBits) */
static const uint8_t pk_dist_bits[PK_DIST_BITS_COUNT] = {
    0x02, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
    0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08
};

/* Distance position codes (DistCode) — Shannon-Fano codes, LSB first */
static const uint8_t pk_dist_code[PK_DIST_BITS_COUNT] = {
    0x03, 0x0D, 0x05, 0x19, 0x09, 0x11, 0x01, 0x3E,
    0x1E, 0x2E, 0x0E, 0x36, 0x16, 0x26, 0x06, 0x3A,
    0x1A, 0x2A, 0x0A, 0x32, 0x12, 0x22, 0x42, 0x02,
    0x7C, 0x3C, 0x5C, 0x1C, 0x6C, 0x2C, 0x4C, 0x0C,
    0x74, 0x34, 0x54, 0x14, 0x64, 0x24, 0x44, 0x04,
    0x78, 0x38, 0x58, 0x18, 0x68, 0x28, 0x48, 0x08,
    0xF0, 0x70, 0xB0, 0x30, 0xD0, 0x50, 0x90, 0x10,
    0xE0, 0x60, 0xA0, 0x20, 0xC0, 0x40, 0x80, 0x00
};

/* Length code bit lengths (LenBits) — Shannon-Fano code widths */
static const uint8_t pk_len_bits[PK_LEN_BITS_COUNT] = {
    0x03, 0x02, 0x03, 0x03, 0x04, 0x04, 0x04, 0x05,
    0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x07, 0x07
};

/* Length codes (LenCode) — Shannon-Fano codes, LSB first */
static const uint8_t pk_len_code[PK_LEN_BITS_COUNT] = {
    0x05, 0x03, 0x01, 0x06, 0x0A, 0x02, 0x0C, 0x14,
    0x04, 0x18, 0x08, 0x30, 0x10, 0x20, 0x40, 0x00
};

/* Extra bits beyond the Shannon-Fano code for each length symbol
 * (ExLenBits).  Codes 0–7 have no extra bits; codes 8–15 have 1–8. */
static const uint8_t pk_ex_len_bits[PK_LEN_BITS_COUNT] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

/* Length base values (LenBase).  The actual repeat length is:
 *     LenBase[code] + extra_bits_value + 2
 * (The +2 accounts for the minimum match length of 2.)              */
static const uint16_t pk_len_base[PK_LEN_BITS_COUNT] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x000A, 0x000E, 0x0016, 0x0026, 0x0046, 0x0086, 0x0106
};

/* ASCII literal bit lengths (ChBitsAsc) — from StormLib */
static const uint8_t pk_ascii_bits[PK_ASCII_COUNT] = {
    0x0B, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x08, 0x07, 0x0C, 0x0C, 0x07, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0D, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x04, 0x0A, 0x08, 0x0C, 0x0A, 0x0C, 0x0A, 0x08,
    0x07, 0x07, 0x08, 0x09, 0x07, 0x06, 0x07, 0x08,
    0x07, 0x06, 0x07, 0x07, 0x07, 0x07, 0x08, 0x07,
    0x07, 0x08, 0x08, 0x0C, 0x0B, 0x07, 0x09, 0x0B,
    0x0C, 0x06, 0x07, 0x06, 0x06, 0x05, 0x07, 0x08,
    0x08, 0x06, 0x0B, 0x09, 0x06, 0x07, 0x06, 0x06,
    0x07, 0x0B, 0x06, 0x06, 0x06, 0x07, 0x09, 0x08,
    0x09, 0x09, 0x0B, 0x08, 0x0B, 0x09, 0x0C, 0x08,
    0x0C, 0x05, 0x06, 0x06, 0x06, 0x05, 0x06, 0x06,
    0x06, 0x05, 0x0B, 0x07, 0x05, 0x06, 0x05, 0x05,
    0x06, 0x0A, 0x05, 0x05, 0x05, 0x05, 0x08, 0x07,
    0x08, 0x08, 0x0A, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
    0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D, 0x0D,
    0x0D, 0x0C, 0x0D, 0x0D, 0x0D, 0x0D, 0x0C, 0x0D,
    0x0D, 0x0D, 0x0C, 0x0C, 0x0C, 0x0D, 0x0D, 0x0D,
    0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D
};

/* ASCII literal Shannon-Fano codes (ChCodeAsc) — from StormLib */
static const uint16_t pk_ascii_code[PK_ASCII_COUNT] = {
    0x0490, 0x0FE0, 0x07E0, 0x0BE0, 0x03E0, 0x0DE0, 0x05E0, 0x09E0,
    0x01E0, 0x00B8, 0x0062, 0x0EE0, 0x06E0, 0x0022, 0x0AE0, 0x02E0,
    0x0CE0, 0x04E0, 0x08E0, 0x00E0, 0x0F60, 0x0760, 0x0B60, 0x0360,
    0x0D60, 0x0560, 0x1240, 0x0960, 0x0160, 0x0E60, 0x0660, 0x0A60,
    0x000F, 0x0250, 0x0038, 0x0260, 0x0050, 0x0C60, 0x0390, 0x00D8,
    0x0042, 0x0002, 0x0058, 0x01B0, 0x007C, 0x0029, 0x003C, 0x0098,
    0x005C, 0x0009, 0x001C, 0x006C, 0x002C, 0x004C, 0x0018, 0x000C,
    0x0074, 0x00E8, 0x0068, 0x0460, 0x0090, 0x0034, 0x00B0, 0x0710,
    0x0860, 0x0031, 0x0054, 0x0011, 0x0021, 0x0017, 0x0014, 0x00A8,
    0x0028, 0x0001, 0x0310, 0x0130, 0x003E, 0x0064, 0x001E, 0x002E,
    0x0024, 0x0510, 0x000E, 0x0036, 0x0016, 0x0044, 0x0030, 0x00C8,
    0x01D0, 0x00D0, 0x0110, 0x0048, 0x0610, 0x0150, 0x0060, 0x0088,
    0x0FA0, 0x0007, 0x0026, 0x0006, 0x003A, 0x001B, 0x001A, 0x002A,
    0x000A, 0x000B, 0x0210, 0x0004, 0x0013, 0x0032, 0x0003, 0x001D,
    0x0012, 0x0190, 0x000D, 0x0015, 0x0005, 0x0019, 0x0008, 0x0078,
    0x00F0, 0x0070, 0x0290, 0x0410, 0x0010, 0x07A0, 0x0BA0, 0x03A0,
    0x0240, 0x1C40, 0x0C40, 0x1440, 0x0440, 0x1840, 0x0840, 0x1040,
    0x0040, 0x1F80, 0x0F80, 0x1780, 0x0780, 0x1B80, 0x0B80, 0x1380,
    0x0380, 0x1D80, 0x0D80, 0x1580, 0x0580, 0x1980, 0x0980, 0x1180,
    0x0180, 0x1E80, 0x0E80, 0x1680, 0x0680, 0x1A80, 0x0A80, 0x1280,
    0x0280, 0x1C80, 0x0C80, 0x1480, 0x0480, 0x1880, 0x0880, 0x1080,
    0x0080, 0x1F00, 0x0F00, 0x1700, 0x0700, 0x1B00, 0x0B00, 0x1300,
    0x0DA0, 0x05A0, 0x09A0, 0x01A0, 0x0EA0, 0x06A0, 0x0AA0, 0x02A0,
    0x0CA0, 0x04A0, 0x08A0, 0x00A0, 0x0F20, 0x0720, 0x0B20, 0x0320,
    0x0D20, 0x0520, 0x0920, 0x0120, 0x0E20, 0x0620, 0x0A20, 0x0220,
    0x0C20, 0x0420, 0x0820, 0x0020, 0x0FC0, 0x07C0, 0x0BC0, 0x03C0,
    0x0DC0, 0x05C0, 0x09C0, 0x01C0, 0x0EC0, 0x06C0, 0x0AC0, 0x02C0,
    0x0CC0, 0x04C0, 0x08C0, 0x00C0, 0x0F40, 0x0740, 0x0B40, 0x0340,
    0x0300, 0x0D40, 0x1D00, 0x0D00, 0x1500, 0x0540, 0x0500, 0x1900,
    0x0900, 0x0940, 0x1100, 0x0100, 0x1E00, 0x0E00, 0x0140, 0x1600,
    0x0600, 0x1A00, 0x0E40, 0x0640, 0x0A40, 0x0A00, 0x1200, 0x0200,
    0x1C00, 0x0C00, 0x1400, 0x0400, 0x1800, 0x0800, 0x1000, 0x0000
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

/* Decode a distance position code (6-bit base).  Returns the code index
 * [0..63] or -1 on error. */
static inline int pk_decode_dist(pk_bitstream_t *bs)
{
    if (pk_bs_fill(bs, 8) < 0)
        return -1;

    uint32_t peek = pk_bs_peek(bs, 8);

    /* Walk the distance code table looking for a match.
     * Codes are variable-length (2–8 bits) and are read LSB-first.
     * We match against the code stored in pk_dist_code[]. */
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
    /* Maximum ASCII code length is 13 bits. */
    if (pk_bs_fill(bs, 13) < 0) {
        /* Try partial — we may have enough for a shorter code. */
    }

    /* We need up to 13 bits; peek as many as we have. */
    uint32_t peek = bs->bits;

    for (int i = 0; i < PK_ASCII_COUNT; i++) {
        int nbits = pk_ascii_bits[i];
        if (nbits == 0)
            continue;
        if (bs->avail < nbits)
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
        /* If we've produced all expected output, stop.  Some compressors
         * (e.g. DevilutionX / StormLib) don't emit an end-of-stream
         * sentinel when the output exactly fills the expected size. */
        if (out_pos >= out_limit)
            break;

        /* Read one flag bit: 0 = literal, 1 = match. */
        uint32_t flag = pk_bs_read(&bs, 1);
        if (flag == (uint32_t)-1)
            break;  /* end of stream — input exhausted */

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

            /* Decode the length code index via Shannon-Fano. */
            int len_idx = pk_decode_len(&bs);
            if (len_idx < 0)
                return PK_ERR_INPUT;

            uint32_t match_len;

            /* Read extra length bits if this code has any. */
            uint32_t ex_bits = pk_ex_len_bits[len_idx];
            if (ex_bits != 0) {
                uint32_t extra = pk_bs_read(&bs, (int)ex_bits);
                if (extra == (uint32_t)-1) {
                    /* Special case: for the last length code (15) with
                     * 8 extra bits, running out of input with value 0
                     * could mean end of stream.  But if we truly can't
                     * read, it's an error for other codes. */
                    if (len_idx != 15)
                        return PK_ERR_INPUT;
                    extra = 0;
                }
                match_len = pk_len_base[len_idx] + extra + 2;
            } else {
                match_len = pk_len_base[len_idx] + 2;
            }

            /* Decode the distance position code. */
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

                /* End-of-stream sentinel: distance == 0 with length == 2
                 * is physically meaningless and terminates the stream. */
                if (dist == 0)
                    break;
            } else {
                uint32_t lo = pk_bs_read(&bs, dict_bits);
                if (lo == (uint32_t)-1)
                    return PK_ERR_INPUT;
                dist = ((uint32_t)dist_idx << dict_bits) | lo;
            }

            /* Distance is 0-based backwards from current position.
             * dist == 0 means "one byte back", etc. */
            if ((size_t)(dist + 1) > out_pos)
                return PK_ERR_INPUT;  /* distance goes before start of output */

            size_t copy_from = out_pos - dist - 1;

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
 * Convenience wrapper for sector decompression
 *
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