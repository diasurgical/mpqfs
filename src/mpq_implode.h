/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Header-only PKWARE Data Compression Library (DCL) implode compressor.
 *
 * This is the compression counterpart to mpq_explode.h.  It produces
 * output in the same format that pk_explode_sector() / pkexplode()
 * can decompress.
 *
 * The compressor uses:
 *   - Binary mode (comp_type = 0): literals are 8-bit raw values
 *   - Dictionary size selectable: 1024 (bits=4), 2048 (bits=5), 4096 (bits=6)
 *   - LZ77 sliding-window matching with Shannon-Fano coded lengths/distances
 *   - End-of-stream sentinel: match with length=2, distance=0
 *
 * This implementation is designed for small buffers (MPQ sectors, typically
 * 4096 bytes) and favours simplicity and correctness over speed.
 *
 * Usage:
 *
 *   uint8_t src[4096] = { ... };
 *   uint8_t dst[8192];
 *   size_t  dst_size = sizeof(dst);
 *
 *   int rc = pk_implode_sector(src, 4096, dst, &dst_size, 6);
 *   if (rc == PK_OK) {
 *       // dst contains dst_size bytes of compressed data
 *   }
 */

#ifndef MPQFS_MPQ_IMPLODE_H
#define MPQFS_MPQ_IMPLODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* We share the error codes and table constants from the explode header. */
#include "mpq_explode.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Bit-writer: accumulates bits LSB-first into an output buffer
 * -------------------------------------------------------------------------- */

typedef struct pk_bitwriter {
    uint8_t *data;       /* Output buffer                      */
    size_t   capacity;   /* Total bytes available in buffer     */
    size_t   pos;        /* Current byte position               */
    uint32_t bits;       /* Bit accumulator                     */
    int      avail;      /* Number of valid bits in accumulator */
} pk_bitwriter_t;

static inline void pk_bw_init(pk_bitwriter_t *bw, uint8_t *data, size_t capacity)
{
    bw->data     = data;
    bw->capacity = capacity;
    bw->pos      = 0;
    bw->bits     = 0;
    bw->avail    = 0;
}

/* Flush complete bytes from the bit accumulator to the output buffer.
 * Returns 0 on success, -1 if the output buffer is full. */
static inline int pk_bw_flush_bytes(pk_bitwriter_t *bw)
{
    while (bw->avail >= 8) {
        if (bw->pos >= bw->capacity)
            return -1;
        bw->data[bw->pos++] = (uint8_t)(bw->bits & 0xFF);
        bw->bits >>= 8;
        bw->avail -= 8;
    }
    return 0;
}

/* Write `nbits` bits (from the LSB of `value`) to the output.
 * Returns 0 on success, -1 on overflow. */
static inline int pk_bw_write(pk_bitwriter_t *bw, int nbits, uint32_t value)
{
    bw->bits  |= (value & ((1u << nbits) - 1u)) << bw->avail;
    bw->avail += nbits;
    return pk_bw_flush_bytes(bw);
}

/* Finalise: flush any remaining partial byte (zero-padded). */
static inline int pk_bw_finish(pk_bitwriter_t *bw)
{
    if (bw->avail > 0) {
        if (bw->pos >= bw->capacity)
            return -1;
        bw->data[bw->pos++] = (uint8_t)(bw->bits & 0xFF);
        bw->bits  = 0;
        bw->avail = 0;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Encoding tables (derived from the decoding tables in mpq_explode.h)
 *
 * For each length index i (0..15):
 *   pk_len_bits[i]    = number of bits in the Shannon-Fano code
 *   pk_len_code[i]    = the code value (LSB-first)
 *   pk_ex_len_bits[i] = number of extra bits after the code
 *   pk_len_base[i]    = base length value (add extra bits + 2 for total)
 *
 * For each distance index i (0..63):
 *   pk_dist_bits[i]   = number of bits in the Shannon-Fano code
 *   pk_dist_code[i]   = the code value (LSB-first)
 *
 * These tables are already defined in mpq_explode.h, so we reuse them
 * directly.
 * -------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
 * Length encoding
 *
 * Given a match length (>= 2), find the length code index that covers it,
 * then output the Shannon-Fano code + extra bits.
 * -------------------------------------------------------------------------- */

/* Find the length code index for a given match length (match_len >= 2).
 * The actual encoded length value is (match_len - 2), which maps into
 * the pk_len_base[] table. */
static inline int pk_encode_length_index(uint32_t match_len)
{
    uint32_t val = match_len - 2;

    /* Walk the table backwards to find the right bucket. */
    for (int i = PK_LEN_BITS_COUNT - 1; i >= 0; i--) {
        if (val >= pk_len_base[i])
            return i;
    }
    return 0;
}

static inline int pk_write_length(pk_bitwriter_t *bw, uint32_t match_len)
{
    int idx = pk_encode_length_index(match_len);

    /* Write the Shannon-Fano code for this length bucket. */
    if (pk_bw_write(bw, pk_len_bits[idx], pk_len_code[idx]) != 0)
        return -1;

    /* Write extra bits if any. */
    uint32_t ex = pk_ex_len_bits[idx];
    if (ex > 0) {
        uint32_t extra_val = (match_len - 2) - pk_len_base[idx];
        if (pk_bw_write(bw, (int)ex, extra_val) != 0)
            return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Distance encoding
 *
 * The distance is split into:
 *   dist_idx = distance >> dict_bits   (or distance >> 2 for len==2)
 *   low_bits = distance & mask
 *
 * dist_idx is encoded with Shannon-Fano (pk_dist_code/pk_dist_bits),
 * then the low bits are written raw.
 * -------------------------------------------------------------------------- */

static inline int pk_write_distance(pk_bitwriter_t *bw, uint32_t distance,
                                    uint32_t match_len, int dict_bits)
{
    uint32_t dist_idx;
    uint32_t lo;
    int lo_bits;

    if (match_len == 2) {
        dist_idx = distance >> 2;
        lo       = distance & 3;
        lo_bits  = 2;
    } else {
        dist_idx = distance >> dict_bits;
        lo       = distance & ((1u << dict_bits) - 1u);
        lo_bits  = dict_bits;
    }

    if (dist_idx >= PK_DIST_BITS_COUNT)
        return -1;  /* distance too large for the encoding */

    /* Write the Shannon-Fano code for the distance index. */
    if (pk_bw_write(bw, pk_dist_bits[dist_idx], pk_dist_code[dist_idx]) != 0)
        return -1;

    /* Write the low bits. */
    if (pk_bw_write(bw, lo_bits, lo) != 0)
        return -1;

    return 0;
}

/* --------------------------------------------------------------------------
 * LZ77 match finder: simple sliding-window search
 *
 * Searches backward in the output for the longest match of the current
 * position.  The dictionary window size is (1 << dict_bits) bytes.
 *
 * For sectors up to 4096 bytes this is fast enough; a hash-based approach
 * would be needed for larger buffers.
 * -------------------------------------------------------------------------- */

#define PK_MIN_MATCH   2
#define PK_MAX_MATCH   (0x106 + 2)  /* 0x204 = 516 bytes, matching StormLib */

static inline uint32_t pk_find_match(const uint8_t *data, size_t data_size,
                                     size_t pos, int dict_bits,
                                     uint32_t *out_distance)
{
    uint32_t dict_size = 1u << dict_bits;
    uint32_t best_len  = 0;
    uint32_t best_dist = 0;

    /* How far back can we look? */
    size_t search_start = (pos > dict_size) ? (pos - dict_size) : 0;

    /* How many bytes remain to match against? */
    size_t remaining = data_size - pos;
    uint32_t max_len = (remaining < PK_MAX_MATCH) ? (uint32_t)remaining : PK_MAX_MATCH;

    if (max_len < PK_MIN_MATCH)
        return 0;

    const uint8_t *cur = data + pos;

    for (size_t back = search_start; back < pos; back++) {
        const uint8_t *candidate = data + back;

        /* Quick first-byte check. */
        if (candidate[0] != cur[0])
            continue;

        /* Count matching bytes. */
        uint32_t len = 0;
        while (len < max_len && candidate[len] == cur[len])
            len++;

        if (len >= PK_MIN_MATCH && len > best_len) {
            best_len  = len;
            /* Distance is 0-based: 0 means "1 byte back". */
            best_dist = (uint32_t)(pos - back - 1);

            if (best_len >= max_len)
                break;  /* can't do better */
        }
    }

    /* A 2-byte match at distance >= 256 isn't worth encoding (the distance
     * encoding would take more space than just emitting two literals). */
    if (best_len == 2 && best_dist >= 0x100)
        return 0;

    /* For len==2 matches, the maximum distance encodable with 2 low bits
     * and 6-bit dist_idx is (63 << 2) | 3 = 255.  Handled by the check
     * above since best_dist >= 0x100 is rejected. */

    *out_distance = best_dist;
    return best_len;
}

/* --------------------------------------------------------------------------
 * Main implode function
 *
 * Compresses `src_size` bytes from `src` into `dst`.
 * `*dst_size` must be set to the capacity of `dst` on entry; on success
 * it is updated to the actual compressed size.
 *
 * `dict_bits` must be 4 (1024), 5 (2048), or 6 (4096).
 *
 * Returns PK_OK on success, or PK_ERR_OUTPUT if the output buffer is
 * too small (in which case the data should be stored uncompressed).
 * -------------------------------------------------------------------------- */

static int pkimplode(const uint8_t *src, size_t src_size,
                     uint8_t *dst, size_t *dst_size,
                     int dict_bits)
{
    if (dict_bits < 4 || dict_bits > 6)
        return PK_ERR_DICT_SIZE;

    pk_bitwriter_t bw;
    pk_bw_init(&bw, dst, *dst_size);

    /* Write the 2-byte header. */
    if (bw.capacity < 2)
        return PK_ERR_OUTPUT;
    dst[0] = 0;           /* comp_type = binary */
    dst[1] = (uint8_t)dict_bits;
    bw.pos = 2;

    /* Compress the input data. */
    size_t pos = 0;
    while (pos < src_size) {
        uint32_t distance = 0;
        uint32_t match_len = pk_find_match(src, src_size, pos, dict_bits,
                                           &distance);

        if (match_len >= PK_MIN_MATCH) {
            /* Output a match: flag bit = 1. */
            if (pk_bw_write(&bw, 1, 1) != 0)
                return PK_ERR_OUTPUT;

            if (pk_write_length(&bw, match_len) != 0)
                return PK_ERR_OUTPUT;

            if (pk_write_distance(&bw, distance, match_len, dict_bits) != 0)
                return PK_ERR_OUTPUT;

            pos += match_len;
        } else {
            /* Output a literal: flag bit = 0, then 8-bit value. */
            if (pk_bw_write(&bw, 1, 0) != 0)
                return PK_ERR_OUTPUT;
            if (pk_bw_write(&bw, 8, src[pos]) != 0)
                return PK_ERR_OUTPUT;
            pos++;
        }
    }

    /* Write end-of-stream sentinel: match with length=2, distance=0.
     *
     * Encoding:
     *   flag = 1                                       (1 bit)
     *   length code for index 0 (base=0, len=0+2=2)    (pk_len_bits[0] bits)
     *   distance index for (0 >> 2) = 0                (pk_dist_bits[0] bits)
     *   distance low 2 bits = 0                        (2 bits)
     */
    if (pk_bw_write(&bw, 1, 1) != 0)       /* flag = match */
        return PK_ERR_OUTPUT;
    if (pk_bw_write(&bw, pk_len_bits[0], pk_len_code[0]) != 0)  /* length index 0 */
        return PK_ERR_OUTPUT;
    if (pk_bw_write(&bw, pk_dist_bits[0], pk_dist_code[0]) != 0)  /* dist index 0 */
        return PK_ERR_OUTPUT;
    if (pk_bw_write(&bw, 2, 0) != 0)       /* dist low bits = 0 */
        return PK_ERR_OUTPUT;

    /* Flush any remaining bits. */
    if (pk_bw_finish(&bw) != 0)
        return PK_ERR_OUTPUT;

    *dst_size = bw.pos;
    return PK_OK;
}

/* --------------------------------------------------------------------------
 * Convenience wrapper for sector compression
 *
 * Compresses a single MPQ sector.  If the compressed output is not
 * smaller than the input, returns the original data size (meaning the
 * sector should be stored uncompressed).
 *
 * `dst` must have room for at least `src_size` bytes.
 * On return, `*dst_size` is the compressed size, or `src_size` if
 * compression did not help.
 *
 * Returns PK_OK on success (compressed or stored-as-is).
 * -------------------------------------------------------------------------- */

static inline int pk_implode_sector(const uint8_t *src, size_t src_size,
                                    uint8_t *dst, size_t *dst_size,
                                    int dict_bits)
{
    /* Need a temporary buffer since compressed output might be larger
     * than input (incompressible data + overhead).  We try compressing
     * into a buffer of 2x the source size. */
    size_t tmp_cap = src_size * 2 + 64;
    uint8_t tmp_stack[8256];  /* enough for 4096-byte sectors */
    uint8_t *tmp;
    int used_heap = 0;

    if (tmp_cap <= sizeof(tmp_stack)) {
        tmp = tmp_stack;
    } else {
        tmp = (uint8_t *)malloc(tmp_cap);
        if (!tmp) {
            /* Fall back: store uncompressed. */
            memcpy(dst, src, src_size);
            *dst_size = src_size;
            return PK_OK;
        }
        used_heap = 1;
    }

    size_t comp_size = tmp_cap;
    int rc = pkimplode(src, src_size, tmp, &comp_size, dict_bits);

    if (rc == PK_OK && comp_size < src_size) {
        /* Compression helped — use the compressed output. */
        memcpy(dst, tmp, comp_size);
        *dst_size = comp_size;
    } else {
        /* Compression didn't help or failed — store uncompressed.
         * The caller (sector writer) will detect comp_size == src_size
         * and know the sector is stored raw. */
        memcpy(dst, src, src_size);
        *dst_size = src_size;
    }

    if (used_heap)
        free(tmp);

    return PK_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_IMPLODE_H */