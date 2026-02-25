/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Public PKWARE DCL implode / explode wrappers.
 *
 * These functions expose the internal pkimplode() / pkexplode() routines
 * (from mpq_implode.h / mpq_explode.h) as part of the public mpqfs API,
 * allowing consumers (e.g. DevilutionX) to compress and decompress
 * arbitrary data using the PKWARE DCL format without pulling in a
 * separate PKWare library.
 */

#include "mpq_platform.h"
#include "mpq_implode.h"   /* pkimplode(), PK_OK, PK_ERR_* */
#include "mpq_explode.h"   /* pkexplode(), PK_OK, PK_ERR_* */
#include "../include/mpqfs/mpqfs.h"

int mpqfs_pk_implode(const uint8_t *src, size_t src_size,
                     uint8_t *dst, size_t *dst_size,
                     int dict_bits)
{
    if (!src || !dst || !dst_size)
        return PK_ERR_INPUT;

    return pkimplode(src, src_size, dst, dst_size, dict_bits);
}

int mpqfs_pk_explode(const uint8_t *src, size_t src_size,
                     uint8_t *dst, size_t *dst_size)
{
    if (!src || !dst || !dst_size)
        return PK_ERR_INPUT;

    return pkexplode(src, src_size, dst, dst_size);
}