/*
 * mpqfs — minimal MPQ v1 reader/writer with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * MPQ cryptographic primitives: encryption table, string hashing,
 * block encryption/decryption, and file key derivation.
 *
 * Also contains the public API wrappers (mpqfs_crypto_init, mpqfs_hash_string,
 * mpqfs_encrypt_block, etc.) declared in <mpqfs/mpqfs.h>.
 */

#include "mpq_platform.h"
#include "mpq_crypto.h"
#include "../include/mpqfs/mpqfs.h"

#include <string.h>

/* -----------------------------------------------------------------------
 * Fixed ASCII-to-uppercase table
 *
 * This table matches the one used by StormLib / the original Storm.dll.
 * It converts:
 *   - a-z (0x61-0x7A) to A-Z (0x41-0x5A)
 *   - forward slash '/' (0x2F) to backslash '\\' (0x5C)
 *   - all other bytes pass through unchanged
 *
 * Using a fixed table instead of toupper() is critical because:
 *   1) toupper() is locale-dependent — on systems with non-C locales it
 *      may convert characters >= 0x80 (e.g. accented letters), producing
 *      hash values that differ from what the game expects.
 *   2) The MPQ format defines case-insensitivity only over ASCII a-z.
 *      Bytes >= 0x80 must be passed through unchanged.
 * ----------------------------------------------------------------------- */

static const unsigned char mpq_ascii_to_upper[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x5C,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

/* -----------------------------------------------------------------------
 * Global encryption table (1280 entries = 5 × 256)
 * ----------------------------------------------------------------------- */

static uint32_t g_crypt_table[0x500];
static int      g_crypt_table_ready = 0;

void mpq_crypto_init(void)
{
    if (g_crypt_table_ready)
        return;

    uint32_t seed = 0x00100001;

    for (uint32_t index1 = 0; index1 < 0x100; index1++) {
        uint32_t index2 = index1;

        for (int i = 0; i < 5; i++, index2 += 0x100) {
            uint32_t temp1, temp2;

            seed  = (seed * 125 + 3) % 0x2AAAAB;
            temp1 = (seed & 0xFFFF) << 0x10;

            seed  = (seed * 125 + 3) % 0x2AAAAB;
            temp2 = (seed & 0xFFFF);

            g_crypt_table[index2] = temp1 | temp2;
        }
    }

    g_crypt_table_ready = 1;
}

/* -----------------------------------------------------------------------
 * String hashing
 *
 * Uses the fixed ASCII table above to normalise characters.  This
 * guarantees identical hash values regardless of the host's locale
 * settings, matching the behaviour of Storm.dll / StormLib.
 * ----------------------------------------------------------------------- */

uint32_t mpq_hash_string(const char *str, uint32_t hash_type)
{
    uint32_t seed1 = 0x7FED7FED;
    uint32_t seed2 = 0xEEEEEEEE;

    for (; *str != '\0'; str++) {
        /* Normalise via fixed table: upper-case + forward-slash → backslash */
        uint32_t ch = mpq_ascii_to_upper[(unsigned char)*str];

        seed1 = g_crypt_table[hash_type + ch] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

/* -----------------------------------------------------------------------
 * Block decryption / encryption
 *
 * The key schedule mixes in values from the 5th segment of the crypto
 * table (offset 0x400, MPQ_HASH_KEY2_MIX), NOT from the file-key
 * segment (offset 0x300).  This matches StormLib's EncryptMpqBlock /
 * DecryptMpqBlock exactly.
 * ----------------------------------------------------------------------- */

void mpq_decrypt_block(uint32_t *data, size_t count, uint32_t key)
{
    uint32_t seed = 0xEEEEEEEE;

    for (size_t i = 0; i < count; i++) {
        seed += g_crypt_table[MPQ_HASH_KEY2_MIX + (key & 0xFF)];

        uint32_t ch = data[i] ^ (key + seed);
        data[i] = ch;

        key  = ((~key << 0x15) + 0x11111111) | (key >> 0x0B);
        seed = ch + seed + (seed << 5) + 3;
    }
}

void mpq_encrypt_block(uint32_t *data, size_t count, uint32_t key)
{
    uint32_t seed = 0xEEEEEEEE;

    for (size_t i = 0; i < count; i++) {
        seed += g_crypt_table[MPQ_HASH_KEY2_MIX + (key & 0xFF)];

        uint32_t ch  = data[i] ^ (key + seed);
        data[i] = ch;

        key  = ((~key << 0x15) + 0x11111111) | (key >> 0x0B);
        seed = ch + seed + (seed << 5) + 3;
    }
}

/* -----------------------------------------------------------------------
 * File key derivation
 * ----------------------------------------------------------------------- */

uint32_t mpq_file_key(const char *path, uint32_t block_offset,
                      uint32_t file_size, int adjust)
{
    /*
     * The encryption key is derived from the *filename* portion of the
     * path (everything after the last backslash).
     */
    const char *name = strrchr(path, '\\');
    if (name)
        name++;   /* skip the backslash */
    else
        name = path;

    /* Also handle forward slashes, just in case. */
    const char *name2 = strrchr(name, '/');
    if (name2)
        name = name2 + 1;

    uint32_t key = mpq_hash_string(name, MPQ_HASH_FILE_KEY);

    if (adjust) {
        /* MPQ_FILE_FIX_KEY: further mix in block offset and size. */
        key = (key + block_offset) ^ file_size;
    }

    return key;
}

/* -----------------------------------------------------------------------
 * Public API wrappers
 *
 * These are declared in <mpqfs/mpqfs.h> and provide the public-facing
 * crypto primitives.  Each ensures the crypto table is initialised
 * before proceeding.
 * ----------------------------------------------------------------------- */

void mpqfs_crypto_init(void)
{
    mpq_crypto_init();
}

uint32_t mpqfs_hash_string(const char *str, uint32_t hash_type)
{
    mpq_crypto_init();
    return mpq_hash_string(str, hash_type);
}

uint32_t mpqfs_hash_string_s(const char *str, size_t len, uint32_t hash_type)
{
    mpq_crypto_init();

    uint32_t seed1 = 0x7FED7FED;
    uint32_t seed2 = 0xEEEEEEEE;

    for (size_t i = 0; i < len; i++) {
        uint32_t ch = mpq_ascii_to_upper[(unsigned char)str[i]];
        seed1 = g_crypt_table[hash_type + ch] ^ (seed1 + seed2);
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

void mpqfs_encrypt_block(uint32_t *data, size_t count, uint32_t key)
{
    mpq_crypto_init();
    mpq_encrypt_block(data, count, key);
#if MPQFS_BIG_ENDIAN
    /* The caller passes host-order data.  After encryption the result
     * must be in little-endian for writing to the MPQ file on disk. */
    for (size_t i = 0; i < count; i++)
        data[i] = mpqfs_le32(data[i]);
#endif
}

void mpqfs_decrypt_block(uint32_t *data, size_t count, uint32_t key)
{
    mpq_crypto_init();
#if MPQFS_BIG_ENDIAN
    /* The caller passes little-endian on-disk data.  Swap to host order
     * before decryption so the XOR arithmetic is correct. */
    for (size_t i = 0; i < count; i++)
        data[i] = mpqfs_le32(data[i]);
#endif
    mpq_decrypt_block(data, count, key);
}

void mpqfs_file_hash(const char *filename,
                     uint32_t *out_index,
                     uint32_t *out_hash_a,
                     uint32_t *out_hash_b)
{
    mpq_crypto_init();
    if (out_index)
        *out_index  = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX);
    if (out_hash_a)
        *out_hash_a = mpq_hash_string(filename, MPQ_HASH_NAME_A);
    if (out_hash_b)
        *out_hash_b = mpq_hash_string(filename, MPQ_HASH_NAME_B);
}

void mpqfs_file_hash_s(const char *filename, size_t len,
                       uint32_t *out_index,
                       uint32_t *out_hash_a,
                       uint32_t *out_hash_b)
{
    mpq_crypto_init();
    if (out_index)
        *out_index  = mpqfs_hash_string_s(filename, len, MPQFS_HASH_TABLE_INDEX);
    if (out_hash_a)
        *out_hash_a = mpqfs_hash_string_s(filename, len, MPQFS_HASH_NAME_A);
    if (out_hash_b)
        *out_hash_b = mpqfs_hash_string_s(filename, len, MPQFS_HASH_NAME_B);
}