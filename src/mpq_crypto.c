/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * MPQ cryptographic primitives: encryption table, string hashing,
 * block encryption/decryption, and file key derivation.
 */

#include "mpq_platform.h"
#include "mpq_crypto.h"

#include <ctype.h>
#include <string.h>

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
 * ----------------------------------------------------------------------- */

uint32_t mpq_hash_string(const char *str, uint32_t hash_type)
{
    uint32_t seed1 = 0x7FED7FED;
    uint32_t seed2 = 0xEEEEEEEE;

    for (; *str != '\0'; str++) {
        /* Normalise: upper-case, forward-slash → backslash */
        unsigned char ch = (unsigned char)*str;
        if (ch == '/')
            ch = '\\';
        ch = (unsigned char)toupper(ch);

        seed1 = g_crypt_table[hash_type + ch] ^ (seed1 + seed2);
        seed2 = (uint32_t)ch + seed1 + seed2 + (seed2 << 5) + 3;
    }

    return seed1;
}

/* -----------------------------------------------------------------------
 * Block decryption / encryption
 * ----------------------------------------------------------------------- */

void mpq_decrypt_block(uint32_t *data, size_t count, uint32_t key)
{
    uint32_t seed = 0xEEEEEEEE;

    for (size_t i = 0; i < count; i++) {
        seed += g_crypt_table[MPQ_HASH_FILE_KEY + (key & 0xFF)];

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
        seed += g_crypt_table[MPQ_HASH_FILE_KEY + (key & 0xFF)];

        uint32_t ch  = data[i];
        data[i] = ch ^ (key + seed);

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