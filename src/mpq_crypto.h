/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Internal header: MPQ cryptographic primitives.
 *
 * MPQ archives encrypt their hash and block tables (and optionally
 * individual file data) using a simple symmetric cipher driven by a
 * 1280-entry lookup table derived from a fixed seed.
 */

#ifndef MPQFS_MPQ_CRYPTO_H
#define MPQFS_MPQ_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialise the global encryption table.
 * This MUST be called once (it is idempotent) before any other
 * crypto function is used.  mpqfs_open() takes care of this for you.
 */
void mpq_crypto_init(void);

/*
 * Hash types used by mpq_hash_string().
 */
#define MPQ_HASH_TABLE_INDEX  0x000   /* hash table bucket index   */
#define MPQ_HASH_NAME_A       0x100   /* verification hash A       */
#define MPQ_HASH_NAME_B       0x200   /* verification hash B       */
#define MPQ_HASH_FILE_KEY     0x300   /* file decryption key       */

/*
 * Compute an MPQ hash for the given NUL-terminated string.
 * |hash_type| is one of the MPQ_HASH_* constants above.
 *
 * Filenames are treated case-insensitively and backslash / forward
 * slash are normalised to backslash before hashing.
 */
uint32_t mpq_hash_string(const char *str, uint32_t hash_type);

/*
 * Decrypt an array of uint32_t values in-place.
 * |data| points to |count| uint32_t words.  |key| is the decryption
 * key (e.g. mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY)).
 */
void mpq_decrypt_block(uint32_t *data, size_t count, uint32_t key);

/*
 * Encrypt an array of uint32_t values in-place.
 * Provided for symmetry / testing; not used during normal reading.
 */
void mpq_encrypt_block(uint32_t *data, size_t count, uint32_t key);

/*
 * Derive the base encryption key for a file from its full archive
 * path (e.g. "levels\\l1data\\l1.min").
 *
 * If |adjust| is true the key is further modified by the file's
 * block offset and uncompressed size (flag 0x00020000 —
 * MPQ_FILE_FIX_KEY).
 */
uint32_t mpq_file_key(const char *path, uint32_t block_offset,
                      uint32_t file_size, int adjust);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_CRYPTO_H */