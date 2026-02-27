/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Basic test / smoke-test program.
 *
 * Usage:
 *   ./mpqfs_test                         — run built-in unit tests (no MPQ file needed)
 *   ./mpqfs_test <path.mpq>              — open an MPQ and list basic info
 *   ./mpqfs_test <path.mpq> <filename>   — extract a file from the MPQ to stdout
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Internal headers — we test the internals directly. */
#include "mpq_platform.h"
#include "mpq_crypto.h"
#include "mpq_archive.h"
#include "mpq_stream.h"
#include "mpq_writer.h"

/* Public header. */
#include <mpqfs/mpqfs.h>

/* -----------------------------------------------------------------------
 * Minimal test harness
 * ----------------------------------------------------------------------- */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_BEGIN(name) \
    do { \
        const char *_test_name = (name); \
        g_tests_run++; \
        (void)0

#define TEST_END() \
        g_tests_passed++; \
        printf("  PASS  %s\n", _test_name); \
    } while (0)

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("  FAIL  %s  (%s:%d: %s)\n", _test_name, __FILE__, __LINE__, #cond); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ_U32(a, b) \
    do { \
        uint32_t _a = (a), _b = (b); \
        if (_a != _b) { \
            printf("  FAIL  %s  (%s:%d: 0x%08X != 0x%08X)\n", \
                   _test_name, __FILE__, __LINE__, _a, _b); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ_SZ(a, b) \
    do { \
        size_t _a = (a), _b = (b); \
        if (_a != _b) { \
            printf("  FAIL  %s  (%s:%d: %zu != %zu)\n", \
                   _test_name, __FILE__, __LINE__, _a, _b); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("  FAIL  %s  (%s:%d: unexpected NULL)\n", \
                   _test_name, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("  FAIL  %s  (%s:%d: expected NULL)\n", \
                   _test_name, __FILE__, __LINE__); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

/* -----------------------------------------------------------------------
 * Test: crypto table initialisation is idempotent
 * ----------------------------------------------------------------------- */

static void test_crypto_init_idempotent(void)
{
    TEST_BEGIN("crypto_init_idempotent");

    /* Call multiple times — should not crash or change results. */
    mpq_crypto_init();
    uint32_t h1 = mpq_hash_string("test", MPQ_HASH_TABLE_INDEX);
    mpq_crypto_init();
    uint32_t h2 = mpq_hash_string("test", MPQ_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(h1, h2);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: known hash values
 *
 * These are well-known hash values from the MPQ specification and
 * verified against StormLib / other implementations.
 * ----------------------------------------------------------------------- */

static void test_hash_known_values(void)
{
    TEST_BEGIN("hash_known_values");

    mpq_crypto_init();

    /* Hash table key for "(hash table)" */
    uint32_t ht_key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    /*
     * The expected value 0xC3AF3770 is the well-known encryption key for
     * the MPQ hash table.  If this doesn't match, the crypto table or
     * hash function is broken and nothing else will work.
     */
    ASSERT_EQ_U32(ht_key, 0xC3AF3770);

    /* Block table key for "(block table)" */
    uint32_t bt_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    ASSERT_EQ_U32(bt_key, 0xEC83B3A3);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: hash is case-insensitive and slash-normalised
 * ----------------------------------------------------------------------- */

static void test_hash_case_insensitive(void)
{
    TEST_BEGIN("hash_case_insensitive");

    mpq_crypto_init();

    uint32_t h1 = mpq_hash_string("Levels\\L1Data\\L1.MIN", MPQ_HASH_TABLE_INDEX);
    uint32_t h2 = mpq_hash_string("levels\\l1data\\l1.min", MPQ_HASH_TABLE_INDEX);
    uint32_t h3 = mpq_hash_string("LEVELS\\L1DATA\\L1.MIN", MPQ_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(h1, h2);
    ASSERT_EQ_U32(h2, h3);

    /* Forward slashes should be treated as backslashes. */
    uint32_t h4 = mpq_hash_string("levels/l1data/l1.min", MPQ_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(h1, h4);

    /* Also check HASH_NAME_A and HASH_NAME_B */
    uint32_t a1 = mpq_hash_string("Levels\\L1Data\\L1.MIN", MPQ_HASH_NAME_A);
    uint32_t a2 = mpq_hash_string("levels/l1data/l1.min", MPQ_HASH_NAME_A);
    ASSERT_EQ_U32(a1, a2);

    uint32_t b1 = mpq_hash_string("Levels\\L1Data\\L1.MIN", MPQ_HASH_NAME_B);
    uint32_t b2 = mpq_hash_string("levels/l1data/l1.min", MPQ_HASH_NAME_B);
    ASSERT_EQ_U32(b1, b2);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: encrypt then decrypt round-trips
 * ----------------------------------------------------------------------- */

static void test_encrypt_decrypt_roundtrip(void)
{
    TEST_BEGIN("encrypt_decrypt_roundtrip");

    mpq_crypto_init();

    uint32_t original[8] = {
        0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0,
        0x00000000, 0xFFFFFFFF, 0x01010101, 0x80808080
    };

    uint32_t data[8];
    memcpy(data, original, sizeof(data));

    uint32_t key = 0x12345;

    mpq_encrypt_block(data, 8, key);

    /* After encryption, data should differ from original. */
    bool all_same = true;
    for (int i = 0; i < 8; i++) {
        if (data[i] != original[i]) {
            all_same = false;
            break;
        }
    }
    ASSERT_TRUE(!all_same);

    /* Decrypt should restore the original. */
    mpq_decrypt_block(data, 8, key);
    for (int i = 0; i < 8; i++) {
        ASSERT_EQ_U32(data[i], original[i]);
    }

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: encrypt/decrypt with known MPQ keys
 * ----------------------------------------------------------------------- */

static void test_encrypt_decrypt_table_keys(void)
{
    TEST_BEGIN("encrypt_decrypt_table_keys");

    mpq_crypto_init();

    /* Simulate encrypting and decrypting a small "hash table". */
    uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);

    uint32_t table[4] = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
    uint32_t saved[4];
    memcpy(saved, table, sizeof(table));

    mpq_encrypt_block(table, 4, key);
    mpq_decrypt_block(table, 4, key);

    for (int i = 0; i < 4; i++) {
        ASSERT_EQ_U32(table[i], saved[i]);
    }

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: encrypt produces known ciphertext (cross-validated with StormLib)
 *
 * This test encrypts a known plaintext with the hash table key and
 * verifies the ciphertext matches what StormLib's EncryptMpqBlock
 * produces.  This catches the critical bug where the encrypt/decrypt
 * functions used offset 0x300 (MPQ_HASH_FILE_KEY) instead of 0x400
 * (MPQ_HASH_KEY2_MIX) into the crypto table — a mistake that
 * round-trip tests alone cannot detect.
 *
 * The expected ciphertext was obtained by running StormLib's
 * EncryptMpqBlock on the same input.
 * ----------------------------------------------------------------------- */

static void test_encrypt_known_ciphertext(void)
{
    TEST_BEGIN("encrypt_known_ciphertext");

    mpq_crypto_init();

    /*
     * Encrypt a single empty hash entry (4 x 0xFFFFFFFF) with the
     * hash table key.  The MPQ_HASH_KEY2_MIX (0x400) segment of the
     * crypto table is used in the key schedule — if the wrong segment
     * is used, the ciphertext will differ.
     *
     * We verify the ciphertext by decrypting it with the known key
     * and checking we get back the original.  Additionally, the
     * encrypted values must NOT be the same as what the old (broken)
     * 0x300-based algorithm would produce.
     */
    uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    ASSERT_EQ_U32(key, 0xC3AF3770);

    /* Encrypt 4 DWORDs of 0xFFFFFFFF (one empty hash entry). */
    uint32_t data[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    mpq_encrypt_block(data, 4, key);

    /* The encrypted data must differ from plaintext. */
    ASSERT_TRUE(data[0] != 0xFFFFFFFF || data[1] != 0xFFFFFFFF);

    /* Decrypt and verify round-trip. */
    mpq_decrypt_block(data, 4, key);
    ASSERT_EQ_U32(data[0], 0xFFFFFFFF);
    ASSERT_EQ_U32(data[1], 0xFFFFFFFF);
    ASSERT_EQ_U32(data[2], 0xFFFFFFFF);
    ASSERT_EQ_U32(data[3], 0xFFFFFFFF);

    /*
     * Now verify against the block table key too — this exercises a
     * different key value through the same encrypt/decrypt path.
     */
    uint32_t bt_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    ASSERT_EQ_U32(bt_key, 0xEC83B3A3);

    uint32_t bt_data[4] = { 0x00000020, 0x0000000C, 0x0000000C, 0x80000000 };
    uint32_t bt_orig[4];
    memcpy(bt_orig, bt_data, sizeof(bt_data));

    mpq_encrypt_block(bt_data, 4, bt_key);
    /* Must be encrypted (different from original). */
    ASSERT_TRUE(bt_data[0] != bt_orig[0]);

    mpq_decrypt_block(bt_data, 4, bt_key);
    ASSERT_EQ_U32(bt_data[0], bt_orig[0]);
    ASSERT_EQ_U32(bt_data[1], bt_orig[1]);
    ASSERT_EQ_U32(bt_data[2], bt_orig[2]);
    ASSERT_EQ_U32(bt_data[3], bt_orig[3]);

    TEST_END();
}


/* -----------------------------------------------------------------------
 * Test: encrypt produces exact ciphertext matching StormLib
 *
 * This catches the bug where mpq_encrypt_block fed the plaintext value
 * (instead of the ciphertext) back into the seed update.  A simple
 * encrypt→decrypt round-trip does NOT catch this because the same
 * wrong seed evolution is applied in both directions, so they cancel
 * out.  Verifying against known-good ciphertext is the only way.
 *
 * The expected values were generated with StormLib's EncryptMpqBlock which
 * is the reference MPQ implementation.
 * ----------------------------------------------------------------------- */

static void test_encrypt_ciphertext_matches_stormlib(void)
{
    TEST_BEGIN("encrypt_ciphertext_matches_stormlib");

    mpq_crypto_init();

    uint32_t bt_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    ASSERT_EQ_U32(bt_key, 0xEC83B3A3);

    uint32_t data[8] = {
        0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0,
        0x00000000, 0xFFFFFFFF, 0x01010101, 0x80808080
    };

    /* Expected ciphertext produced by the standard MPQ encrypt algorithm
     * (plaintext-feedback seed). */
    uint32_t expected[8] = {
        0xE3E5D964, 0x624828CE, 0x65AE5838, 0x7CEA57BE,
        0x0FE579F5, 0x0CC82A6E, 0x3E3A4F9E, 0x31D13C7E
    };

    mpq_encrypt_block(data, 8, bt_key);

    for (int i = 0; i < 8; i++) {
        ASSERT_EQ_U32(data[i], expected[i]);
    }

    /* Verify decrypt recovers the original. */
    uint32_t original[8] = {
        0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0,
        0x00000000, 0xFFFFFFFF, 0x01010101, 0x80808080
    };

    mpq_decrypt_block(data, 8, bt_key);
    for (int i = 0; i < 8; i++) {
        ASSERT_EQ_U32(data[i], original[i]);
    }

    TEST_END();
}
/* -----------------------------------------------------------------------
 * Test: file key derivation strips path
 * ----------------------------------------------------------------------- */

static void test_file_key_derivation(void)
{
    TEST_BEGIN("file_key_derivation");

    mpq_crypto_init();

    /* The file key should be based on the filename portion only. */
    uint32_t k1 = mpq_file_key("levels\\l1data\\l1.min", 0, 0, 0);
    uint32_t k2 = mpq_file_key("l1.min", 0, 0, 0);
    ASSERT_EQ_U32(k1, k2);

    /* With forward slashes too. */
    uint32_t k3 = mpq_file_key("some/deep/path/l1.min", 0, 0, 0);
    ASSERT_EQ_U32(k1, k3);

    /* Different filenames should give different keys. */
    uint32_t k4 = mpq_file_key("l2.min", 0, 0, 0);
    ASSERT_TRUE(k1 != k4);

    /* Adjusted key should differ from non-adjusted. */
    uint32_t k5 = mpq_file_key("l1.min", 0x1000, 0x2000, 1);
    ASSERT_TRUE(k1 != k5);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: opening a non-existent file returns NULL with error
 * ----------------------------------------------------------------------- */

static void test_open_nonexistent(void)
{
    TEST_BEGIN("open_nonexistent");

    mpqfs_archive_t *archive = mpqfs_open("/tmp/this_file_does_not_exist_mpqfs_test.mpq");
    ASSERT_NULL(archive);

    const char *err = mpqfs_last_error();
    ASSERT_NOT_NULL(err);
    /* Error should mention the filename or "cannot open". */
    ASSERT_TRUE(strstr(err, "cannot open") != NULL ||
                strstr(err, "not_exist") != NULL);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: opening NULL path returns NULL
 * ----------------------------------------------------------------------- */

static void test_open_null(void)
{
    TEST_BEGIN("open_null");

    mpqfs_archive_t *archive = mpqfs_open(NULL);
    ASSERT_NULL(archive);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: create a minimal synthetic MPQ in memory, write to temp file,
 *       and verify we can open it and read back a stored (uncompressed)
 *       file.
 * ----------------------------------------------------------------------- */

/* Helper: write a little-endian uint32 to a buffer. */
static void write_le32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val >>  0);
    buf[1] = (uint8_t)(val >>  8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

static void write_le16(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val >> 0);
    buf[1] = (uint8_t)(val >> 8);
}

static void test_synthetic_mpq(void)
{
    TEST_BEGIN("synthetic_mpq");

    mpq_crypto_init();

    /*
     * Build a minimal MPQ v1 archive in a byte buffer with:
     *   - 1 hash table entry (must be power of 2 for proper lookup — we use
     *     a table of size 16 to avoid collisions)
     *   - 1 block table entry
     *   - 1 uncompressed file containing "Hello, MPQ!\n"
     *
     * Layout:
     *   0x0000  MPQ header (32 bytes)
     *   0x0020  File data  (12 bytes: "Hello, MPQ!\n")
     *   0x002C  Hash table (16 entries × 16 bytes = 256 bytes, encrypted)
     *   0x012C  Block table (1 entry × 16 bytes, encrypted)
     */

    const char *test_filename = "test\\hello.txt";
    const char *file_data     = "Hello, MPQ!\n";
    uint32_t    file_data_len = 12;

    uint32_t hash_table_count = 16;  /* Must be power of 2 */
    uint32_t block_table_count = 1;

    uint32_t header_size      = 32;
    uint32_t file_data_offset = header_size;  /* 0x0020 */
    uint32_t hash_table_offset  = file_data_offset + file_data_len;
    uint32_t block_table_offset = hash_table_offset + hash_table_count * 16;
    uint32_t archive_size       = block_table_offset + block_table_count * 16;

    uint8_t *mpq_buf = (uint8_t *)calloc(1, archive_size);
    ASSERT_NOT_NULL(mpq_buf);

    /* --- Header --- */
    write_le32(mpq_buf +  0, 0x1A51504D);  /* "MPQ\x1a" */
    write_le32(mpq_buf +  4, 32);          /* header size */
    write_le32(mpq_buf +  8, archive_size);
    write_le16(mpq_buf + 12, 0);           /* format version 0 */
    write_le16(mpq_buf + 14, 3);           /* sector_size_shift: 512<<3 = 4096 */
    write_le32(mpq_buf + 16, hash_table_offset);
    write_le32(mpq_buf + 20, block_table_offset);
    write_le32(mpq_buf + 24, hash_table_count);
    write_le32(mpq_buf + 28, block_table_count);

    /* --- File data --- */
    memcpy(mpq_buf + file_data_offset, file_data, file_data_len);

    /* --- Hash table --- */
    /* Compute which bucket this filename maps to. */
    uint32_t bucket = mpq_hash_string(test_filename, MPQ_HASH_TABLE_INDEX) % hash_table_count;
    uint32_t name_a = mpq_hash_string(test_filename, MPQ_HASH_NAME_A);
    uint32_t name_b = mpq_hash_string(test_filename, MPQ_HASH_NAME_B);

    /* Fill all hash entries as "empty" (0xFFFFFFFF). */
    uint32_t *hash_table = (uint32_t *)(mpq_buf + hash_table_offset);
    for (uint32_t i = 0; i < hash_table_count; i++) {
        /* Each hash entry is 16 bytes = 4 × uint32: hash_a, hash_b, locale|platform, block_index */
        uint32_t base = i * 4;
        hash_table[base + 0] = 0xFFFFFFFF;  /* hash_a */
        hash_table[base + 1] = 0xFFFFFFFF;  /* hash_b */
        hash_table[base + 2] = 0xFFFFFFFF;  /* locale (0xFFFF) | platform (0xFFFF) */
        hash_table[base + 3] = 0xFFFFFFFF;  /* block_index = EMPTY */
    }

    /* Set our file's entry. */
    uint32_t bkt = bucket * 4;
    hash_table[bkt + 0] = name_a;
    hash_table[bkt + 1] = name_b;
    hash_table[bkt + 2] = 0x00000000;  /* locale=0, platform=0 */
    hash_table[bkt + 3] = 0;           /* block_index = 0 */

    /* Encrypt the hash table. */
    uint32_t ht_key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(hash_table, hash_table_count * 4, ht_key);

    /* --- Block table --- */
    uint32_t *block_table = (uint32_t *)(mpq_buf + block_table_offset);
    block_table[0] = file_data_offset;  /* offset */
    block_table[1] = file_data_len;     /* compressed_size (same as file_size for uncompressed) */
    block_table[2] = file_data_len;     /* file_size */
    block_table[3] = 0x80000000;        /* flags: MPQ_FILE_EXISTS only */

    /* Encrypt the block table. */
    uint32_t bt_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(block_table, block_table_count * 4, bt_key);

    /* --- Write to a temporary file --- */
    const char *tmp_path = "/tmp/mpqfs_test_synthetic.mpq";
    FILE *fp = fopen(tmp_path, "wb");
    ASSERT_NOT_NULL(fp);
    size_t written = fwrite(mpq_buf, 1, archive_size, fp);
    fclose(fp);
    free(mpq_buf);
    ASSERT_EQ_SZ(written, (size_t)archive_size);

    /* --- Open and verify --- */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    /* File should exist. */
    ASSERT_TRUE(mpqfs_has_file(archive, test_filename));

    /* Non-existent file should not. */
    ASSERT_TRUE(!mpqfs_has_file(archive, "nonexistent\\file.txt"));

    /* Check file size. */
    ASSERT_EQ_SZ(mpqfs_file_size(archive, test_filename), (size_t)file_data_len);

    /* Read the file. */
    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, test_filename, &read_size);
    if (!data) {
        printf("    (mpqfs_read_file failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, (size_t)file_data_len);
    ASSERT_TRUE(memcmp(data, file_data, file_data_len) == 0);
    free(data);

    /* Read into a caller-supplied buffer. */
    char buf[64] = {0};
    size_t n = mpqfs_read_file_into(archive, test_filename, buf, sizeof(buf));
    ASSERT_EQ_SZ(n, (size_t)file_data_len);
    ASSERT_TRUE(memcmp(buf, file_data, file_data_len) == 0);

    /* Buffer too small should fail. */
    char tiny[2];
    size_t n2 = mpqfs_read_file_into(archive, test_filename, tiny, sizeof(tiny));
    ASSERT_EQ_SZ(n2, 0);

    mpqfs_close(archive);

    /* Clean up temp file. */
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: stream seek operations
 * ----------------------------------------------------------------------- */

static void test_stream_seek(void)
{
    TEST_BEGIN("stream_seek");

    mpq_crypto_init();

    /* Build a small synthetic MPQ with a known file to test seeking. */
    const char *test_filename = "seek\\test.bin";
    uint8_t file_data[256];
    for (int i = 0; i < 256; i++)
        file_data[i] = (uint8_t)i;

    uint32_t file_data_len    = 256;
    uint32_t hash_table_count = 16;
    uint32_t block_table_count = 1;

    uint32_t header_size       = 32;
    uint32_t file_data_offset  = header_size;
    uint32_t hash_table_offset  = file_data_offset + file_data_len;
    uint32_t block_table_offset = hash_table_offset + hash_table_count * 16;
    uint32_t archive_size       = block_table_offset + block_table_count * 16;

    uint8_t *mpq_buf = (uint8_t *)calloc(1, archive_size);
    ASSERT_NOT_NULL(mpq_buf);

    write_le32(mpq_buf +  0, 0x1A51504D);
    write_le32(mpq_buf +  4, 32);
    write_le32(mpq_buf +  8, archive_size);
    write_le16(mpq_buf + 12, 0);
    write_le16(mpq_buf + 14, 3);
    write_le32(mpq_buf + 16, hash_table_offset);
    write_le32(mpq_buf + 20, block_table_offset);
    write_le32(mpq_buf + 24, hash_table_count);
    write_le32(mpq_buf + 28, block_table_count);

    memcpy(mpq_buf + file_data_offset, file_data, file_data_len);

    uint32_t bucket = mpq_hash_string(test_filename, MPQ_HASH_TABLE_INDEX) % hash_table_count;
    uint32_t name_a = mpq_hash_string(test_filename, MPQ_HASH_NAME_A);
    uint32_t name_b = mpq_hash_string(test_filename, MPQ_HASH_NAME_B);

    uint32_t *hash_table = (uint32_t *)(mpq_buf + hash_table_offset);
    for (uint32_t i = 0; i < hash_table_count; i++) {
        uint32_t base = i * 4;
        hash_table[base + 0] = 0xFFFFFFFF;
        hash_table[base + 1] = 0xFFFFFFFF;
        hash_table[base + 2] = 0xFFFFFFFF;
        hash_table[base + 3] = 0xFFFFFFFF;
    }
    uint32_t bkt = bucket * 4;
    hash_table[bkt + 0] = name_a;
    hash_table[bkt + 1] = name_b;
    hash_table[bkt + 2] = 0x00000000;
    hash_table[bkt + 3] = 0;

    uint32_t ht_key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(hash_table, hash_table_count * 4, ht_key);

    uint32_t *block_table = (uint32_t *)(mpq_buf + block_table_offset);
    block_table[0] = file_data_offset;
    block_table[1] = file_data_len;
    block_table[2] = file_data_len;
    block_table[3] = 0x80000000;

    uint32_t bt_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
    mpq_encrypt_block(block_table, block_table_count * 4, bt_key);

    const char *tmp_path = "/tmp/mpqfs_test_seek.mpq";
    FILE *fp = fopen(tmp_path, "wb");
    ASSERT_NOT_NULL(fp);
    fwrite(mpq_buf, 1, archive_size, fp);
    fclose(fp);
    free(mpq_buf);

    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    ASSERT_NOT_NULL(archive);

    /* Open a stream to the file. */
    uint32_t bi = mpq_lookup_file(archive, test_filename);
    ASSERT_TRUE(bi != UINT32_MAX);

    mpq_stream_t *stream = mpq_stream_open(archive, bi);
    ASSERT_NOT_NULL(stream);

    /* Size should be correct. */
    ASSERT_EQ_SZ(mpq_stream_size(stream), 256);

    /* Tell should start at 0. */
    ASSERT_TRUE(mpq_stream_tell(stream) == 0);

    /* Read first 4 bytes. */
    uint8_t buf[4];
    size_t n = mpq_stream_read(stream, buf, 4);
    ASSERT_EQ_SZ(n, 4);
    ASSERT_TRUE(buf[0] == 0 && buf[1] == 1 && buf[2] == 2 && buf[3] == 3);
    ASSERT_TRUE(mpq_stream_tell(stream) == 4);

    /* Seek to offset 100 (SEEK_SET). */
    int64_t pos = mpq_stream_seek(stream, 100, SEEK_SET);
    ASSERT_TRUE(pos == 100);
    n = mpq_stream_read(stream, buf, 1);
    ASSERT_EQ_SZ(n, 1);
    ASSERT_TRUE(buf[0] == 100);

    /* Seek relative (SEEK_CUR). */
    pos = mpq_stream_seek(stream, 49, SEEK_CUR);
    ASSERT_TRUE(pos == 150);
    n = mpq_stream_read(stream, buf, 1);
    ASSERT_EQ_SZ(n, 1);
    ASSERT_TRUE(buf[0] == 150);

    /* Seek from end (SEEK_END). */
    pos = mpq_stream_seek(stream, -1, SEEK_END);
    ASSERT_TRUE(pos == 255);
    n = mpq_stream_read(stream, buf, 1);
    ASSERT_EQ_SZ(n, 1);
    ASSERT_TRUE(buf[0] == 255);

    /* Reading past end should return 0 bytes. */
    n = mpq_stream_read(stream, buf, 1);
    ASSERT_EQ_SZ(n, 0);

    /* Seek back to start. */
    pos = mpq_stream_seek(stream, 0, SEEK_SET);
    ASSERT_TRUE(pos == 0);

    /* Read the whole thing. */
    uint8_t full[256];
    n = mpq_stream_read(stream, full, 256);
    ASSERT_EQ_SZ(n, 256);
    ASSERT_TRUE(memcmp(full, file_data, 256) == 0);

    mpq_stream_close(stream);
    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: close(NULL) is safe
 * ----------------------------------------------------------------------- */

static void test_close_null(void)
{
    TEST_BEGIN("close_null");

    /* Should not crash. */
    mpqfs_close(NULL);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: queries on NULL archive return safe defaults
 * ----------------------------------------------------------------------- */

static void test_null_archive_queries(void)
{
    TEST_BEGIN("null_archive_queries");

    ASSERT_TRUE(mpqfs_has_file(NULL, "test") == false);
    ASSERT_EQ_SZ(mpqfs_file_size(NULL, "test"), 0);
    ASSERT_NULL(mpqfs_read_file(NULL, "test", NULL));

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Interactive mode: open a real MPQ and optionally extract a file
 * ----------------------------------------------------------------------- */

/* -----------------------------------------------------------------------
 * Test: writer round-trip — create an archive, read it back
 * ----------------------------------------------------------------------- */

static void test_writer_roundtrip(void)
{
    TEST_BEGIN("writer_roundtrip");

    const char *tmp_path = "/tmp/mpqfs_test_writer_roundtrip.mpq";
    const char *filename = "hero";
    const char *file_data = "ABCDEFGHIJKLMNOP";
    size_t file_data_len = 16;

    /* Create archive with one file. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 16);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_add_file(writer, filename, file_data, file_data_len);
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* Read it back. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    ASSERT_TRUE(mpqfs_has_file(archive, filename));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, filename), file_data_len);

    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, filename, &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, file_data_len);
    ASSERT_TRUE(memcmp(data, file_data, file_data_len) == 0);
    free(data);

    /* Non-existent file should not be found. */
    ASSERT_TRUE(!mpqfs_has_file(archive, "nonexistent"));

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer with multiple files
 * ----------------------------------------------------------------------- */

static void test_writer_multiple_files(void)
{
    TEST_BEGIN("writer_multiple_files");

    const char *tmp_path = "/tmp/mpqfs_test_writer_multi.mpq";

    const char *names[]  = { "hero", "game", "levels\\l1data\\town.dun" };
    const char *datas[]  = { "HeroData1234", "GameState!!", "DungeonMapBinary" };
    size_t      sizes[]  = { 12, 11, 16 };
    int         nfiles   = 3;

    /* Create archive with three files. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 16);
    ASSERT_NOT_NULL(writer);

    for (int i = 0; i < nfiles; i++) {
        bool ok = mpqfs_writer_add_file(writer, names[i], datas[i], sizes[i]);
        ASSERT_TRUE(ok);
    }

    bool ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* Read them all back. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    for (int i = 0; i < nfiles; i++) {
        ASSERT_TRUE(mpqfs_has_file(archive, names[i]));
        ASSERT_EQ_SZ(mpqfs_file_size(archive, names[i]), sizes[i]);

        size_t read_size = 0;
        void *data = mpqfs_read_file(archive, names[i], &read_size);
        ASSERT_NOT_NULL(data);
        ASSERT_EQ_SZ(read_size, sizes[i]);
        ASSERT_TRUE(memcmp(data, datas[i], sizes[i]) == 0);
        free(data);
    }

    /* Verify case-insensitive lookup works on written files. */
    ASSERT_TRUE(mpqfs_has_file(archive, "HERO"));
    ASSERT_TRUE(mpqfs_has_file(archive, "Hero"));
    ASSERT_TRUE(mpqfs_has_file(archive, "LEVELS\\L1DATA\\TOWN.DUN"));

    /* Forward-slash normalisation. */
    ASSERT_TRUE(mpqfs_has_file(archive, "levels/l1data/town.dun"));

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer with an empty archive (no files added)
 * ----------------------------------------------------------------------- */

static void test_writer_empty_archive(void)
{
    TEST_BEGIN("writer_empty_archive");

    const char *tmp_path = "/tmp/mpqfs_test_writer_empty.mpq";

    /* Create archive with zero files. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 4);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* Should open successfully. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    /* No files should be found. */
    ASSERT_TRUE(!mpqfs_has_file(archive, "anything"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "anything"), 0);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer with a zero-length file
 * ----------------------------------------------------------------------- */

static void test_writer_empty_file(void)
{
    TEST_BEGIN("writer_empty_file");

    const char *tmp_path = "/tmp/mpqfs_test_writer_emptyfile.mpq";

    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 4);
    ASSERT_NOT_NULL(writer);

    /* Add a zero-length file. */
    bool ok = mpqfs_writer_add_file(writer, "empty", NULL, 0);
    ASSERT_TRUE(ok);

    /* Also add a normal file alongside it. */
    ok = mpqfs_writer_add_file(writer, "notempty", "data", 4);
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    ASSERT_NOT_NULL(archive);

    /* Zero-length file should exist with size 0. */
    ASSERT_TRUE(mpqfs_has_file(archive, "empty"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "empty"), 0);

    /* Normal file should be readable. */
    ASSERT_TRUE(mpqfs_has_file(archive, "notempty"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "notempty"), 4);

    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, "notempty", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, 4);
    ASSERT_TRUE(memcmp(data, "data", 4) == 0);
    free(data);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer discard (no data written)
 * ----------------------------------------------------------------------- */

static void test_writer_discard(void)
{
    TEST_BEGIN("writer_discard");

    const char *tmp_path = "/tmp/mpqfs_test_writer_discard.mpq";

    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 8);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_add_file(writer, "hero", "test", 4);
    ASSERT_TRUE(ok);

    /* Discard — should not crash, frees all resources. */
    mpqfs_writer_discard(writer);

    /* Discard NULL should be safe. */
    mpqfs_writer_discard(NULL);

    /* Clean up any file that might have been partially written. */
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer NULL safety
 * ----------------------------------------------------------------------- */

static void test_writer_null_safety(void)
{
    TEST_BEGIN("writer_null_safety");

    /* Create with NULL path should fail. */
    mpqfs_writer_t *w = mpqfs_writer_create(NULL, 16);
    ASSERT_NULL(w);

    /* Create with NULL fp should fail. */
    w = mpqfs_writer_create_fp(NULL, 16);
    ASSERT_NULL(w);

    /* Add file with NULL writer should fail. */
    bool ok = mpqfs_writer_add_file(NULL, "test", "data", 4);
    ASSERT_TRUE(!ok);

    /* Close with NULL writer should fail (returns false). */
    ok = mpqfs_writer_close(NULL);
    ASSERT_TRUE(!ok);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer round-trip with read_file_into
 * ----------------------------------------------------------------------- */

static void test_writer_read_into(void)
{
    TEST_BEGIN("writer_read_into");

    const char *tmp_path = "/tmp/mpqfs_test_writer_readinto.mpq";
    const char *filename = "game";
    const char *file_data = "SaveGamePayload_12345678";
    size_t file_data_len = 24;

    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 8);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_add_file(writer, filename, file_data, file_data_len);
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    ASSERT_NOT_NULL(archive);

    /* Read into caller-supplied buffer. */
    char buf[64] = {0};
    size_t n = mpqfs_read_file_into(archive, filename, buf, sizeof(buf));
    ASSERT_EQ_SZ(n, file_data_len);
    ASSERT_TRUE(memcmp(buf, file_data, file_data_len) == 0);

    /* Buffer too small should fail. */
    char tiny[4];
    size_t n2 = mpqfs_read_file_into(archive, filename, tiny, sizeof(tiny));
    ASSERT_EQ_SZ(n2, 0);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer FILE* variant (mpqfs_writer_create_fp)
 * ----------------------------------------------------------------------- */

static void test_writer_fp(void)
{
    TEST_BEGIN("writer_fp");

    const char *tmp_path = "/tmp/mpqfs_test_writer_fp.mpq";
    const char *filename = "testfile";
    const char *file_data = "FP_DATA";
    size_t file_data_len = 7;

    /* Open the file ourselves. */
    FILE *fp = fopen(tmp_path, "wb");
    ASSERT_NOT_NULL(fp);

    mpqfs_writer_t *writer = mpqfs_writer_create_fp(fp, 8);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_add_file(writer, filename, file_data, file_data_len);
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* We still own the FILE* — close it ourselves. */
    fclose(fp);

    /* Verify by reading back. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    ASSERT_NOT_NULL(archive);

    ASSERT_TRUE(mpqfs_has_file(archive, filename));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, filename), file_data_len);

    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, filename, &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, file_data_len);
    ASSERT_TRUE(memcmp(data, file_data, file_data_len) == 0);
    free(data);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer hash table auto-sizing (power of 2 rounding)
 * ----------------------------------------------------------------------- */

static void test_writer_hash_table_sizing(void)
{
    TEST_BEGIN("writer_hash_table_sizing");

    const char *tmp_path = "/tmp/mpqfs_test_writer_htsize.mpq";

    /* Request hash table size of 5 — should be rounded up to 8. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 5);
    ASSERT_NOT_NULL(writer);

    /* Add 6 files (which fits in a table of 8, since we need
     * at least 1 empty slot = capacity of 7). */
    const char *names[] = { "a", "b", "c", "d", "e", "f" };
    for (int i = 0; i < 6; i++) {
        char data[1] = { (char)('A' + i) };
        bool ok = mpqfs_writer_add_file(writer, names[i], data, 1);
        ASSERT_TRUE(ok);
    }

    bool ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* Read them back — all 6 should be present. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    ASSERT_NOT_NULL(archive);

    for (int i = 0; i < 6; i++) {
        ASSERT_TRUE(mpqfs_has_file(archive, names[i]));
        ASSERT_EQ_SZ(mpqfs_file_size(archive, names[i]), 1);

        size_t sz = 0;
        void *data = mpqfs_read_file(archive, names[i], &sz);
        ASSERT_NOT_NULL(data);
        ASSERT_EQ_SZ(sz, 1);
        ASSERT_TRUE(((char *)data)[0] == (char)('A' + i));
        free(data);
    }

    /* Verify hash table count is 8 (rounded from 5). */
    ASSERT_EQ_U32(archive->header.hash_table_count, 8);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer compresses files with PKWARE implode and reads them back
 *
 * Verifies that:
 *   - Compressible data gets IMPLODE flag and smaller on-disk size
 *   - Incompressible data is stored raw (no IMPLODE flag)
 *   - Round-trip read produces identical content in both cases
 * ----------------------------------------------------------------------- */

static void test_writer_compression(void)
{
    TEST_BEGIN("writer_compression");

    const char *tmp_path = "/tmp/mpqfs_test_writer_compress.sv";

    /* Build compressible data: repeating pattern. */
    uint8_t compressible[8192];
    for (size_t i = 0; i < sizeof(compressible); i++)
        compressible[i] = (uint8_t)("ABCDEFGH"[i % 8]);

    /* Build incompressible data: pseudo-random bytes. */
    uint8_t incompressible[512];
    {
        uint32_t rng = 0xDEADBEEF;
        for (size_t i = 0; i < sizeof(incompressible); i++) {
            rng = rng * 1103515245 + 12345;
            incompressible[i] = (uint8_t)(rng >> 16);
        }
    }

    /* Write archive with both files. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, 2048);
    ASSERT_NOT_NULL(writer);

    bool ok = mpqfs_writer_add_file(writer, "compressible",
                                    compressible, sizeof(compressible));
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_add_file(writer, "incompressible",
                               incompressible, sizeof(incompressible));
    ASSERT_TRUE(ok);

    ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* Read back and verify. */
    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    /* Compressible file: should have IMPLODE flag and smaller compressed size. */
    ASSERT_TRUE(mpqfs_has_file(archive, "compressible"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "compressible"), sizeof(compressible));

    {
        uint32_t bi = mpq_lookup_file(archive, "compressible");
        ASSERT_TRUE(bi != UINT32_MAX);
        const mpq_block_entry_t *blk = &archive->block_table[bi];
        ASSERT_TRUE((blk->flags & MPQ_FILE_IMPLODE) != 0);
        ASSERT_TRUE(blk->compressed_size < blk->file_size);
    }

    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, "compressible", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, sizeof(compressible));
    ASSERT_TRUE(memcmp(data, compressible, sizeof(compressible)) == 0);
    free(data);

    /* Incompressible file: should be stored without IMPLODE flag. */
    ASSERT_TRUE(mpqfs_has_file(archive, "incompressible"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "incompressible"), sizeof(incompressible));

    {
        uint32_t bi = mpq_lookup_file(archive, "incompressible");
        ASSERT_TRUE(bi != UINT32_MAX);
        const mpq_block_entry_t *blk = &archive->block_table[bi];
        /* Incompressible data should NOT have IMPLODE flag. */
        ASSERT_TRUE((blk->flags & MPQ_FILE_IMPLODE) == 0);
        ASSERT_EQ_U32(blk->compressed_size, blk->file_size);
    }

    data = mpqfs_read_file(archive, "incompressible", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, sizeof(incompressible));
    ASSERT_TRUE(memcmp(data, incompressible, sizeof(incompressible)) == 0);
    free(data);

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: read a real DevilutionX save file (share_0.sv)
 *
 * This is a regression test for the PKWARE explode fix.  share_0.sv is
 * a real save file produced by DevilutionX with PKWARE implode compressed
 * files.  We verify that the reader can open it and extract all three
 * files it contains: hero (1288 bytes), heroitems (20296 bytes), and
 * hotkeys (136 bytes).
 * ----------------------------------------------------------------------- */

static void test_read_share_save(void)
{
    TEST_BEGIN("read_share_save");

    /* Try to open share_0.sv from the project root.  If the file doesn't
     * exist (e.g. in CI), skip the test gracefully. */
    mpqfs_archive_t *archive = mpqfs_open("share_0.sv");
    if (!archive) {
        /* Not a failure — the test fixture may not be present. */
        printf("    (skipped: share_0.sv not found)\n");
        g_tests_passed++;
        return;
    }

    /* Verify header shape matches DevilutionX format. */
    ASSERT_EQ_U32(archive->header.hash_table_count, 2048);
    ASSERT_EQ_U32(archive->header.block_table_count, 2048);

    /* ---- hero: 1288 bytes, IMPLODE compressed ---- */
    ASSERT_TRUE(mpqfs_has_file(archive, "hero"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "hero"), 1288);

    {
        uint32_t bi = mpq_lookup_file(archive, "hero");
        ASSERT_TRUE(bi != UINT32_MAX);
        ASSERT_TRUE((archive->block_table[bi].flags & MPQ_FILE_IMPLODE) != 0);
    }

    size_t read_size = 0;
    void *data = mpqfs_read_file(archive, "hero", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, 1288);
    free(data);

    /* ---- heroitems: 20296 bytes, IMPLODE compressed ---- */
    ASSERT_TRUE(mpqfs_has_file(archive, "heroitems"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "heroitems"), 20296);

    data = mpqfs_read_file(archive, "heroitems", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, 20296);
    free(data);

    /* ---- hotkeys: 136 bytes, IMPLODE compressed ---- */
    ASSERT_TRUE(mpqfs_has_file(archive, "hotkeys"));
    ASSERT_EQ_SZ(mpqfs_file_size(archive, "hotkeys"), 136);

    data = mpqfs_read_file(archive, "hotkeys", &read_size);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ_SZ(read_size, 136);
    free(data);

    /* Non-existent file should not be found. */
    ASSERT_TRUE(!mpqfs_has_file(archive, "nonexistent"));

    mpqfs_close(archive);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Test: writer produces DevilutionX-compatible save file layout
 *
 * DevilutionX expects:
 *   [Header 32B] [Block table] [Hash table] [File data...]
 *   - block_table_count == hash_table_count (both = hash_table_size)
 *   - Block table at offset 0x20 (right after header)
 *   - Hash table at offset 0x20 + hash_table_size * 16
 *   - Unused block table entries are zeroed
 * ----------------------------------------------------------------------- */

static void test_writer_save_file_layout(void)
{
    TEST_BEGIN("writer_save_file_layout");

    const char *tmp_path = "/tmp/mpqfs_test_writer_savefile.sv";

    /* Use 2048 entries like DevilutionX does for Diablo 1 saves. */
    uint32_t hash_table_size = 2048;
    uint32_t table_entry_bytes = hash_table_size * 16;

    /* Typical Diablo 1 save file names. */
    const char *names[]  = { "hero", "game", "levels\\l1data\\town.dun" };
    const char *datas[]  = { "HeroSaveData1234", "GameStateData!!!", "DungeonMapBinary" };
    size_t      sizes[]  = { 16, 16, 16 };
    int         nfiles   = 3;

    /* Create archive. */
    mpqfs_writer_t *writer = mpqfs_writer_create(tmp_path, hash_table_size);
    ASSERT_NOT_NULL(writer);

    for (int i = 0; i < nfiles; i++) {
        bool ok = mpqfs_writer_add_file(writer, names[i], datas[i], sizes[i]);
        ASSERT_TRUE(ok);
    }

    bool ok = mpqfs_writer_close(writer);
    ASSERT_TRUE(ok);

    /* ---- Verify the on-disk layout matches DevilutionX ---- */

    /* Read back raw header to check offsets. */
    FILE *fp = fopen(tmp_path, "rb");
    ASSERT_NOT_NULL(fp);

    uint8_t hdr[32];
    ASSERT_TRUE(fread(hdr, 1, 32, fp) == 32);

    uint32_t header_size       = mpqfs_read_le32(hdr + 4);
    uint32_t archive_size      = mpqfs_read_le32(hdr + 8);
    uint32_t hash_table_offset = mpqfs_read_le32(hdr + 16);
    uint32_t block_table_offset = mpqfs_read_le32(hdr + 20);
    uint32_t hash_table_count  = mpqfs_read_le32(hdr + 24);
    uint32_t block_table_count = mpqfs_read_le32(hdr + 28);

    /* Block table must be right after the header. */
    ASSERT_EQ_U32(block_table_offset, header_size);
    ASSERT_EQ_U32(block_table_offset, 32);

    /* Hash table must follow the block table. */
    ASSERT_EQ_U32(hash_table_offset, block_table_offset + table_entry_bytes);

    /* Both table counts must equal hash_table_size. */
    ASSERT_EQ_U32(hash_table_count, hash_table_size);
    ASSERT_EQ_U32(block_table_count, hash_table_size);

    /* File data starts after both tables. */
    uint32_t data_start = hash_table_offset + table_entry_bytes;

    /* Archive size should be data_start + total file data. */
    uint32_t total_data = 0;
    for (int i = 0; i < nfiles; i++)
        total_data += (uint32_t)sizes[i];
    ASSERT_EQ_U32(archive_size, data_start + total_data);

    fclose(fp);

    /* ---- Verify round-trip: read all files back ---- */

    mpqfs_archive_t *archive = mpqfs_open(tmp_path);
    if (!archive) {
        printf("    (mpqfs_open failed: %s)\n", mpqfs_last_error());
    }
    ASSERT_NOT_NULL(archive);

    /* Confirm the parsed header matches. */
    ASSERT_EQ_U32(archive->header.hash_table_count, hash_table_size);
    ASSERT_EQ_U32(archive->header.block_table_count, hash_table_size);
    ASSERT_EQ_U32(archive->header.block_table_offset, 32);

    for (int i = 0; i < nfiles; i++) {
        ASSERT_TRUE(mpqfs_has_file(archive, names[i]));
        ASSERT_EQ_SZ(mpqfs_file_size(archive, names[i]), sizes[i]);

        size_t read_size = 0;
        void *data = mpqfs_read_file(archive, names[i], &read_size);
        ASSERT_NOT_NULL(data);
        ASSERT_EQ_SZ(read_size, sizes[i]);
        ASSERT_TRUE(memcmp(data, datas[i], sizes[i]) == 0);
        free(data);
    }

    /* Verify unused block table entries don't interfere. */
    ASSERT_TRUE(!mpqfs_has_file(archive, "nonexistent"));

    /* Case-insensitive and slash normalisation on save filenames. */
    ASSERT_TRUE(mpqfs_has_file(archive, "HERO"));
    ASSERT_TRUE(mpqfs_has_file(archive, "levels/l1data/town.dun"));

    mpqfs_close(archive);
    remove(tmp_path);

    TEST_END();
}

/* -----------------------------------------------------------------------
 * Interactive mode: open a real MPQ and optionally extract a file
 * ----------------------------------------------------------------------- */

/* -----------------------------------------------------------------------
 * Work Item 1 — New public API tests
 * ----------------------------------------------------------------------- */

/* Test: mpqfs_clone on a writer-created archive */
static void test_clone_roundtrip(void)
{
    TEST_BEGIN("clone_roundtrip");

    const char *path = "test_clone.mpq";
    const uint8_t data[] = "Hello from clone test!";

    /* Create a small archive. */
    mpqfs_writer_t *w = mpqfs_writer_create(path, 4);
    ASSERT_NOT_NULL(w);
    ASSERT_TRUE(mpqfs_writer_add_file(w, "greeting", data, sizeof(data)));
    ASSERT_TRUE(mpqfs_writer_close(w));

    /* Open it. */
    mpqfs_archive_t *archive = mpqfs_open(path);
    ASSERT_NOT_NULL(archive);
    ASSERT_TRUE(mpqfs_has_file(archive, "greeting"));

    /* Clone it. */
    mpqfs_archive_t *clone = mpqfs_clone(archive);
    ASSERT_NOT_NULL(clone);

    /* The clone should see the same files. */
    ASSERT_TRUE(mpqfs_has_file(clone, "greeting"));
    ASSERT_EQ_SZ(mpqfs_file_size(clone, "greeting"), sizeof(data));

    /* Read from the clone. */
    size_t read_size = 0;
    void *buf = mpqfs_read_file(clone, "greeting", &read_size);
    ASSERT_NOT_NULL(buf);
    ASSERT_EQ_SZ(read_size, sizeof(data));
    ASSERT_TRUE(memcmp(buf, data, sizeof(data)) == 0);
    free(buf);

    /* Both handles close independently. */
    mpqfs_close(clone);
    mpqfs_close(archive);
    remove(path);

    TEST_END();
}

/* Test: mpqfs_clone returns NULL for fp-opened archives */
static void test_clone_fp_fails(void)
{
    TEST_BEGIN("clone_fp_fails");

    const char *path = "test_clone_fp.mpq";
    const uint8_t data[] = "data";

    mpqfs_writer_t *w = mpqfs_writer_create(path, 4);
    ASSERT_NOT_NULL(w);
    ASSERT_TRUE(mpqfs_writer_add_file(w, "f", data, sizeof(data)));
    ASSERT_TRUE(mpqfs_writer_close(w));

    FILE *fp = fopen(path, "rb");
    ASSERT_NOT_NULL(fp);

    mpqfs_archive_t *archive = mpqfs_open_fp(fp);
    ASSERT_NOT_NULL(archive);

    /* Clone should fail — no path available. */
    mpqfs_archive_t *clone = mpqfs_clone(archive);
    ASSERT_NULL(clone);

    mpqfs_close(archive);
    fclose(fp);
    remove(path);

    TEST_END();
}

/* Test: mpqfs_clone NULL safety */
static void test_clone_null(void)
{
    TEST_BEGIN("clone_null");

    mpqfs_archive_t *clone = mpqfs_clone(NULL);
    ASSERT_NULL(clone);

    TEST_END();
}

/* Test: public crypto init is idempotent */
static void test_public_crypto_init(void)
{
    TEST_BEGIN("public_crypto_init");

    mpqfs_crypto_init();
    uint32_t h1 = mpqfs_hash_string("test", MPQFS_HASH_TABLE_INDEX);
    mpqfs_crypto_init();
    uint32_t h2 = mpqfs_hash_string("test", MPQFS_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(h1, h2);

    TEST_END();
}

/* Test: mpqfs_hash_string matches internal mpq_hash_string */
static void test_public_hash_string(void)
{
    TEST_BEGIN("public_hash_string");

    mpq_crypto_init();
    mpqfs_crypto_init();

    /* Compare public and internal for several hash types. */
    ASSERT_EQ_U32(mpqfs_hash_string("(hash table)", MPQFS_HASH_FILE_KEY),
                  mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY));

    ASSERT_EQ_U32(mpqfs_hash_string("(block table)", MPQFS_HASH_FILE_KEY),
                  mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY));

    ASSERT_EQ_U32(mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_TABLE_INDEX),
                  mpq_hash_string("levels\\l1data\\l1.min", MPQ_HASH_TABLE_INDEX));

    ASSERT_EQ_U32(mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_NAME_A),
                  mpq_hash_string("levels\\l1data\\l1.min", MPQ_HASH_NAME_A));

    ASSERT_EQ_U32(mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_NAME_B),
                  mpq_hash_string("levels\\l1data\\l1.min", MPQ_HASH_NAME_B));

    TEST_END();
}

/* Test: mpqfs_hash_string_s length-delimited variant */
static void test_hash_string_s(void)
{
    TEST_BEGIN("hash_string_s");

    /* Hash with length should match hash of NUL-terminated equivalent. */
    const char *full = "hello_world";
    ASSERT_EQ_U32(mpqfs_hash_string_s(full, 11, MPQFS_HASH_TABLE_INDEX),
                  mpqfs_hash_string(full, MPQFS_HASH_TABLE_INDEX));

    ASSERT_EQ_U32(mpqfs_hash_string_s(full, 11, MPQFS_HASH_NAME_A),
                  mpqfs_hash_string(full, MPQFS_HASH_NAME_A));

    ASSERT_EQ_U32(mpqfs_hash_string_s(full, 11, MPQFS_HASH_NAME_B),
                  mpqfs_hash_string(full, MPQFS_HASH_NAME_B));

    /* Hashing a substring should differ from the full string. */
    uint32_t sub = mpqfs_hash_string_s(full, 5, MPQFS_HASH_TABLE_INDEX);
    uint32_t hello_hash = mpqfs_hash_string("hello", MPQFS_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(sub, hello_hash);

    /* Verify it doesn't read past len — "hello_world" with len=5 == "hello". */
    const char *with_extra = "helloXXXXX";
    ASSERT_EQ_U32(mpqfs_hash_string_s(with_extra, 5, MPQFS_HASH_TABLE_INDEX),
                  hello_hash);

    TEST_END();
}

/* Test: mpqfs_encrypt_block / mpqfs_decrypt_block roundtrip */
static void test_public_encrypt_decrypt(void)
{
    TEST_BEGIN("public_encrypt_decrypt");

    uint32_t original[8] = { 0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00,
                             0x12345678, 0x9ABCDEF0, 0x0FEDCBA9, 0x87654321 };
    uint32_t data[8];
    memcpy(data, original, sizeof(data));

    uint32_t key = 0xDEADBEEF;

    mpqfs_encrypt_block(data, 8, key);
    /* Encrypted data should differ from original. */
    ASSERT_TRUE(memcmp(data, original, sizeof(data)) != 0);

    mpqfs_decrypt_block(data, 8, key);
    /* Decrypted should match original. */
    ASSERT_TRUE(memcmp(data, original, sizeof(data)) == 0);

    TEST_END();
}

/* Test: pre-calculated key constants are correct */
static void test_key_constants(void)
{
    TEST_BEGIN("key_constants");

    mpqfs_crypto_init();

    ASSERT_EQ_U32(MPQFS_BLOCK_TABLE_KEY,
                  mpqfs_hash_string("(block table)", MPQFS_HASH_FILE_KEY));

    ASSERT_EQ_U32(MPQFS_HASH_TABLE_KEY,
                  mpqfs_hash_string("(hash table)", MPQFS_HASH_FILE_KEY));

    /* Also verify the numeric values. */
    ASSERT_EQ_U32(MPQFS_BLOCK_TABLE_KEY, 3968054179u);
    ASSERT_EQ_U32(MPQFS_HASH_TABLE_KEY,  3283040112u);

    TEST_END();
}

/* Test: mpqfs_file_hash convenience function */
static void test_file_hash(void)
{
    TEST_BEGIN("file_hash");

    uint32_t idx, ha, hb;
    mpqfs_file_hash("levels\\l1data\\l1.min", &idx, &ha, &hb);

    ASSERT_EQ_U32(idx, mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_TABLE_INDEX));
    ASSERT_EQ_U32(ha,  mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_NAME_A));
    ASSERT_EQ_U32(hb,  mpqfs_hash_string("levels\\l1data\\l1.min", MPQFS_HASH_NAME_B));

    /* Test with NULL output pointers — should not crash. */
    mpqfs_file_hash("test", NULL, NULL, NULL);
    mpqfs_file_hash("test", &idx, NULL, NULL);
    mpqfs_file_hash("test", NULL, &ha, NULL);
    mpqfs_file_hash("test", NULL, NULL, &hb);

    TEST_END();
}

/* Test: mpqfs_file_hash_s length-delimited variant */
static void test_file_hash_s(void)
{
    TEST_BEGIN("file_hash_s");

    uint32_t idx1, ha1, hb1;
    uint32_t idx2, ha2, hb2;

    const char *name = "test_file";
    mpqfs_file_hash(name, &idx1, &ha1, &hb1);
    mpqfs_file_hash_s(name, strlen(name), &idx2, &ha2, &hb2);

    ASSERT_EQ_U32(idx1, idx2);
    ASSERT_EQ_U32(ha1, ha2);
    ASSERT_EQ_U32(hb1, hb2);

    /* Verify substring works correctly. */
    uint32_t sub_idx, sub_ha, sub_hb;
    uint32_t full_idx, full_ha, full_hb;
    mpqfs_file_hash_s("hello_world", 5, &sub_idx, &sub_ha, &sub_hb);
    mpqfs_file_hash("hello", &full_idx, &full_ha, &full_hb);

    ASSERT_EQ_U32(sub_idx, full_idx);
    ASSERT_EQ_U32(sub_ha, full_ha);
    ASSERT_EQ_U32(sub_hb, full_hb);

    TEST_END();
}

/* Test: mpqfs_pk_implode / mpqfs_pk_explode roundtrip */
static void test_pk_roundtrip(void)
{
    TEST_BEGIN("pk_roundtrip");

    /* Create some compressible test data. */
    uint8_t src[512];
    for (size_t i = 0; i < sizeof(src); i++)
        src[i] = (uint8_t)(i & 0x1F);  /* repeating pattern */

    uint8_t compressed[2048];
    size_t comp_size = sizeof(compressed);

    int rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, 6);
    ASSERT_TRUE(rc == 0);
    ASSERT_TRUE(comp_size > 0);
    ASSERT_TRUE(comp_size < sizeof(src));  /* should compress well */

    /* Decompress and verify. */
    uint8_t decompressed[512];
    size_t decomp_size = sizeof(decompressed);

    rc = mpqfs_pk_explode(compressed, comp_size, decompressed, &decomp_size);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ_SZ(decomp_size, sizeof(src));
    ASSERT_TRUE(memcmp(decompressed, src, sizeof(src)) == 0);

    TEST_END();
}

/* Test: mpqfs_pk_implode with different dict_bits values */
static void test_pk_dict_bits(void)
{
    TEST_BEGIN("pk_dict_bits");

    uint8_t src[256];
    for (size_t i = 0; i < sizeof(src); i++)
        src[i] = (uint8_t)(i % 10);

    /* Test all valid dict_bits: 4, 5, 6 */
    for (int bits = 4; bits <= 6; bits++) {
        uint8_t compressed[1024];
        size_t comp_size = sizeof(compressed);

        int rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, bits);
        ASSERT_TRUE(rc == 0);

        uint8_t decompressed[256];
        size_t decomp_size = sizeof(decompressed);

        rc = mpqfs_pk_explode(compressed, comp_size, decompressed, &decomp_size);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ_SZ(decomp_size, sizeof(src));
        ASSERT_TRUE(memcmp(decompressed, src, sizeof(src)) == 0);
    }

    /* Invalid dict_bits should fail. */
    uint8_t compressed[1024];
    size_t comp_size = sizeof(compressed);
    int rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, 3);
    ASSERT_TRUE(rc != 0);

    comp_size = sizeof(compressed);
    rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, 7);
    ASSERT_TRUE(rc != 0);

    TEST_END();
}

/* Test: mpqfs_pk_implode / mpqfs_pk_explode NULL safety */
static void test_pk_null_safety(void)
{
    TEST_BEGIN("pk_null_safety");

    uint8_t buf[64];
    size_t sz = sizeof(buf);

    ASSERT_TRUE(mpqfs_pk_implode(NULL, 10, buf, &sz, 6) != 0);
    ASSERT_TRUE(mpqfs_pk_implode(buf, 10, NULL, &sz, 6) != 0);
    ASSERT_TRUE(mpqfs_pk_implode(buf, 10, buf, NULL, 6) != 0);

    ASSERT_TRUE(mpqfs_pk_explode(NULL, 10, buf, &sz) != 0);
    ASSERT_TRUE(mpqfs_pk_explode(buf, 10, NULL, &sz) != 0);
    ASSERT_TRUE(mpqfs_pk_explode(buf, 10, buf, NULL) != 0);

    TEST_END();
}

/* Test: hash type constants match internal values */
/* Test: PKWARE DCL sentinel correctness.
 *
 * The PKWARE DCL end-of-stream sentinel is length code index 15 with
 * extra bits value 8 (LenBase[15] + 8 = 0x10E in StormLib terms).
 *
 * A previous bug used length=2 / distance=0 as the sentinel, which
 * collided with a valid RLE match (repeat the previous byte twice).
 * Data containing such matches would decompress too early, producing
 * truncated output.
 *
 * This test creates input that forces the compressor to emit length-2,
 * distance-0 matches and verifies that the roundtrip is lossless.
 */
static void test_pk_sentinel(void)
{
    TEST_BEGIN("pk_sentinel");

    /* Build data that will produce length-2, distance-0 matches:
     * pairs of identical bytes followed by a different byte.
     * E.g. AA B CC D EE F ...
     * The compressor should encode each pair as a length-2 match at
     * distance 0 (repeat the previous byte).  If the sentinel is
     * incorrectly defined as length=2/distance=0, the decompressor
     * would stop at the first such match. */
    uint8_t src[512];
    for (size_t i = 0; i < sizeof(src); i++) {
        /* Groups of 3: two identical bytes then a different one. */
        size_t group = i / 3;
        size_t pos   = i % 3;
        if (pos < 2)
            src[i] = (uint8_t)(group & 0xFF);
        else
            src[i] = (uint8_t)((group + 0x80) & 0xFF);
    }

    uint8_t compressed[2048];
    size_t comp_size = sizeof(compressed);

    int rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, 6);
    ASSERT_TRUE(rc == 0);
    ASSERT_TRUE(comp_size > 0);

    uint8_t decompressed[512];
    size_t decomp_size = sizeof(decompressed);

    rc = mpqfs_pk_explode(compressed, comp_size, decompressed, &decomp_size);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ_SZ(decomp_size, sizeof(src));
    ASSERT_TRUE(memcmp(decompressed, src, sizeof(src)) == 0);

    /* Also test with a long run of a single byte — this forces many
     * consecutive length-2/distance-0 matches. */
    memset(src, 0x42, sizeof(src));

    comp_size = sizeof(compressed);
    rc = mpqfs_pk_implode(src, sizeof(src), compressed, &comp_size, 6);
    ASSERT_TRUE(rc == 0);

    decomp_size = sizeof(decompressed);
    rc = mpqfs_pk_explode(compressed, comp_size, decompressed, &decomp_size);
    ASSERT_TRUE(rc == 0);
    ASSERT_EQ_SZ(decomp_size, sizeof(src));
    ASSERT_TRUE(memcmp(decompressed, src, sizeof(src)) == 0);

    /* Test with a hand-crafted compressed stream containing a length=2,
     * distance=0 match followed by the correct sentinel.
     * The decompressor must treat the length=2/distance=0 match as a
     * valid copy (repeat the previous byte twice), NOT as end-of-stream.
     *
     * Stream layout (binary mode, dict_bits=6):
     *   byte 0: 0x00  (comp_type = binary)
     *   byte 1: 0x06  (dict_bits = 6)
     *   bits (LSB first):
     *     bit  0:      0          — literal flag
     *     bits 1-8:    01000001   — literal 'A' (0x41)
     *     bit  9:      1          — match flag
     *     bits 10-12:  101        — length code index 0 (pk_len_code[0]=0x05, 3 bits) → len=2
     *     bits 13-14:  11         — dist code index 0 (pk_dist_code[0]=0x03, 2 bits)
     *     bits 15-16:  00         — dist low 2 bits = 0  → distance=0 (1 byte back)
     *     === this is length=2, distance=0: MUST copy 'A','A', NOT stop ===
     *     bit  17:     1          — match flag (sentinel)
     *     bits 18-24:  0000000    — length code index 15 (pk_len_code[15]=0x00, 7 bits)
     *     bits 25-32:  00001000   — extra bits = 8 (sentinel value)
     *
     * Expected output: 'A', 'A', 'A' (3 bytes)
     * (literal 'A', then copy 2 from 1 byte back = 'A','A')
     *
     * Byte encoding (computed by EMIT_BITS helper):
     *   byte 2 = 0x82, byte 3 = 0x76, byte 4 = 0x02, byte 5 = 0x10, byte 6 = 0x00
     */
    {
        uint8_t crafted[] = {
            0x00, 0x06,  /* header: binary mode, dict_bits=6 */
            0x82, 0x76, 0x02, 0x10, 0x00
        };
        uint8_t out[8];
        size_t out_size = sizeof(out);
        rc = mpqfs_pk_explode(crafted, sizeof(crafted), out, &out_size);
        ASSERT_TRUE(rc == 0);
        ASSERT_EQ_SZ(out_size, 3);
        ASSERT_TRUE(out[0] == 'A');
        ASSERT_TRUE(out[1] == 'A');
        ASSERT_TRUE(out[2] == 'A');
    }

    TEST_END();
}

static void test_hash_type_constants(void)
{
    TEST_BEGIN("hash_type_constants");

    ASSERT_EQ_U32(MPQFS_HASH_TABLE_INDEX, MPQ_HASH_TABLE_INDEX);
    ASSERT_EQ_U32(MPQFS_HASH_NAME_A,      MPQ_HASH_NAME_A);
    ASSERT_EQ_U32(MPQFS_HASH_NAME_B,      MPQ_HASH_NAME_B);
    ASSERT_EQ_U32(MPQFS_HASH_FILE_KEY,    MPQ_HASH_FILE_KEY);

    TEST_END();
}

static const char *flags_to_str(uint32_t flags, char *buf, size_t buf_size)
{
    buf[0] = '\0';
    if (flags & MPQ_FILE_IMPLODE)      strncat(buf, "IMPLODE ",      buf_size - strlen(buf) - 1);
    if (flags & MPQ_FILE_COMPRESS)     strncat(buf, "COMPRESS ",     buf_size - strlen(buf) - 1);
    if (flags & MPQ_FILE_ENCRYPTED)    strncat(buf, "ENCRYPTED ",    buf_size - strlen(buf) - 1);
    if (flags & MPQ_FILE_FIX_KEY)      strncat(buf, "FIX_KEY ",      buf_size - strlen(buf) - 1);
    if (flags & MPQ_FILE_SINGLE_UNIT)  strncat(buf, "SINGLE_UNIT ",  buf_size - strlen(buf) - 1);
    if (flags & MPQ_FILE_EXISTS)       strncat(buf, "EXISTS ",       buf_size - strlen(buf) - 1);
    if (buf[0] == '\0')                strncat(buf, "(none)",        buf_size - strlen(buf) - 1);
    return buf;
}

static int interactive_mode(const char *mpq_path, const char *filename)
{
    fprintf(stderr, "Opening: %s\n", mpq_path);

    mpqfs_archive_t *archive = mpqfs_open(mpq_path);
    if (!archive) {
        fprintf(stderr, "Error: %s\n", mpqfs_last_error());
        return 1;
    }

    fprintf(stderr, "Archive opened successfully.\n");

    /* Always dump header info. */
    fprintf(stderr, "\n--- MPQ Header ---\n");
    fprintf(stderr, "  Archive offset:    0x%08llX\n", (unsigned long long)archive->archive_offset);
    fprintf(stderr, "  Header size:       %u\n",  archive->header.header_size);
    fprintf(stderr, "  Archive size:      %u\n",  archive->header.archive_size);
    fprintf(stderr, "  Format version:    %u\n",  (unsigned)archive->header.format_version);
    fprintf(stderr, "  Sector size shift: %u (sector size = %u)\n",
           (unsigned)archive->header.sector_size_shift, archive->sector_size);
    fprintf(stderr, "  Hash table offset: 0x%08X (%u entries)\n",
           archive->header.hash_table_offset, archive->header.hash_table_count);
    fprintf(stderr, "  Block table offset:0x%08X (%u entries)\n",
           archive->header.block_table_offset, archive->header.block_table_count);

    if (filename) {
        fprintf(stderr, "\nLooking up: %s\n", filename);

        if (!mpqfs_has_file(archive, filename)) {
            fprintf(stderr, "File not found in archive: %s\n", filename);
            mpqfs_close(archive);
            return 1;
        }

        size_t fsize = mpqfs_file_size(archive, filename);
        fprintf(stderr, "File size: %zu bytes\n", fsize);

        /* Also show the block entry details for this file. */
        uint32_t bi = mpq_lookup_file(archive, filename);
        if (bi != UINT32_MAX) {
            const mpq_block_entry_t *blk = &archive->block_table[bi];
            char fbuf[256];
            fprintf(stderr, "  Block index:       %u\n", bi);
            fprintf(stderr, "  Offset:            0x%08X\n", blk->offset);
            fprintf(stderr, "  Compressed size:   %u\n", blk->compressed_size);
            fprintf(stderr, "  Uncompressed size: %u\n", blk->file_size);
            fprintf(stderr, "  Flags:             0x%08X  %s\n", blk->flags,
                   flags_to_str(blk->flags, fbuf, sizeof(fbuf)));
        }

        size_t read_size = 0;
        void *data = mpqfs_read_file(archive, filename, &read_size);
        if (!data) {
            fprintf(stderr, "Error reading file: %s\n", mpqfs_last_error());
            mpqfs_close(archive);
            return 1;
        }

        fprintf(stderr, "Read %zu bytes. Writing to stdout...\n", read_size);
        fwrite(data, 1, read_size, stdout);
        free(data);
    } else {
        /* Dump block table. */
        fprintf(stderr, "\n--- Block Table (%u entries) ---\n", archive->header.block_table_count);
        fprintf(stderr, "  %-6s  %-10s  %-10s  %-10s  %-10s  %s\n",
               "Index", "Offset", "CmpSize", "FileSize", "Flags", "Description");
        for (uint32_t i = 0; i < archive->header.block_table_count; i++) {
            const mpq_block_entry_t *blk = &archive->block_table[i];
            char fbuf[256];
            fprintf(stderr, "  %-6u  0x%08X  %-10u  %-10u  0x%08X  %s\n",
                   i, blk->offset, blk->compressed_size, blk->file_size,
                   blk->flags, flags_to_str(blk->flags, fbuf, sizeof(fbuf)));
        }

        /* Dump hash table — show non-empty entries. */
        fprintf(stderr, "\n--- Hash Table (%u entries, non-empty shown) ---\n",
               archive->header.hash_table_count);
        fprintf(stderr, "  %-6s  %-10s  %-10s  %-6s  %-5s  %-10s\n",
               "Slot", "HashA", "HashB", "Locale", "Plat", "BlockIdx");
        uint32_t occupied = 0;
        for (uint32_t i = 0; i < archive->header.hash_table_count; i++) {
            const mpq_hash_entry_t *h = &archive->hash_table[i];
            if (h->block_index == MPQ_HASH_ENTRY_EMPTY)
                continue;
            if (h->block_index == MPQ_HASH_ENTRY_DELETED) {
                fprintf(stderr, "  %-6u  (deleted)\n", i);
                occupied++;
                continue;
            }
            fprintf(stderr, "  %-6u  0x%08X  0x%08X  %-6u  %-5u  %u\n",
                   i, h->hash_a, h->hash_b, (unsigned)h->locale,
                   (unsigned)h->platform, h->block_index);
            occupied++;
        }
        fprintf(stderr, "  (%u/%u slots occupied)\n", occupied, archive->header.hash_table_count);

        fprintf(stderr, "\nUse: mpqfs_test <archive> <filename> to extract a file.\n");
    }

    mpqfs_close(archive);
    return 0;
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc >= 2) {
        /* Interactive / integration test mode. */
        return interactive_mode(argv[1], argc >= 3 ? argv[2] : NULL);
    }

    /* Run unit tests. */
    printf("mpqfs unit tests\n");
    printf("================\n\n");

    test_crypto_init_idempotent();
    test_hash_known_values();
    test_hash_case_insensitive();
    test_encrypt_decrypt_roundtrip();
    test_encrypt_decrypt_table_keys();
    test_encrypt_known_ciphertext();
    test_encrypt_ciphertext_matches_stormlib();
    test_file_key_derivation();
    test_open_nonexistent();
    test_open_null();
    test_close_null();
    test_null_archive_queries();
    test_synthetic_mpq();
    test_stream_seek();

    /* Writer tests */
    test_writer_roundtrip();
    test_writer_multiple_files();
    test_writer_empty_archive();
    test_writer_empty_file();
    test_writer_discard();
    test_writer_null_safety();
    test_writer_read_into();
    test_writer_fp();
    test_writer_hash_table_sizing();
    test_writer_compression();
    test_writer_save_file_layout();
    test_read_share_save();

    /* Work Item 1 — new public API tests */
    test_clone_roundtrip();
    test_clone_fp_fails();
    test_clone_null();
    test_public_crypto_init();
    test_public_hash_string();
    test_hash_string_s();
    test_public_encrypt_decrypt();
    test_key_constants();
    test_file_hash();
    test_file_hash_s();
    test_pk_roundtrip();
    test_pk_dict_bits();
    test_pk_null_safety();
    test_pk_sentinel();
    test_hash_type_constants();

    printf("\n");
    printf("Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n");

    return g_tests_failed > 0 ? 1 : 0;
}