/*
 * mpqfs — minimal MPQ v1 reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Archive lifecycle: open, close, file lookup, and whole-file reads.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mpq_archive.h"
#include "mpq_crypto.h"
#include "mpq_fopen.h"
#include "mpq_platform.h"
#include "mpq_stream.h"
#include "mpqfs/mpqfs.h"

/* Portable strdup — avoids reliance on POSIX strdup() which may not be
 * declared in strict C99 mode on all toolchains. */
static char *MpqfsStrdup(const char *s)
{
	MPQFS_RET_CHECK(s, NULL);
	size_t len = strlen(s) + 1;
	char *copy = (char *)malloc(len);
	if (copy)
		memcpy(copy, s, len);
	return copy;
}

/* -----------------------------------------------------------------------
 * Header parsing
 * ----------------------------------------------------------------------- */

/*
 * Scan for the MPQ signature.  The archive may be embedded in another
 * file (e.g. an exe stub) — the header always appears on a 512-byte
 * boundary.  We scan up to 128 MiB.
 */
static int MpqFindHeader(FILE *fp, int64_t *outOffset)
{
	uint8_t buf[4];
	const int64_t maxSearch = 128LL * 1024 * 1024;

	for (int64_t off = 0; off < maxSearch; off += 512) {
		MPQFS_RET_CHECK(fseek(fp, (long)off, SEEK_SET) == 0, -1);
		MPQFS_RET_CHECK(fread(buf, 1, 4, fp) == 4, -1);
		if (mpqfs_read_le32(buf) == MPQ_SIGNATURE) {
			*outOffset = off;
			return 0;
		}
	}

	return -1;
}

static int MpqReadHeader(FILE *fp, int64_t archiveOffset,
    mpq_header_t *hdr)
{
	uint8_t raw[MPQ_HEADER_SIZE_V1];

	MPQFS_RET_CHECK(fseek(fp, (long)archiveOffset, SEEK_SET) == 0, -1);
	MPQFS_RET_CHECK(fread(raw, 1, MPQ_HEADER_SIZE_V1, fp) == MPQ_HEADER_SIZE_V1, -1);

	hdr->signature = mpqfs_read_le32(raw + 0);
	hdr->header_size = mpqfs_read_le32(raw + 4);
	hdr->archive_size = mpqfs_read_le32(raw + 8);
	hdr->format_version = mpqfs_read_le16(raw + 12);
	hdr->sector_size_shift = mpqfs_read_le16(raw + 14);
	hdr->hash_table_offset = mpqfs_read_le32(raw + 16);
	hdr->block_table_offset = mpqfs_read_le32(raw + 20);
	hdr->hash_table_count = mpqfs_read_le32(raw + 24);
	hdr->block_table_count = mpqfs_read_le32(raw + 28);

	MPQFS_RET_CHECK(hdr->signature == MPQ_SIGNATURE, -1);

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

static void MpqFixupLe32Array(uint32_t *data, size_t count) // NOLINT(readability-non-const-parameter)
{
#if MPQFS_BIG_ENDIAN
	for (size_t i = 0; i < count; i++)
		data[i] = mpqfs_le32(data[i]);
#else
	MPQFS_UNUSED(data);
	MPQFS_UNUSED(count);
#endif
}

static mpq_hash_entry_t *MpqLoadHashTable(FILE *fp,
    int64_t archiveOffset,
    const mpq_header_t *hdr)
{
	uint32_t count = hdr->hash_table_count;
	size_t bytes = (size_t)count * sizeof(mpq_hash_entry_t);

	mpq_hash_entry_t *table = (mpq_hash_entry_t *)malloc(bytes);
	MPQFS_RET_CHECK(table, NULL);

	int64_t absOffset = archiveOffset + (int64_t)hdr->hash_table_offset;
	if (MPQFS_UNLIKELY(fseek(fp, (long)absOffset, SEEK_SET) != 0)) {
		free(table);
		return NULL;
	}
	if (MPQFS_UNLIKELY(fread(table, 1, bytes, fp) != bytes)) {
		free(table);
		return NULL;
	}

	/* Byte-swap from LE on disk to native for decryption. */
	uint32_t dwordCount = count * 4;                          /* 16 bytes per entry = 4 dwords */
	MpqFixupLe32Array((uint32_t *)(void *)table, dwordCount); // NOLINT(bugprone-casting-through-void)

	/* Decrypt in-place. */
	uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
	mpq_decrypt_block((uint32_t *)(void *)table, dwordCount, key); // NOLINT(bugprone-casting-through-void)

	/* On BE, the decrypted values are now in native order — which is
	 * what we want for direct struct field access.  On LE they were
	 * already native.  No further swap needed. */

	return table;
}

static mpq_block_entry_t *MpqLoadBlockTable(FILE *fp,
    int64_t archiveOffset,
    const mpq_header_t *hdr)
{
	uint32_t count = hdr->block_table_count;
	size_t bytes = (size_t)count * sizeof(mpq_block_entry_t);

	mpq_block_entry_t *table = (mpq_block_entry_t *)malloc(bytes);
	MPQFS_RET_CHECK(table, NULL);

	int64_t absOffset = archiveOffset + (int64_t)hdr->block_table_offset;
	if (MPQFS_UNLIKELY(fseek(fp, (long)absOffset, SEEK_SET) != 0)) {
		free(table);
		return NULL;
	}
	if (MPQFS_UNLIKELY(fread(table, 1, bytes, fp) != bytes)) {
		free(table);
		return NULL;
	}

	uint32_t dwordCount = count * 4;
	MpqFixupLe32Array((uint32_t *)(void *)table, dwordCount); // NOLINT(bugprone-casting-through-void)

	uint32_t key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
	mpq_decrypt_block((uint32_t *)(void *)table, dwordCount, key); // NOLINT(bugprone-casting-through-void)

	return table;
}

/* -----------------------------------------------------------------------
 * File lookup
 * ----------------------------------------------------------------------- */

uint32_t mpq_lookup_hash_entry(const mpqfs_archive_t *archive, const char *filename)
{
	if (!archive || !filename)
		return UINT32_MAX;

	uint32_t hashCount = archive->header.hash_table_count;
	if (hashCount == 0)
		return UINT32_MAX;

	uint32_t index = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX) % hashCount;
	uint32_t nameA = mpq_hash_string(filename, MPQ_HASH_NAME_A);
	uint32_t nameB = mpq_hash_string(filename, MPQ_HASH_NAME_B);

	uint32_t start = index;

	for (;;) {
		const mpq_hash_entry_t *entry = &archive->hash_table[index];

		if (entry->block_index == MPQ_HASH_ENTRY_EMPTY) {
			/* End of probe chain — file does not exist. */
			return UINT32_MAX;
		}

		if (entry->block_index != MPQ_HASH_ENTRY_DELETED && entry->hash_a == nameA && entry->hash_b == nameB) {
			/* Match — validate block index range. */
			if (entry->block_index < archive->header.block_table_count)
				return index;

			return UINT32_MAX;
		}

		index = (index + 1) % hashCount;
		if (index == start) {
			/* Wrapped around — not found. */
			return UINT32_MAX;
		}
	}
}

uint32_t mpq_lookup_file(const mpqfs_archive_t *archive, const char *filename)
{
	uint32_t hash = mpq_lookup_hash_entry(archive, filename);
	if (hash == UINT32_MAX)
		return UINT32_MAX;
	return archive->hash_table[hash].block_index;
}

/* -----------------------------------------------------------------------
 * Internal: shared archive init after the FILE* is obtained
 * ----------------------------------------------------------------------- */

static mpqfs_error_code MpqInitArchive(FILE *fp, int ownsFd,
    mpqfs_archive_t **outArchive)
{
	*outArchive = NULL;

	mpqfs_archive_t *archive = (mpqfs_archive_t *)calloc(1, sizeof(*archive));
	if (MPQFS_UNLIKELY(!archive)) {
		fclose(fp);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	archive->fp = fp;
	archive->owns_fd = ownsFd;

	/* Locate the MPQ header. */
	if (MPQFS_UNLIKELY(MpqFindHeader(fp, &archive->archive_offset) != 0)) {
		fclose(fp);
		free(archive);
		return MPQFS_ERR_NOT_MPQ;
	}

	/* Read & validate header. */
	if (MPQFS_UNLIKELY(MpqReadHeader(fp, archive->archive_offset, &archive->header) != 0)) {
		fclose(fp);
		free(archive);
		return MPQFS_ERR_CORRUPT_ARCHIVE;
	}

	if (MPQFS_UNLIKELY(archive->header.format_version != 0)) {
		fclose(fp);
		free(archive);
		return MPQFS_ERR_UNSUPPORTED_VERSION;
	}

	archive->sector_size = 512U << archive->header.sector_size_shift;

	/* Load tables. */
	archive->hash_table = MpqLoadHashTable(fp, archive->archive_offset,
	    &archive->header);
	if (MPQFS_UNLIKELY(!archive->hash_table)) {
		fclose(fp);
		free(archive);
		return MPQFS_ERR_IO;
	}

	archive->block_table = MpqLoadBlockTable(fp, archive->archive_offset,
	    &archive->header);
	if (MPQFS_UNLIKELY(!archive->block_table)) {
		free(archive->hash_table);
		fclose(fp);
		free(archive);
		return MPQFS_ERR_IO;
	}

	*outArchive = archive;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: open / close
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_open(const char *path, mpqfs_archive_t **outArchive)
{
	*outArchive = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(path, MPQFS_ERR_INVALID_ARGUMENT);

	FILE *fp = fopen_utf8(path, "rb");
	MPQFS_RET_CHECK(fp, MPQFS_ERR_IO);

#ifdef MPQFS_FILE_BUFFER_SIZE
	if (MPQFS_UNLIKELY(setvbuf(fp, NULL, _IOFBF, MPQFS_FILE_BUFFER_SIZE) != 0)) {
		fclose(fp);
		return MPQFS_ERR_IO;
	}
#endif

	mpqfs_archive_t *archive;
	mpqfs_error_code rc = MpqInitArchive(fp, 1, &archive);
	MPQFS_RET_CHECK(rc == MPQFS_OK, rc);

	archive->path = MpqfsStrdup(path);
	if (MPQFS_UNLIKELY(!archive->path)) {
		mpqfs_close(archive);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	*outArchive = archive;
	return MPQFS_OK;
}

#if MPQFS_HAS_FDOPEN

mpqfs_error_code mpqfs_open_fd(int fd, mpqfs_archive_t **outArchive)
{
	*outArchive = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(fd >= 0, MPQFS_ERR_INVALID_ARGUMENT);

	FILE *fp = fdopen(fd, "rb");
	MPQFS_RET_CHECK(fp, MPQFS_ERR_IO);

	return MpqInitArchive(fp, 1, outArchive);
}

#endif /* MPQFS_HAS_FDOPEN */

mpqfs_error_code mpqfs_open_fp(FILE *fp, mpqfs_archive_t **outArchive)
{
	*outArchive = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(fp, MPQFS_ERR_INVALID_ARGUMENT);

	return MpqInitArchive(fp, 0, outArchive);
}

void mpqfs_close(mpqfs_archive_t *archive)
{
	if (!archive)
		return;

	free(archive->block_table);
	free(archive->hash_table);
	free(archive->path);

	if (archive->fp && archive->owns_fd)
		fclose(archive->fp);

	free(archive);
}

mpqfs_error_code mpqfs_clone(const mpqfs_archive_t *archive, mpqfs_archive_t **outArchive)
{
	*outArchive = NULL;

	MPQFS_RET_CHECK(archive, MPQFS_ERR_INVALID_ARGUMENT);

	MPQFS_RET_CHECK(archive->path, MPQFS_ERR_NO_PATH);

	return mpqfs_open(archive->path, outArchive);
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

uint32_t mpqfs_find_hash(mpqfs_archive_t *archive, const char *filename)
{
	return mpq_lookup_hash_entry(archive, filename);
}

bool mpqfs_has_file_hash(mpqfs_archive_t *archive, uint32_t hash)
{
	if (!archive)
		return false;

	if (hash >= archive->header.hash_table_count)
		return false;

	const mpq_hash_entry_t *entry = &archive->hash_table[hash];
	if (entry->block_index >= archive->header.block_table_count)
		return false;

	return (archive->block_table[entry->block_index].flags & MPQ_FILE_EXISTS) != 0;
}

mpqfs_error_code mpqfs_file_size(mpqfs_archive_t *archive, const char *filename,
    size_t *outSize)
{
	*outSize = 0;

	MPQFS_RET_CHECK(archive && filename, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t bi = mpq_lookup_file(archive, filename);
	MPQFS_RET_CHECK(bi != UINT32_MAX, MPQFS_ERR_FILE_NOT_FOUND);

	const mpq_block_entry_t *block = &archive->block_table[bi];
	MPQFS_RET_CHECK(block->flags & MPQ_FILE_EXISTS, MPQFS_ERR_FILE_NOT_FOUND);

	*outSize = (size_t)block->file_size;
	return MPQFS_OK;
}

mpqfs_error_code mpqfs_file_size_from_hash(mpqfs_archive_t *archive, uint32_t hash,
    size_t *outSize)
{
	*outSize = 0;

	MPQFS_RET_CHECK(archive, MPQFS_ERR_INVALID_ARGUMENT);

	MPQFS_RET_CHECK(hash < archive->header.hash_table_count, MPQFS_ERR_INVALID_HASH);

	const mpq_hash_entry_t *entry = &archive->hash_table[hash];
	MPQFS_RET_CHECK(entry->block_index < archive->header.block_table_count, MPQFS_ERR_CORRUPT_ARCHIVE);

	const mpq_block_entry_t *block = &archive->block_table[entry->block_index];
	MPQFS_RET_CHECK(block->flags & MPQ_FILE_EXISTS, MPQFS_ERR_FILE_NOT_FOUND);

	*outSize = (size_t)block->file_size;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: whole-file read
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_read_file(mpqfs_archive_t *archive, const char *filename,
    void **outData, size_t *outSize)
{
	*outData = NULL;
	*outSize = 0;

	MPQFS_RET_CHECK(archive && filename, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t bi = mpq_lookup_file(archive, filename);
	MPQFS_RET_CHECK(bi != UINT32_MAX, MPQFS_ERR_FILE_NOT_FOUND);

	mpqfs_stream_t *stream;
	mpqfs_error_code rc = mpq_stream_open_named(archive, bi, filename, &stream);
	MPQFS_RET_CHECK(rc == MPQFS_OK, rc);

	size_t total;
	rc = mpq_stream_size(stream, &total);
	if (rc != MPQFS_OK) {
		mpq_stream_close(stream);
		return rc;
	}

	uint8_t *buf = (uint8_t *)malloc(total);
	if (MPQFS_UNLIKELY(!buf)) {
		mpq_stream_close(stream);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	size_t offset = 0;
	while (offset < total) {
		size_t n;
		rc = mpq_stream_read(stream, buf + offset, total - offset, &n);
		if (MPQFS_UNLIKELY(rc != MPQFS_OK)) {
			free(buf);
			mpq_stream_close(stream);
			return rc;
		}
		if (n == 0)
			break; /* shouldn't happen, but guard against infinite loops */
		offset += n;
	}

	mpq_stream_close(stream);

	*outData = buf;
	*outSize = offset;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: whole-file read into caller-supplied buffer
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_read_file_into(mpqfs_archive_t *archive, const char *filename,
    void *buffer, size_t bufferSize, size_t *outBytesRead)
{
	*outBytesRead = 0;

	MPQFS_RET_CHECK(archive && filename && buffer && bufferSize != 0, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t bi = mpq_lookup_file(archive, filename);
	MPQFS_RET_CHECK(bi != UINT32_MAX, MPQFS_ERR_FILE_NOT_FOUND);

	mpqfs_stream_t *stream;
	mpqfs_error_code rc = mpq_stream_open_named(archive, bi, filename, &stream);
	MPQFS_RET_CHECK(rc == MPQFS_OK, rc);

	size_t total;
	mpq_stream_size(stream, &total);
	if (MPQFS_UNLIKELY(total > bufferSize)) {
		mpq_stream_close(stream);
		return MPQFS_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t *dst = (uint8_t *)buffer;
	size_t offset = 0;
	while (offset < total) {
		size_t n;
		rc = mpq_stream_read(stream, dst + offset, total - offset, &n);
		if (MPQFS_UNLIKELY(rc != MPQFS_OK)) {
			mpq_stream_close(stream);
			return rc;
		}
		if (n == 0)
			break;
		offset += n;
	}

	mpq_stream_close(stream);
	*outBytesRead = offset;
	return MPQFS_OK;
}
