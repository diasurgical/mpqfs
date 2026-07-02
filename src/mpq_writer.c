/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * MPQ v1 writer: creates archives in the style used by DevilutionX
 * for its save-game files (.sv / .hsv).
 *
 * The produced archive layout is:
 *
 *   Offset 0x0000:  MPQ Header (32 bytes)
 *   Offset 0x0020:  Block table (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  Hash table  (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  File data   (PKWARE implode compressed, with
 *                                sector offset tables)
 *
 * This layout matches DevilutionX's MpqWriter exactly:
 *   - Block table and hash table are the same size (hash_table_size entries)
 *   - Both tables are placed immediately after the header, before file data
 *   - Block table comes first, then hash table
 *   - Unused block table entries are zeroed out
 *
 * Files are compressed with PKWARE DCL implode (sector-based).  Each
 * compressed file's on-disk data consists of a sector offset table
 * followed by the compressed sector payloads.  Sectors that do not
 * benefit from compression are stored raw.  If no sector in a file
 * compresses, the file is stored without an offset table and without
 * the IMPLODE flag.
 *
 * Hash and block tables are encrypted with the standard MPQ keys
 * "(hash table)" and "(block table)" respectively, exactly as the
 * original game does.
 *
 * Streaming strategy
 * ------------------
 * File data is compressed and written to disk inside
 * mpqfs_writer_add_file() so that peak RAM usage does not scale with
 * the total size of all files.  Only per-file metadata is kept in
 * memory.  The header and tables are written (or rewritten) during
 * mpqfs_writer_close() once all metadata is known.
 */

#include "mpq_explode.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "mpq_archive.h"
#include "mpq_crypto.h"
#include "mpq_implode.h"
#include "mpq_platform.h"
#include "mpq_writer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Internal: round up to the next power of two (minimum 1)
 * ----------------------------------------------------------------------- */

static uint32_t MpqRoundUpPow2(uint32_t v)
{
	if (v == 0)
		return 1;

	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

/* -----------------------------------------------------------------------
 * Internal: duplicate a string (C99 doesn't have strdup portably)
 * ----------------------------------------------------------------------- */

static char *MpqStrdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *dup = (char *)malloc(len);
	if (dup)
		memcpy(dup, s, len);
	return dup;
}

/* -----------------------------------------------------------------------
 * Internal: shared writer init after the FILE* is obtained
 * ----------------------------------------------------------------------- */

static mpqfs_error_code MpqWriterInit(FILE *fp, int ownsFd,
    uint32_t hashTableSize,
    mpqfs_writer_t **outWriter)
{
	*outWriter = NULL;

	mpqfs_writer_t *writer = (mpqfs_writer_t *)calloc(1, sizeof(*writer));
	if (MPQFS_UNLIKELY(!writer)) {
		if (ownsFd && fp)
			fclose(fp);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	writer->fp = fp;
	writer->owns_fd = ownsFd;

	/* Ensure hash_table_size is at least 4 and a power of 2. */
	if (hashTableSize < 4)
		hashTableSize = 4;
	writer->hash_table_size = MpqRoundUpPow2(hashTableSize);

	/* Default sector size shift of 3: 512 << 3 = 4096 bytes per sector.
	 * This matches Diablo 1's typical settings. */
	writer->sector_size_shift = 3;

	/* Pre-allocate file list. */
	writer->file_capacity = MPQFS_WRITER_INITIAL_CAPACITY;
	writer->file_count = 0;
	writer->files = (mpqfs_writer_file_t *)calloc(writer->file_capacity,
	    sizeof(mpqfs_writer_file_t));
	if (MPQFS_UNLIKELY(!writer->files)) {
		if (ownsFd && fp)
			fclose(fp);
		free(writer);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	/* Compute data_start: header + block table + hash table.
	 * File data will be written starting at this offset. */
	uint32_t tableEntryBytes = writer->hash_table_size * 16;
	writer->data_start = MPQ_HEADER_SIZE_V1 + tableEntryBytes + tableEntryBytes;
	writer->data_cursor = writer->data_start;

	/* Write placeholder zeroes for the header + tables region so that
	 * the file position naturally lands at data_start.  This avoids
	 * seeking beyond EOF, which fails on some platforms (e.g. Amiga).
	 * The header and tables will be overwritten with real data during
	 * mpqfs_writer_close(). */
	if (MPQFS_UNLIKELY(fseek(fp, 0, SEEK_SET) != 0)) {
		if (ownsFd && fp)
			fclose(fp);
		free(writer->files);
		free(writer);
		return MPQFS_ERR_IO;
	}
	{
		uint8_t *zeroes = (uint8_t *)calloc(1, writer->data_start);
		if (MPQFS_UNLIKELY(!zeroes)) {
			if (ownsFd && fp)
				fclose(fp);
			free(writer->files);
			free(writer);
			return MPQFS_ERR_OUT_OF_MEMORY;
		}
		size_t n = writer->data_start;
		if (MPQFS_UNLIKELY(fwrite(zeroes, 1, n, fp) != n)) {
			free(zeroes);
			if (ownsFd && fp)
				fclose(fp);
			free(writer->files);
			free(writer);
			return MPQFS_ERR_IO;
		}
		free(zeroes);
	}

	*outWriter = writer;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: create a writer
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_create(const char *path,
    uint32_t hashTableSize, mpqfs_writer_t **outWriter)
{
	*outWriter = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(path, MPQFS_ERR_INVALID_ARGUMENT);

	FILE *fp = fopen(path, "wb");
	MPQFS_RET_CHECK(fp, MPQFS_ERR_IO);

#ifdef MPQFS_FILE_BUFFER_SIZE
	if (MPQFS_UNLIKELY(setvbuf(fp, NULL, _IOFBF, MPQFS_FILE_BUFFER_SIZE) != 0)) {
		fclose(fp);
		return MPQFS_ERR_IO;
	}
#endif

	return MpqWriterInit(fp, 1, hashTableSize, outWriter);
}

mpqfs_error_code mpqfs_writer_create_fp(FILE *fp,
    uint32_t hashTableSize, mpqfs_writer_t **outWriter)
{
	*outWriter = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(fp, MPQFS_ERR_INVALID_ARGUMENT);

	return MpqWriterInit(fp, 0, hashTableSize, outWriter);
}

#if MPQFS_HAS_FDOPEN

mpqfs_error_code mpqfs_writer_create_fd(int fd,
    uint32_t hashTableSize, mpqfs_writer_t **outWriter)
{
	*outWriter = NULL;

	mpq_crypto_init();

	MPQFS_RET_CHECK(fd >= 0, MPQFS_ERR_INVALID_ARGUMENT);

	FILE *fp = fdopen(fd, "wb");
	MPQFS_RET_CHECK(fp, MPQFS_ERR_IO);

	return MpqWriterInit(fp, 1, hashTableSize, outWriter);
}

#endif /* MPQFS_HAS_FDOPEN */

/* -----------------------------------------------------------------------
 * Internal: write raw bytes at the current file position
 * ----------------------------------------------------------------------- */

static int MpqRawWrite(FILE *fp, const void *buf, size_t count)
{
	if (count == 0)
		return 0;
	if (fwrite(buf, 1, count, fp) != count)
		return -1;
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: compress a single file and write it directly to disk
 *
 * The compressed data (sector offset table + compressed sectors) is
 * written to |fp| at the current file position.  On success the
 * metadata fields of |entry| are filled in (offset, compressed_size,
 * file_size, flags) and MPQFS_OK is returned.
 *
 * For zero-length files nothing is written and compressed_size is 0.
 * ----------------------------------------------------------------------- */

static mpqfs_error_code MpqCompressAndWriteFile(FILE *fp,
    const uint8_t *fileData, uint32_t fileSize,
    uint16_t sectorSizeShift,
    uint32_t fileOffset,
    mpqfs_writer_file_t *entry)
{
	uint32_t sectorSize = 512U << sectorSizeShift;
	int dictBits = (int)sectorSizeShift + 6; /* shift=3 → bits=6 (4096) */

	/* Clamp dict_bits to valid range [4..6]. */
	if (dictBits < 4) dictBits = 4;
	if (dictBits > 6) dictBits = 6;

	entry->file_size = fileSize;
	entry->offset = fileOffset;

	if (fileSize == 0) {
		entry->compressed_size = 0;
		entry->flags = MPQ_FILE_EXISTS;
		return MPQFS_OK;
	}

	uint32_t sectorCount = (fileSize + sectorSize - 1) / sectorSize;
	uint32_t offsetTableEntries = sectorCount + 1;
	uint32_t offsetTableBytes = offsetTableEntries * 4;

	/* Allocate worst-case output: offset table + each sector uncompressed. */
	size_t maxOut = (size_t)offsetTableBytes + (size_t)fileSize;
	/* Add headroom for compression overhead on incompressible data. */
	maxOut += (size_t)sectorCount * 64;

	uint8_t *buf = (uint8_t *)malloc(maxOut);
	MPQFS_RET_CHECK(buf, MPQFS_ERR_OUT_OF_MEMORY);

	/* We'll fill in the offset table after compressing all sectors. */
	uint32_t *offsetTable = (uint32_t *)malloc(offsetTableEntries * sizeof(uint32_t));
	if (MPQFS_UNLIKELY(!offsetTable)) {
		free(buf);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	/* Compress each sector. */
	uint32_t writeCursor = offsetTableBytes; /* first sector starts after offset table */
	int anyCompressed = 0;

	for (uint32_t s = 0; s < sectorCount; s++) {
		uint32_t srcOffset = s * sectorSize;
		uint32_t remaining = fileSize - srcOffset;
		uint32_t thisSize = (remaining < sectorSize) ? remaining : sectorSize;

		offsetTable[s] = writeCursor;

		/* Try to compress this sector. */
		size_t compSize = maxOut - writeCursor;
		int rc = pk_implode_sector(fileData + srcOffset, thisSize,
		    buf + writeCursor, &compSize, dictBits);

		if (rc == PK_OK && compSize < thisSize) {
			/* Compression helped. */
			writeCursor += (uint32_t)compSize;
			anyCompressed = 1;
		} else {
			/* Store uncompressed (comp_size == this_size means no gain). */
			memcpy(buf + writeCursor, fileData + srcOffset, thisSize);
			writeCursor += thisSize;
		}
	}

	offsetTable[sectorCount] = writeCursor; /* end sentinel */

	uint32_t totalSize;
	uint32_t flags;

	if (anyCompressed) {
		/* Write the offset table into the buffer. */
		for (uint32_t i = 0; i < offsetTableEntries; i++) {
			mpqfs_write_le32(buf + ((size_t)i * 4), offsetTable[i]);
		}

		totalSize = writeCursor;
		flags = MPQ_FILE_EXISTS | MPQ_FILE_IMPLODE;
	} else {
		/* No sector benefited from compression — store the file
		 * completely uncompressed (no offset table, no IMPLODE flag).
		 * This matches what DevilutionX does when compression doesn't help. */
		memcpy(buf, fileData, fileSize);
		totalSize = fileSize;
		flags = MPQ_FILE_EXISTS;
	}

	free(offsetTable);

	/* Write the compressed (or raw) data to disk. */
	int writeOk = MpqRawWrite(fp, buf, totalSize);
	free(buf);

	MPQFS_RET_CHECK(writeOk == 0, MPQFS_ERR_IO);

	entry->compressed_size = totalSize;
	entry->flags = flags;

	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: add a file to the archive
 *
 * The file data is compressed and written to disk immediately.  Only
 * the per-file metadata is retained in RAM.
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_add_file(mpqfs_writer_t *writer, const char *filename,
    const void *data, size_t size)
{
	MPQFS_RET_CHECK(writer && filename, MPQFS_ERR_INVALID_ARGUMENT);

	MPQFS_RET_CHECK(data || size <= 0, MPQFS_ERR_INVALID_ARGUMENT);

	/* Check that we haven't exceeded the hash table capacity.
	 * We need at least one empty slot for the hash table probe chain
	 * to terminate, so limit to (hash_table_size - 1) files. */
	MPQFS_RET_CHECK(writer->file_count < writer->hash_table_size - 1, MPQFS_ERR_HASH_TABLE_FULL);

	/* Grow the files array if needed. */
	if (writer->file_count >= writer->file_capacity) {
		uint32_t newCap = writer->file_capacity * 2;
		mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(writer->files,
		    newCap * sizeof(mpqfs_writer_file_t));
		MPQFS_RET_CHECK(newFiles, MPQFS_ERR_OUT_OF_MEMORY);
		/* Zero out the newly allocated portion. */
		memset(newFiles + writer->file_capacity, 0,
		    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
		writer->files = newFiles;
		writer->file_capacity = newCap;
	}

	/* Make an owned copy of the filename. */
	char *nameCopy = MpqStrdup(filename);
	MPQFS_RET_CHECK(nameCopy, MPQFS_ERR_OUT_OF_MEMORY);

	/* Compress the file data and write it to disk at data_cursor. */
	mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
	entry->filename = nameCopy;

	mpqfs_error_code rc = MpqCompressAndWriteFile(writer->fp,
	    (const uint8_t *)data, (uint32_t)size,
	    writer->sector_size_shift,
	    writer->data_cursor,
	    entry);
	if (MPQFS_UNLIKELY(rc != MPQFS_OK)) {
		free(nameCopy);
		entry->filename = NULL;
		return rc;
	}

	/* Advance the data cursor past the data we just wrote. */
	writer->data_cursor += entry->compressed_size;

	writer->file_count++;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: check if a file has been added
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_has_file(const mpqfs_writer_t *writer,
    const char *filename)
{
	if (!writer || !filename)
		return false;

	uint32_t nameA = mpq_hash_string(filename, MPQ_HASH_NAME_A);
	uint32_t nameB = mpq_hash_string(filename, MPQ_HASH_NAME_B);

	for (uint32_t i = 0; i < writer->file_count; i++) {
		if (writer->files[i].removed)
			continue;
		if (writer->files[i].filename != NULL) {
			if (strcmp(writer->files[i].filename, filename) == 0)
				return true;
		} else if (writer->files[i].has_raw_hashes) {
			if (writer->files[i].hash_a == nameA
			    && writer->files[i].hash_b == nameB)
				return true;
		}
	}
	return false;
}

/* -----------------------------------------------------------------------
 * Public API: rename a file in the writer metadata
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_rename_file(mpqfs_writer_t *writer,
    const char *old_name,
    const char *new_name)
{
	MPQFS_RET_CHECK(writer && old_name && new_name, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t nameA = mpq_hash_string(old_name, MPQ_HASH_NAME_A);
	uint32_t nameB = mpq_hash_string(old_name, MPQ_HASH_NAME_B);

	for (uint32_t i = 0; i < writer->file_count; i++) {
		if (writer->files[i].removed)
			continue;

		int match = 0;
		if (writer->files[i].filename != NULL) {
			match = (strcmp(writer->files[i].filename, old_name) == 0);
		} else if (writer->files[i].has_raw_hashes) {
			match = (writer->files[i].hash_a == nameA
			    && writer->files[i].hash_b == nameB);
		}

		if (match) {
			char *nameCopy = MpqStrdup(new_name);
			MPQFS_RET_CHECK(nameCopy, MPQFS_ERR_OUT_OF_MEMORY);
			free(writer->files[i].filename);
			writer->files[i].filename = nameCopy;
			writer->files[i].has_raw_hashes = 0;
			return MPQFS_OK;
		}
	}
	return MPQFS_ERR_FILE_NOT_FOUND;
}

/* -----------------------------------------------------------------------
 * Public API: remove a file from the writer metadata
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_remove_file(mpqfs_writer_t *writer,
    const char *filename)
{
	MPQFS_RET_CHECK(writer && filename, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t nameA = mpq_hash_string(filename, MPQ_HASH_NAME_A);
	uint32_t nameB = mpq_hash_string(filename, MPQ_HASH_NAME_B);

	for (uint32_t i = 0; i < writer->file_count; i++) {
		if (writer->files[i].removed)
			continue;

		int match = 0;
		if (writer->files[i].filename != NULL) {
			match = (strcmp(writer->files[i].filename, filename) == 0);
		} else if (writer->files[i].has_raw_hashes) {
			match = (writer->files[i].hash_a == nameA
			    && writer->files[i].hash_b == nameB);
		}

		if (match) {
			writer->files[i].removed = 1;
			return MPQFS_OK;
		}
	}
	return MPQFS_ERR_FILE_NOT_FOUND;
}

/* -----------------------------------------------------------------------
 * Public API: copy a file from an existing archive (raw, no recompress)
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_carry_forward(mpqfs_writer_t *writer,
    const char *filename,
    mpqfs_archive_t *archive,
    uint32_t block_index)
{
	MPQFS_RET_CHECK(writer && filename && archive, MPQFS_ERR_INVALID_ARGUMENT);

	MPQFS_RET_CHECK(block_index < archive->header.block_table_count, MPQFS_ERR_INVALID_ARGUMENT);

	const mpq_block_entry_t *blk = &archive->block_table[block_index];

	MPQFS_RET_CHECK(blk->flags & MPQ_FILE_EXISTS, MPQFS_ERR_FILE_NOT_FOUND);

	/* Check hash table capacity. */
	MPQFS_RET_CHECK(writer->file_count < writer->hash_table_size - 1, MPQFS_ERR_HASH_TABLE_FULL);

	/* Grow the files array if needed. */
	if (writer->file_count >= writer->file_capacity) {
		uint32_t newCap = writer->file_capacity * 2;
		mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(
		    writer->files, newCap * sizeof(mpqfs_writer_file_t));
		MPQFS_RET_CHECK(newFiles, MPQFS_ERR_OUT_OF_MEMORY);
		memset(newFiles + writer->file_capacity, 0,
		    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
		writer->files = newFiles;
		writer->file_capacity = newCap;
	}

	char *nameCopy = MpqStrdup(filename);
	MPQFS_RET_CHECK(nameCopy, MPQFS_ERR_OUT_OF_MEMORY);

	uint32_t rawSize = blk->compressed_size;

	/* Read the raw compressed data from the source archive. */
	uint8_t *rawBuf = (uint8_t *)malloc(rawSize);
	if (MPQFS_UNLIKELY(!rawBuf)) {
		free(nameCopy);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	if (MPQFS_UNLIKELY(fseek(archive->fp,
	                       (long)(archive->archive_offset + blk->offset), SEEK_SET)
	        != 0)) {
		free(rawBuf);
		free(nameCopy);
		return MPQFS_ERR_IO;
	}

	if (MPQFS_UNLIKELY(fread(rawBuf, 1, rawSize, archive->fp) != rawSize)) {
		free(rawBuf);
		free(nameCopy);
		return MPQFS_ERR_IO;
	}

	/* Write the raw data to the new archive at data_cursor. */
	if (MPQFS_UNLIKELY(MpqRawWrite(writer->fp, rawBuf, rawSize) != 0)) {
		free(rawBuf);
		free(nameCopy);
		return MPQFS_ERR_IO;
	}

	free(rawBuf);

	/* Record metadata — same flags/sizes as original, new offset. */
	mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
	entry->filename = nameCopy;
	entry->offset = writer->data_cursor;
	entry->compressed_size = blk->compressed_size;
	entry->file_size = blk->file_size;
	entry->flags = blk->flags;
	entry->removed = 0;

	writer->data_cursor += rawSize;
	writer->file_count++;

	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Internal: read raw compressed data for a block and write it to the
 * writer's output file at data_cursor.  On success, *out_raw_size
 * receives the number of bytes written.
 * ----------------------------------------------------------------------- */

static mpqfs_error_code MpqCopyRawBlock(mpqfs_writer_t *writer,
    mpqfs_archive_t *archive,
    const mpq_block_entry_t *blk,
    uint32_t *out_raw_size)
{
	uint32_t rawSize = blk->compressed_size;

	uint8_t *rawBuf = (uint8_t *)malloc(rawSize);
	MPQFS_RET_CHECK(rawBuf, MPQFS_ERR_OUT_OF_MEMORY);

	if (MPQFS_UNLIKELY(fseek(archive->fp,
	                       (long)(archive->archive_offset + blk->offset), SEEK_SET)
	        != 0)) {
		free(rawBuf);
		return MPQFS_ERR_IO;
	}

	if (MPQFS_UNLIKELY(fread(rawBuf, 1, rawSize, archive->fp) != rawSize)) {
		free(rawBuf);
		return MPQFS_ERR_IO;
	}

	if (MPQFS_UNLIKELY(MpqRawWrite(writer->fp, rawBuf, rawSize) != 0)) {
		free(rawBuf);
		return MPQFS_ERR_IO;
	}

	free(rawBuf);
	*out_raw_size = rawSize;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: carry forward all files from an existing archive
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_carry_forward_all(mpqfs_writer_t *writer,
    mpqfs_archive_t *archive)
{
	MPQFS_RET_CHECK(writer && archive, MPQFS_ERR_INVALID_ARGUMENT);

	uint32_t hashCount = archive->header.hash_table_count;

	for (uint32_t h = 0; h < hashCount; h++) {
		const mpq_hash_entry_t *he = &archive->hash_table[h];

		/* Skip empty / deleted slots. */
		if (he->block_index == MPQ_HASH_ENTRY_EMPTY
		    || he->block_index == MPQ_HASH_ENTRY_DELETED)
			continue;

		if (he->block_index >= archive->header.block_table_count)
			continue;

		const mpq_block_entry_t *blk = &archive->block_table[he->block_index];
		if (!(blk->flags & MPQ_FILE_EXISTS))
			continue;

		/* Check if an entry with the same hash_a/hash_b already
		 * exists in the writer (added by add_file earlier).
		 * If so, skip — the newer version takes precedence. */
		{
			int duplicate = 0;
			for (uint32_t i = 0; i < writer->file_count; i++) {
				if (writer->files[i].removed)
					continue;
				if (writer->files[i].has_raw_hashes
				    && writer->files[i].hash_a == he->hash_a
				    && writer->files[i].hash_b == he->hash_b) {
					duplicate = 1;
					break;
				}
				if (writer->files[i].filename != NULL) {
					uint32_t a = mpq_hash_string(
					    writer->files[i].filename, MPQ_HASH_NAME_A);
					uint32_t b = mpq_hash_string(
					    writer->files[i].filename, MPQ_HASH_NAME_B);
					if (a == he->hash_a && b == he->hash_b) {
						duplicate = 1;
						break;
					}
				}
			}
			if (duplicate)
				continue;
		}

		/* Check capacity. */
		MPQFS_RET_CHECK(writer->file_count < writer->hash_table_size - 1, MPQFS_ERR_HASH_TABLE_FULL);

		/* Grow files array if needed. */
		if (writer->file_count >= writer->file_capacity) {
			uint32_t newCap = writer->file_capacity * 2;
			mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(
			    writer->files, newCap * sizeof(mpqfs_writer_file_t));
			MPQFS_RET_CHECK(newFiles, MPQFS_ERR_OUT_OF_MEMORY);
			memset(newFiles + writer->file_capacity, 0,
			    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
			writer->files = newFiles;
			writer->file_capacity = newCap;
		}

		/* Copy raw data from source archive to writer output. */
		uint32_t rawSize = 0;
		mpqfs_error_code rc = MpqCopyRawBlock(writer, archive, blk, &rawSize);
		MPQFS_RET_CHECK(rc == MPQFS_OK, rc);

		/* Record metadata with raw hashes (no filename). */
		mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
		memset(entry, 0, sizeof(*entry));
		entry->filename = NULL;
		entry->offset = writer->data_cursor;
		entry->compressed_size = blk->compressed_size;
		entry->file_size = blk->file_size;
		entry->flags = blk->flags;
		entry->has_raw_hashes = 1;
		entry->hash_a = he->hash_a;
		entry->hash_b = he->hash_b;
		entry->src_hash_slot = h;

		writer->data_cursor += rawSize;
		writer->file_count++;
	}

	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the hash table
 *
 * Returns a heap-allocated buffer of (hash_table_size * 16) bytes
 * containing the encrypted hash table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *MpqBuildHashTable(mpqfs_writer_t *writer)
{
	uint32_t count = writer->hash_table_size;
	size_t dwordCount = (size_t)count * 4; /* 16 bytes = 4 dwords per entry */
	size_t totalBytes = dwordCount * sizeof(uint32_t);

	uint32_t *table = (uint32_t *)malloc(totalBytes);
	if (!table)
		return NULL;

	/* Initialise all entries to "empty" (0xFFFFFFFF for all fields). */
	memset(table, 0xFF, totalBytes);

	/* Phase 1: Place carry-forward entries at their original hash table
	 * slot positions.  Because the source and destination archives use
	 * the same hash_table_size, the reader's probe chain starting from
	 * hash(filename, TABLE_INDEX) % count will reach these slots at the
	 * same position as in the source archive.
	 *
	 * We must do this first so that filename-based entries (phase 2)
	 * probe around them correctly. */
	for (uint32_t f = 0; f < writer->file_count; f++) {
		if (writer->files[f].removed)
			continue;
		if (!writer->files[f].has_raw_hashes)
			continue;

		uint32_t slot = writer->files[f].src_hash_slot % count;
		uint32_t base = slot * 4;

		/* The slot should be empty since carry-forward entries come
		 * from distinct slots in the source archive.  If there's a
		 * collision (shouldn't happen in practice), fall back to
		 * linear probing. */
		uint32_t idx = slot;
		for (;;) {
			base = idx * 4;
			if (table[base + 3] == MPQ_HASH_ENTRY_EMPTY
			    || table[base + 3] == MPQ_HASH_ENTRY_DELETED) {
				table[base + 0] = writer->files[f].hash_a;
				table[base + 1] = writer->files[f].hash_b;
				table[base + 2] = 0x00000000;
				table[base + 3] = f;
				break;
			}
			idx = (idx + 1) % count;
		}
	}

	/* Phase 2: Insert filename-based entries with normal hashing and
	 * linear probing, skipping over slots already occupied by phase 1. */
	for (uint32_t f = 0; f < writer->file_count; f++) {
		if (writer->files[f].removed)
			continue;
		if (writer->files[f].has_raw_hashes)
			continue;

		const char *filename = writer->files[f].filename;
		uint32_t bucket = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX) % count;
		uint32_t nameA = mpq_hash_string(filename, MPQ_HASH_NAME_A);
		uint32_t nameB = mpq_hash_string(filename, MPQ_HASH_NAME_B);

		/* Linear probe to find an empty slot. */
		uint32_t idx = bucket;
		for (;;) {
			uint32_t base = idx * 4;
			if (table[base + 3] == MPQ_HASH_ENTRY_EMPTY || table[base + 3] == MPQ_HASH_ENTRY_DELETED) {
				table[base + 0] = nameA;      /* hash_a   */
				table[base + 1] = nameB;      /* hash_b   */
				table[base + 2] = 0x00000000; /* locale=0, platform=0 */
				table[base + 3] = f;          /* block_index = file index */
				break;
			}
			idx = (idx + 1) % count;
		}
	}

	/* Encrypt the hash table in-place. */
	uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
	mpq_encrypt_block(table, dwordCount, key);

	return table;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the block table
 *
 * The block table has hash_table_size entries to match DevilutionX's
 * format.  Entries 0..file_count-1 are populated with file metadata;
 * the remaining entries are zeroed (unallocated).
 *
 * Metadata (offset, compressed_size, file_size, flags) is read directly
 * from the mpqfs_writer_file_t entries that were populated during
 * mpqfs_writer_add_file().
 *
 * Returns a heap-allocated buffer of (hash_table_size * 16) bytes
 * containing the encrypted block table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *MpqBuildBlockTable(mpqfs_writer_t *writer)
{
	uint32_t count = writer->hash_table_size;
	size_t dwordCount = (size_t)count * 4;
	size_t totalBytes = dwordCount * sizeof(uint32_t);

	uint32_t *table = (uint32_t *)malloc(totalBytes);
	if (!table)
		return NULL;

	/* Zero the entire table (unused entries stay zeroed). */
	memset(table, 0, totalBytes);

	/* Populate entries for actual files. */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		if (writer->files[i].removed)
			continue;

		uint32_t base = i * 4;

		table[base + 0] = writer->files[i].offset;          /* offset */
		table[base + 1] = writer->files[i].compressed_size; /* compressed_size */
		table[base + 2] = writer->files[i].file_size;       /* file_size */
		table[base + 3] = writer->files[i].flags;           /* flags */
	}

	/* Encrypt the block table in-place. */
	uint32_t key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
	mpq_encrypt_block(table, dwordCount, key);

	return table;
}

/* -----------------------------------------------------------------------
 * Public API: close (finalize and write the archive)
 *
 * By this point all file data has already been written to disk by
 * mpqfs_writer_add_file().  We just need to:
 *   1. Build the encrypted hash and block tables from metadata.
 *   2. Seek back to offset 0 and write the header.
 *   3. Write the block table (at offset 32).
 *   4. Write the hash table.
 *   5. Flush and free resources.
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpqfs_writer_close(mpqfs_writer_t *writer)
{
	MPQFS_RET_CHECK(writer, MPQFS_ERR_INVALID_ARGUMENT);

	FILE *fp = writer->fp;
	mpqfs_error_code result = MPQFS_OK;

	if (MPQFS_UNLIKELY(!fp)) {
		result = MPQFS_ERR_IO;
		goto cleanup;
	}

	/* ---- Build tables from metadata ---- */

	{
		uint32_t headerSize = MPQ_HEADER_SIZE_V1; /* 32 */
		uint32_t hashTableSize = writer->hash_table_size;
		uint32_t tableEntryBytes = hashTableSize * 16;

		uint32_t blockTableOffset = headerSize;
		uint32_t hashTableOffset = blockTableOffset + tableEntryBytes;

		uint32_t archiveSize = writer->data_cursor;

		/* Build encrypted tables. */
		uint32_t *blockTable = MpqBuildBlockTable(writer);

		if (MPQFS_UNLIKELY(!blockTable)) {
			result = MPQFS_ERR_OUT_OF_MEMORY;
			goto cleanup;
		}

		uint32_t *hashTable = MpqBuildHashTable(writer);
		if (MPQFS_UNLIKELY(!hashTable)) {
			free(blockTable);
			result = MPQFS_ERR_OUT_OF_MEMORY;
			goto cleanup;
		}

		/* ---- Write the header and tables ---- */

		if (MPQFS_UNLIKELY(fseek(fp, 0, SEEK_SET) != 0)) {
			free(hashTable);
			free(blockTable);
			result = MPQFS_ERR_IO;
			goto cleanup;
		}

		/* Write the MPQ header. */
		{
			uint8_t hdr[MPQ_HEADER_SIZE_V1];
			memset(hdr, 0, sizeof(hdr));

			mpqfs_write_le32(hdr + 0, MPQ_SIGNATURE);
			mpqfs_write_le32(hdr + 4, headerSize);
			mpqfs_write_le32(hdr + 8, archiveSize);
			mpqfs_write_le16(hdr + 12, 0);
			mpqfs_write_le16(hdr + 14, writer->sector_size_shift);
			mpqfs_write_le32(hdr + 16, hashTableOffset);
			mpqfs_write_le32(hdr + 20, blockTableOffset);
			mpqfs_write_le32(hdr + 24, hashTableSize);
			mpqfs_write_le32(hdr + 28, hashTableSize);

			if (MPQFS_UNLIKELY(MpqRawWrite(fp, hdr, sizeof(hdr)) != 0)) {
				free(hashTable);
				free(blockTable);
				result = MPQFS_ERR_IO;
				goto cleanup;
			}
		}

		/* Write the block table. */
		if (MPQFS_UNLIKELY(MpqRawWrite(fp, blockTable, tableEntryBytes) != 0)) {
			free(hashTable);
			free(blockTable);
			result = MPQFS_ERR_IO;
			goto cleanup;
		}
		free(blockTable);

		/* Write the hash table. */
		if (MPQFS_UNLIKELY(MpqRawWrite(fp, hashTable, tableEntryBytes) != 0)) {
			free(hashTable);
			result = MPQFS_ERR_IO;
			goto cleanup;
		}
		free(hashTable);

		/* File data was already written by add_file — nothing more to do. */

		fflush(fp);
	}

cleanup:
	/* Free all file entry filenames (no data buffers to free). */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		free(writer->files[i].filename);
	}
	free(writer->files);

	/* Close the file if we own it. */
	if (writer->fp && writer->owns_fd)
		fclose(writer->fp);

	free(writer);
	return result;
}

/* -----------------------------------------------------------------------
 * Public API: discard a writer without writing
 * ----------------------------------------------------------------------- */

void mpqfs_writer_discard(mpqfs_writer_t *writer)
{
	if (!writer)
		return;

	/* Free all file entry filenames (no data buffers to free). */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		free(writer->files[i].filename);
	}
	free(writer->files);

	/* Close the file if we own it. */
	if (writer->fp && writer->owns_fd)
		fclose(writer->fp);

	free(writer);
}
