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

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Error helpers
 * ----------------------------------------------------------------------- */

/* Defined in mpq_archive.c — we use it to mirror errors to the
 * thread-local g_last_error. */

void mpq_writer_set_error(mpqfs_writer_t *writer, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (writer) {
		vsnprintf(writer->error, sizeof(writer->error), fmt, ap);
	}

	va_end(ap);

	/* Also mirror into the thread-local last-error so
	 * mpqfs_last_error() picks it up. */
	va_start(ap, fmt);
	/* We can't easily call mpq_set_error with a va_list, so we
	 * just format directly into the writer and then copy via
	 * mpq_set_error with the pre-formatted string. */
	va_end(ap);

	if (writer) {
		mpq_set_error(NULL, "%s", writer->error);
	}
}

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

static mpqfs_writer_t *MpqWriterInit(FILE *fp, int ownsFd,
    uint32_t hashTableSize,
    const char *sourceName)
{
	mpqfs_writer_t *writer = (mpqfs_writer_t *)calloc(1, sizeof(*writer));
	if (!writer) {
		mpq_set_error(NULL, "%s: out of memory", sourceName);
		if (ownsFd && fp)
			fclose(fp);
		return NULL;
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
	if (!writer->files) {
		mpq_writer_set_error(writer, "%s: out of memory for file list",
		    sourceName);
		if (ownsFd && fp)
			fclose(fp);
		free(writer);
		return NULL;
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
	if (fseek(fp, 0, SEEK_SET) != 0) {
		mpq_writer_set_error(writer, "%s: initial seek failed: %s",
		    sourceName, strerror(errno));
		if (ownsFd && fp)
			fclose(fp);
		free(writer->files);
		free(writer);
		return NULL;
	}
	{
		uint8_t *zeroes = (uint8_t *)calloc(1, writer->data_start);
		if (!zeroes) {
			mpq_writer_set_error(writer,
			    "%s: out of memory for placeholder", sourceName);
			if (ownsFd && fp)
				fclose(fp);
			free(writer->files);
			free(writer);
			return NULL;
		}
		size_t n = writer->data_start;
		if (fwrite(zeroes, 1, n, fp) != n) {
			mpq_writer_set_error(writer,
			    "%s: failed to write placeholder: %s",
			    sourceName, strerror(errno));
			free(zeroes);
			if (ownsFd && fp)
				fclose(fp);
			free(writer->files);
			free(writer);
			return NULL;
		}
		free(zeroes);
	}

	return writer;
}

/* -----------------------------------------------------------------------
 * Public API: create a writer
 * ----------------------------------------------------------------------- */

mpqfs_writer_t *mpqfs_writer_create(const char *path,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (!path) {
		mpq_set_error(NULL, "mpqfs_writer_create: path is NULL");
		return NULL;
	}

	FILE *fp = fopen(path, "wb");
	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create: cannot open '%s': %s",
		    path, strerror(errno));
		return NULL;
	}

#ifdef MPQFS_FILE_BUFFER_SIZE
	if (setvbuf(fp, NULL, _IOFBF, MPQFS_FILE_BUFFER_SIZE) != 0) {
		mpq_set_error(NULL, "mpqfs_writer_create: cannot set buffer size: %s",
		    strerror(errno));
		fclose(fp);
		return NULL;
	}
#endif

	return MpqWriterInit(fp, 1, hashTableSize, "mpqfs_writer_create");
}

mpqfs_writer_t *mpqfs_writer_create_fp(FILE *fp,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create_fp: fp is NULL");
		return NULL;
	}

	return MpqWriterInit(fp, 0, hashTableSize, "mpqfs_writer_create_fp");
}

#if MPQFS_HAS_FDOPEN

mpqfs_writer_t *mpqfs_writer_create_fd(int fd,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (fd < 0) {
		mpq_set_error(NULL, "mpqfs_writer_create_fd: invalid file descriptor");
		return NULL;
	}

	FILE *fp = fdopen(fd, "wb");
	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create_fd: fdopen failed: %s",
		    strerror(errno));
		return NULL;
	}

	return MpqWriterInit(fp, 1, hashTableSize, "mpqfs_writer_create_fd");
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
 * file_size, flags) and 0 is returned.  On failure -1 is returned.
 *
 * For zero-length files nothing is written and compressed_size is 0.
 * ----------------------------------------------------------------------- */

static int MpqCompressAndWriteFile(FILE *fp,
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
		return 0;
	}

	uint32_t sectorCount = (fileSize + sectorSize - 1) / sectorSize;
	uint32_t offsetTableEntries = sectorCount + 1;
	uint32_t offsetTableBytes = offsetTableEntries * 4;

	/* Allocate worst-case output: offset table + each sector uncompressed. */
	size_t maxOut = (size_t)offsetTableBytes + (size_t)fileSize;
	/* Add headroom for compression overhead on incompressible data. */
	maxOut += (size_t)sectorCount * 64;

	uint8_t *buf = (uint8_t *)malloc(maxOut);
	if (!buf)
		return -1;

	/* We'll fill in the offset table after compressing all sectors. */
	uint32_t *offsetTable = (uint32_t *)malloc(offsetTableEntries * sizeof(uint32_t));
	if (!offsetTable) {
		free(buf);
		return -1;
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

	if (writeOk != 0)
		return -1;

	entry->compressed_size = totalSize;
	entry->flags = flags;

	return 0;
}

/* -----------------------------------------------------------------------
 * Public API: add a file to the archive
 *
 * The file data is compressed and written to disk immediately.  Only
 * the per-file metadata is retained in RAM.
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_add_file(mpqfs_writer_t *writer, const char *filename,
    const void *data, size_t size)
{
	if (!writer || !filename) {
		if (writer) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_add_file: invalid arguments");
		} else {
			mpq_set_error(NULL, "mpqfs_writer_add_file: writer is NULL");
		}
		return false;
	}

	if (!data && size > 0) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: data is NULL with "
		    "non-zero size");
		return false;
	}

	/* Check that we haven't exceeded the hash table capacity.
	 * We need at least one empty slot for the hash table probe chain
	 * to terminate, so limit to (hash_table_size - 1) files. */
	if (writer->file_count >= writer->hash_table_size - 1) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: hash table full "
		    "(%" PRIu32 " files, table size %" PRIu32 ")",
		    writer->file_count, writer->hash_table_size);
		return false;
	}

	/* Grow the files array if needed. */
	if (writer->file_count >= writer->file_capacity) {
		uint32_t newCap = writer->file_capacity * 2;
		mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(writer->files,
		    newCap * sizeof(mpqfs_writer_file_t));
		if (!newFiles) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_add_file: out of memory");
			return false;
		}
		/* Zero out the newly allocated portion. */
		memset(newFiles + writer->file_capacity, 0,
		    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
		writer->files = newFiles;
		writer->file_capacity = newCap;
	}

	/* Make an owned copy of the filename. */
	char *nameCopy = MpqStrdup(filename);
	if (!nameCopy) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: out of memory for name");
		return false;
	}

	/* Compress the file data and write it to disk at data_cursor. */
	mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
	entry->filename = nameCopy;

	if (MpqCompressAndWriteFile(writer->fp,
	        (const uint8_t *)data, (uint32_t)size,
	        writer->sector_size_shift,
	        writer->data_cursor,
	        entry)
	    != 0) {
		free(nameCopy);
		entry->filename = NULL;
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: failed to compress/write "
		    "file '%s'",
		    filename);
		return false;
	}

	/* Advance the data cursor past the data we just wrote. */
	writer->data_cursor += entry->compressed_size;

	writer->file_count++;
	return true;
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

bool mpqfs_writer_rename_file(mpqfs_writer_t *writer,
    const char *old_name,
    const char *new_name)
{
	if (!writer || !old_name || !new_name)
		return false;

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
			if (!nameCopy) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_rename_file: out of memory");
				return false;
			}
			free(writer->files[i].filename);
			writer->files[i].filename = nameCopy;
			writer->files[i].has_raw_hashes = 0;
			return true;
		}
	}
	return false;
}

/* -----------------------------------------------------------------------
 * Public API: remove a file from the writer metadata
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_remove_file(mpqfs_writer_t *writer,
    const char *filename)
{
	if (!writer || !filename)
		return false;

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
			return true;
		}
	}
	return false;
}

/* -----------------------------------------------------------------------
 * Public API: copy a file from an existing archive (raw, no recompress)
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_carry_forward(mpqfs_writer_t *writer,
    const char *filename,
    mpqfs_archive_t *archive,
    uint32_t block_index)
{
	if (!writer || !filename || !archive) {
		if (writer) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_carry_forward: invalid arguments");
		} else {
			mpq_set_error(NULL, "mpqfs_writer_carry_forward: writer is NULL");
		}
		return false;
	}

	if (block_index >= archive->header.block_table_count) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: block_index %" PRIu32 " out of range",
		    block_index);
		return false;
	}

	const mpq_block_entry_t *blk = &archive->block_table[block_index];

	if (!(blk->flags & MPQ_FILE_EXISTS)) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: block %" PRIu32 " not in use",
		    block_index);
		return false;
	}

	/* Check hash table capacity. */
	if (writer->file_count >= writer->hash_table_size - 1) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: hash table full");
		return false;
	}

	/* Grow the files array if needed. */
	if (writer->file_count >= writer->file_capacity) {
		uint32_t newCap = writer->file_capacity * 2;
		mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(
		    writer->files, newCap * sizeof(mpqfs_writer_file_t));
		if (!newFiles) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_carry_forward: out of memory");
			return false;
		}
		memset(newFiles + writer->file_capacity, 0,
		    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
		writer->files = newFiles;
		writer->file_capacity = newCap;
	}

	char *nameCopy = MpqStrdup(filename);
	if (!nameCopy) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: out of memory for name");
		return false;
	}

	uint32_t rawSize = blk->compressed_size;

	/* Read the raw compressed data from the source archive. */
	uint8_t *rawBuf = (uint8_t *)malloc(rawSize);
	if (!rawBuf) {
		free(nameCopy);
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: out of memory for raw data");
		return false;
	}

	if (fseek(archive->fp,
	        (long)(archive->archive_offset + blk->offset), SEEK_SET)
	    != 0) {
		free(rawBuf);
		free(nameCopy);
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: seek failed on source");
		return false;
	}

	if (fread(rawBuf, 1, rawSize, archive->fp) != rawSize) {
		free(rawBuf);
		free(nameCopy);
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: read failed on source");
		return false;
	}

	/* Write the raw data to the new archive at data_cursor. */
	if (MpqRawWrite(writer->fp, rawBuf, rawSize) != 0) {
		free(rawBuf);
		free(nameCopy);
		mpq_writer_set_error(writer,
		    "mpqfs_writer_carry_forward: write failed");
		return false;
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

	return true;
}

/* -----------------------------------------------------------------------
 * Internal: read raw compressed data for a block and write it to the
 * writer's output file at data_cursor.  Returns 0 on success, -1 on
 * failure.  On success, *out_raw_size receives the number of bytes
 * written.
 * ----------------------------------------------------------------------- */

static int MpqCopyRawBlock(mpqfs_writer_t *writer,
    mpqfs_archive_t *archive,
    const mpq_block_entry_t *blk,
    uint32_t *out_raw_size)
{
	uint32_t rawSize = blk->compressed_size;

	uint8_t *rawBuf = (uint8_t *)malloc(rawSize);
	if (!rawBuf)
		return -1;

	if (fseek(archive->fp,
	        (long)(archive->archive_offset + blk->offset), SEEK_SET)
	    != 0) {
		free(rawBuf);
		return -1;
	}

	if (fread(rawBuf, 1, rawSize, archive->fp) != rawSize) {
		free(rawBuf);
		return -1;
	}

	if (MpqRawWrite(writer->fp, rawBuf, rawSize) != 0) {
		free(rawBuf);
		return -1;
	}

	free(rawBuf);
	*out_raw_size = rawSize;
	return 0;
}

/* -----------------------------------------------------------------------
 * Public API: carry forward all files from an existing archive
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_carry_forward_all(mpqfs_writer_t *writer,
    mpqfs_archive_t *archive)
{
	if (!writer || !archive) {
		if (writer) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_carry_forward_all: invalid arguments");
		} else {
			mpq_set_error(NULL, "mpqfs_writer_carry_forward_all: writer is NULL");
		}
		return false;
	}

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
		if (writer->file_count >= writer->hash_table_size - 1) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_carry_forward_all: hash table full");
			return false;
		}

		/* Grow files array if needed. */
		if (writer->file_count >= writer->file_capacity) {
			uint32_t newCap = writer->file_capacity * 2;
			mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(
			    writer->files, newCap * sizeof(mpqfs_writer_file_t));
			if (!newFiles) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_carry_forward_all: out of memory");
				return false;
			}
			memset(newFiles + writer->file_capacity, 0,
			    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
			writer->files = newFiles;
			writer->file_capacity = newCap;
		}

		/* Copy raw data from source archive to writer output. */
		uint32_t rawSize = 0;
		if (MpqCopyRawBlock(writer, archive, blk, &rawSize) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_carry_forward_all: failed to copy "
			    "block %" PRIu32 "",
			    he->block_index);
			return false;
		}

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

	return true;
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

bool mpqfs_writer_close(mpqfs_writer_t *writer)
{
	if (!writer) {
		mpq_set_error(NULL, "mpqfs_writer_close: writer is NULL");
		return false;
	}

	FILE *fp = writer->fp;
	bool success = true;

	if (!fp) {
		mpq_writer_set_error(writer, "mpqfs_writer_close: no file handle");
		success = false;
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

		if (!blockTable) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to build block table");
			success = false;
			goto cleanup;
		}

		uint32_t *hashTable = MpqBuildHashTable(writer);
		if (!hashTable) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to build hash table");
			free(blockTable);
			success = false;
			goto cleanup;
		}

		/* ---- Write the header and tables ---- */

		if (fseek(fp, 0, SEEK_SET) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: seek failed: %s",
			    strerror(errno));
			free(hashTable);
			free(blockTable);
			success = false;
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

			if (MpqRawWrite(fp, hdr, sizeof(hdr)) != 0) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_close: failed to write header");
				free(hashTable);
				free(blockTable);
				success = false;
				goto cleanup;
			}
		}

		/* Write the block table. */
		if (MpqRawWrite(fp, blockTable, tableEntryBytes) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to write "
			    "block table");
			free(hashTable);
			free(blockTable);
			success = false;
			goto cleanup;
		}
		free(blockTable);

		/* Write the hash table. */
		if (MpqRawWrite(fp, hashTable, tableEntryBytes) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to write hash table");
			free(hashTable);
			success = false;
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
	return success;
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