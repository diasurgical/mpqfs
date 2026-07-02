/*
 * mpqfs — minimal MPQ v1 reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Sector-based file streaming with PKWARE DCL / zlib decompression
 * and optional per-file decryption.
 *
 * MPQ files are divided into sectors of `sector_size` bytes (typically
 * 4096).  Compressed files begin with a sector offset table that gives
 * the byte offset of each sector's compressed data relative to the
 * file's block offset.  The last entry in the table marks the end of
 * the last sector.
 *
 * For each read, we determine which sector(s) the request spans,
 * decompress on demand, cache the most recent sector, and copy into
 * the caller's buffer.
 *
 * Encrypted files (MPQ_FILE_ENCRYPTED) have their sector offset table
 * and sector data encrypted with a key derived from the filename.
 * When MPQ_FILE_FIX_KEY is also set, the key is further adjusted by
 * the block offset and file size.  Each sector is encrypted with
 * (key + sector_index).
 */

#include "mpq_stream.h"
#include "mpq_archive.h"
#include "mpq_crypto.h"
#include "mpq_explode.h"
#include "mpq_platform.h"
#include <inttypes.h>
#include <stdint.h>

#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
#include <zlib.h>
#endif
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
#include <bzlib.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Internal: read raw bytes from the archive at an absolute offset
 * ----------------------------------------------------------------------- */

static int MpqRawRead(mpqfs_archive_t *archive, int64_t offset,
    void *buf, size_t count)
{
	if (fseek(archive->fp, (long)offset, SEEK_SET) != 0)
		return -1;
	if (fread(buf, 1, count, archive->fp) != count)
		return -1;
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: load and decompress a single sector into stream->sector_buf
 * ----------------------------------------------------------------------- */

static mpqfs_error_code MpqStreamLoadSector(mpqfs_stream_t *stream, uint32_t sectorIdx)
{
	/* Already cached? */
	if (stream->cached_sector == sectorIdx)
		return MPQFS_OK;

	mpqfs_archive_t *archive = stream->archive;
	uint32_t flags = stream->flags;

	/* Compute the expected decompressed size for this sector. */
	uint32_t remaining = stream->file_size - (sectorIdx * stream->sector_size);
	uint32_t expect = (remaining < stream->sector_size) ? remaining : stream->sector_size;

	/* Absolute offset of the file's data block in the underlying file. */
	int64_t fileAbs = archive->archive_offset + (int64_t)stream->file_offset;

	if (flags & (MPQ_FILE_IMPLODE | MPQ_FILE_COMPRESS)) {
		/*
		 * Compressed file — use the sector offset table to find the
		 * compressed data for this sector.
		 */
		if (!stream->sector_offsets) {
			return MPQFS_ERR_CORRUPT_ARCHIVE;
		}

		uint32_t sectorStart = stream->sector_offsets[sectorIdx];
		uint32_t sectorEnd = stream->sector_offsets[sectorIdx + 1];

		if (sectorEnd < sectorStart) {
			return MPQFS_ERR_CORRUPT_ARCHIVE;
		}

		uint32_t compSize = sectorEnd - sectorStart;

		if (compSize == 0) {
			/* Zero-length sector — treat as all zeros. */
			memset(stream->sector_buf, 0, expect);
			stream->cached_sector = sectorIdx;
			stream->cached_sector_len = expect;
			return MPQFS_OK;
		}

		/*
		 * If the compressed size equals the expected uncompressed size,
		 * the sector is stored uncompressed (the compressor gave up).
		 */
		if (compSize == expect) {
			if (MpqRawRead(archive, fileAbs + sectorStart,
			        stream->sector_buf, expect)
			    != 0) {
				return MPQFS_ERR_IO;
			}
			/* Decrypt in-place if needed. */
			if (stream->file_key != 0) {
				/* Truncate to complete uint32_t words (matching StormLib). */
				size_t dwords = expect / 4;
				mpq_decrypt_block((uint32_t *)stream->sector_buf,
				    dwords, stream->file_key + sectorIdx);
			}
			stream->cached_sector = sectorIdx;
			stream->cached_sector_len = expect;
			return MPQFS_OK;
		}

		/* Ensure the reusable compressed-data buffer is large enough. */
		if (compSize > stream->comp_buf_cap) {
			uint8_t *newBuf = (uint8_t *)realloc(stream->comp_buf, compSize);
			if (!newBuf) {
				return MPQFS_ERR_OUT_OF_MEMORY;
			}
			stream->comp_buf = newBuf;
			stream->comp_buf_cap = compSize;
		}
		uint8_t *compBuf = stream->comp_buf;

		if (MpqRawRead(archive, fileAbs + sectorStart,
		        compBuf, compSize)
		    != 0) {
			return MPQFS_ERR_IO;
		}

		/* Decrypt the compressed data before decompression. */
		if (stream->file_key != 0) {
			size_t dwords = compSize / 4;
			mpq_decrypt_block((uint32_t *)compBuf,
			    dwords, stream->file_key + sectorIdx);
		}

		int rc;

		if (flags & MPQ_FILE_IMPLODE) {
			/*
			 * PKWARE DCL implode — the entire sector payload is the
			 * imploded stream (no extra compression-type byte).
			 */
			rc = pk_explode_sector(compBuf, compSize,
			    stream->sector_buf, expect);
			if (rc != PK_OK) {
				return MPQFS_ERR_DECOMPRESS_FAILED;
			}
		} else if (flags & MPQ_FILE_COMPRESS) {
			/*
			 * Multi-method compression — the first byte of the sector
			 * indicates the compression method(s) used.
			 */
			if (compSize < 1) {
				return MPQFS_ERR_CORRUPT_ARCHIVE;
			}

			uint8_t compMethod = compBuf[0];
			const uint8_t *srcData = compBuf + 1;
			uint32_t srcLen = compSize - 1;

			/*
			 * MPQ multi-compression can layer multiple methods.
			 * They are applied in a fixed order during compression;
			 * we undo them in reverse order.  In practice Diablo 1
			 * spawn.mpq only uses a single method per sector.
			 *
			 * We handle them from innermost (applied last during
			 * compression = undone first) to outermost.
			 */

			/* --- PKWARE DCL (0x08) --- */
			if (compMethod & MPQ_COMP_PKWARE) {
				rc = pk_explode_sector(srcData, srcLen,
				    stream->sector_buf, expect);
				if (rc != PK_OK) {
					return MPQFS_ERR_DECOMPRESS_FAILED;
				}
				/* Output is now in sector_buf; if another method needs
				 * to run after this, it would read from sector_buf.
				 * For single-method (common case), we're done. */
			}

			/* --- zlib / deflate (0x02) --- */
			if (compMethod & MPQ_COMP_ZLIB) {
#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
				uLongf destLen = (uLongf)expect;
				int zrc = uncompress(stream->sector_buf, &destLen,
				    srcData, (uLong)srcLen);
				if (zrc != Z_OK) {
					return MPQFS_ERR_DECOMPRESS_FAILED;
				}
#else
				return MPQFS_ERR_UNSUPPORTED_COMPRESSION;
#endif
			}

			/* --- bzip2 (0x10) --- */
			if (compMethod & MPQ_COMP_BZIP2) {
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
				unsigned int destLen = (unsigned int)expect;
				int brc = BZ2_bzBuffToBuffDecompress(
				    (char *)stream->sector_buf, &destLen,
				    (char *)srcData, (unsigned int)srcLen,
				    0, 0);
				if (brc != BZ_OK) {
					return MPQFS_ERR_DECOMPRESS_FAILED;
				}
#else
				return MPQFS_ERR_UNSUPPORTED_COMPRESSION;
#endif
			}

			/* --- Unsupported methods --- */
			{
				uint8_t supported = MPQ_COMP_PKWARE;
#if defined(MPQFS_HAS_ZLIB) && MPQFS_HAS_ZLIB
				supported |= MPQ_COMP_ZLIB;
#endif
#if defined(MPQFS_HAS_BZIP2) && MPQFS_HAS_BZIP2
				supported |= MPQ_COMP_BZIP2;
#endif
				if (compMethod & ~supported) {
					return MPQFS_ERR_UNSUPPORTED_COMPRESSION;
				}
			}
		}

		stream->cached_sector = sectorIdx;
		stream->cached_sector_len = expect;
		return MPQFS_OK;

	} /*
	   * Uncompressed file — read directly from the archive.
	   *
	   * For single-unit files or uncompressed multi-sector files, the
	   * data starts right after the file data offset.
	   */
	int64_t sectorAbs = fileAbs + ((int64_t)sectorIdx * (int64_t)stream->sector_size);

	if (MpqRawRead(archive, sectorAbs, stream->sector_buf, expect) != 0) {
		return MPQFS_ERR_IO;
	}

	/* Decrypt in-place if needed. */
	if (stream->file_key != 0) {
		size_t dwords = expect / 4;
		mpq_decrypt_block((uint32_t *)stream->sector_buf,
		    dwords, stream->file_key + sectorIdx);
	}

	stream->cached_sector = sectorIdx;
	stream->cached_sector_len = expect;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: open
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpq_stream_open(mpqfs_archive_t *archive, uint32_t blockIndex,
    mpqfs_stream_t **outStream)
{
	return mpq_stream_open_named(archive, blockIndex, NULL, outStream);
}

mpqfs_error_code mpq_stream_open_named(mpqfs_archive_t *archive,
    uint32_t blockIndex,
    const char *filename,
    mpqfs_stream_t **outStream)
{
	*outStream = NULL;

	if (!archive) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	if (blockIndex >= archive->header.block_table_count) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	const mpq_block_entry_t *block = &archive->block_table[blockIndex];

	if (!(block->flags & MPQ_FILE_EXISTS)) {
		return MPQFS_ERR_FILE_NOT_FOUND;
	}

	/* If the file is encrypted, we MUST have the filename to derive the key. */
	if ((block->flags & MPQ_FILE_ENCRYPTED) && !filename) {
		return MPQFS_ERR_ENCRYPTED_NO_KEY;
	}

	mpqfs_stream_t *stream = (mpqfs_stream_t *)calloc(1, sizeof(*stream));
	if (!stream) {
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	stream->archive = archive;
	stream->block_index = blockIndex;
	stream->file_offset = block->offset;
	stream->compressed_size = block->compressed_size;
	stream->file_size = block->file_size;
	stream->flags = block->flags;
	stream->sector_size = archive->sector_size;
	stream->position = 0;
	stream->cached_sector = (uint32_t)-1;
	stream->cached_sector_len = 0;

	/* Derive the file decryption key if the file is encrypted. */
	if (block->flags & MPQ_FILE_ENCRYPTED) {
		int adjust = (block->flags & MPQ_FILE_FIX_KEY) != 0;
		stream->file_key = mpq_file_key(filename, block->offset,
		    block->file_size, adjust);
	} else {
		stream->file_key = 0;
	}

	/* Zero-length file — nothing else to set up. */
	if (stream->file_size == 0) {
		stream->sector_count = 0;
		stream->sector_offsets = NULL;
		stream->sector_buf = NULL;
		*outStream = stream;
		return MPQFS_OK;
	}

	/* Compute sector count. */
	stream->sector_count = (stream->file_size + stream->sector_size - 1)
	    / stream->sector_size;

	/* Allocate the sector cache buffer. */
	stream->sector_buf = (uint8_t *)malloc(stream->sector_size);
	if (!stream->sector_buf) {
		free(stream);
		return MPQFS_ERR_OUT_OF_MEMORY;
	}

	/*
	 * For compressed files (not single-unit), the block data begins with
	 * a sector offset table: (sector_count + 1) uint32_t values giving
	 * the byte offsets of each sector's compressed data relative to the
	 * start of the block data.
	 */
	if ((stream->flags & (MPQ_FILE_IMPLODE | MPQ_FILE_COMPRESS)) && !(stream->flags & MPQ_FILE_SINGLE_UNIT)) {
		uint32_t tableEntries = stream->sector_count + 1;
		size_t tableBytes = (size_t)tableEntries * sizeof(uint32_t);

		stream->sector_offsets = (uint32_t *)malloc(tableBytes);
		if (!stream->sector_offsets) {
			free(stream->sector_buf);
			free(stream);
			return MPQFS_ERR_OUT_OF_MEMORY;
		}

		int64_t absOffset = archive->archive_offset
		    + (int64_t)stream->file_offset;

		/* Read the raw sector offset table from the archive. */
		uint8_t *rawTable = (uint8_t *)malloc(tableBytes);
		if (!rawTable) {
			free(stream->sector_offsets);
			free(stream->sector_buf);
			free(stream);
			return MPQFS_ERR_OUT_OF_MEMORY;
		}

		if (MpqRawRead(archive, absOffset, rawTable, tableBytes) != 0) {
			free(rawTable);
			free(stream->sector_offsets);
			free(stream->sector_buf);
			free(stream);
			return MPQFS_ERR_IO;
		}

		/* Convert from little-endian to native. */
		for (uint32_t i = 0; i < tableEntries; i++) {
			stream->sector_offsets[i] = mpqfs_read_le32(rawTable + ((size_t)i * 4));
		}

		free(rawTable);

		/* If the file is encrypted, the sector offset table is encrypted
		 * with the base file key (no sector index added). */
		if (stream->file_key != 0) {
			mpq_decrypt_block(stream->sector_offsets, tableEntries,
			    stream->file_key - 1);
		}

		/* Basic sanity check on the offset table. */
		if (stream->sector_offsets[0] != tableBytes) {
			free(stream->sector_offsets);
			free(stream->sector_buf);
			free(stream);
			return MPQFS_ERR_CORRUPT_ARCHIVE;
		}
	} else if (stream->flags & MPQ_FILE_SINGLE_UNIT) {
		/*
		 * Single-unit files store all data as one blob (no sector
		 * offset table).  We treat the entire file as one big sector.
		 */
		stream->sector_count = 1;
		stream->sector_offsets = NULL;

		/* Re-allocate sector buffer to the full file size if it's
		 * larger than the default sector size. */
		if (stream->file_size > stream->sector_size) {
			free(stream->sector_buf);
			stream->sector_buf = (uint8_t *)malloc(stream->file_size);
			if (!stream->sector_buf) {
				free(stream);
				return MPQFS_ERR_OUT_OF_MEMORY;
			}
			stream->sector_size = stream->file_size;
		}
	} else {
		/* Uncompressed, multi-sector. No offset table needed. */
		stream->sector_offsets = NULL;
	}

	*outStream = stream;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: close
 * ----------------------------------------------------------------------- */

void mpq_stream_close(mpqfs_stream_t *stream)
{
	if (!stream)
		return;

	free(stream->sector_offsets);
	free(stream->sector_buf);
	free(stream->comp_buf);
	free(stream);
}

/* -----------------------------------------------------------------------
 * Public API: read
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpq_stream_read(mpqfs_stream_t *stream, void *buf,
    size_t count, size_t *outRead)
{
	*outRead = 0;

	if (!stream || !buf) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	/* Clamp to remaining bytes. */
	uint64_t remaining = 0;
	if (stream->position < (uint64_t)stream->file_size)
		remaining = (uint64_t)stream->file_size - stream->position;

	if (count > remaining)
		count = (size_t)remaining;

	if (count == 0)
		return MPQFS_OK;

	uint8_t *dst = (uint8_t *)buf;
	size_t copied = 0;

	while (copied < count) {
		/* Determine which sector the current position falls in. */
		uint32_t sectorIdx = (uint32_t)(stream->position / stream->sector_size);
		uint32_t offsetIn = (uint32_t)(stream->position % stream->sector_size);

		/* Load the sector (decompressing if necessary). */
		mpqfs_error_code rc = MpqStreamLoadSector(stream, sectorIdx);
		if (rc != MPQFS_OK) {
			if (copied > 0) {
				*outRead = copied;
				return MPQFS_OK;
			}
			return rc;
		}

		/* How many bytes can we copy from this sector? */
		uint32_t avail = stream->cached_sector_len - offsetIn;
		size_t want = count - copied;
		size_t chunk = (want < (size_t)avail) ? want : (size_t)avail;

		memcpy(dst + copied, stream->sector_buf + offsetIn, chunk);

		copied += chunk;
		stream->position += chunk;
	}

	*outRead = copied;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: seek
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpq_stream_seek(mpqfs_stream_t *stream, int64_t offset,
    int whence, int64_t *outPosition)
{
	*outPosition = 0;

	if (!stream) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	int64_t newPos;

	switch (whence) {
	case SEEK_SET:
		newPos = offset;
		break;
	case SEEK_CUR:
		newPos = (int64_t)stream->position + offset;
		break;
	case SEEK_END:
		newPos = (int64_t)stream->file_size + offset;
		break;
	default:
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	if (newPos < 0)
		newPos = 0;

	if (newPos > (int64_t)stream->file_size)
		newPos = (int64_t)stream->file_size;

	stream->position = (uint64_t)newPos;
	*outPosition = newPos;
	return MPQFS_OK;
}

/* -----------------------------------------------------------------------
 * Public API: tell / size
 * ----------------------------------------------------------------------- */

mpqfs_error_code mpq_stream_tell(mpqfs_stream_t *stream, int64_t *outPosition)
{
	*outPosition = 0;
	if (!stream) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}
	*outPosition = (int64_t)stream->position;
	return MPQFS_OK;
}

mpqfs_error_code mpq_stream_size(mpqfs_stream_t *stream, size_t *outSize)
{
	*outSize = 0;
	if (!stream) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}
	*outSize = (size_t)stream->file_size;
	return MPQFS_OK;
}
