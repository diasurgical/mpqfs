/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Public stream API wrappers.
 */

#include <inttypes.h>
#include <stdint.h>

#include "mpq_archive.h"
#include "mpq_stream.h"
#include "mpqfs/mpqfs.h"

mpqfs_error_code mpqfs_stream_open(mpqfs_archive_t *archive,
    const char *filename, mpqfs_stream_t **outStream)
{
	*outStream = NULL;

	if (!archive || !filename) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	uint32_t bi = mpq_lookup_file(archive, filename);
	if (bi == UINT32_MAX) {
		return MPQFS_ERR_FILE_NOT_FOUND;
	}

	return mpq_stream_open_named(archive, bi, filename, outStream);
}

mpqfs_error_code mpqfs_stream_open_from_hash(mpqfs_archive_t *archive,
    uint32_t hash, mpqfs_stream_t **outStream)
{
	*outStream = NULL;

	if (!archive) {
		return MPQFS_ERR_INVALID_ARGUMENT;
	}

	if (hash >= archive->header.hash_table_count) {
		return MPQFS_ERR_INVALID_HASH;
	}

	uint32_t bi = archive->hash_table[hash].block_index;
	if (bi >= archive->header.block_table_count) {
		return MPQFS_ERR_CORRUPT_ARCHIVE;
	}

	return mpq_stream_open(archive, bi, outStream);
}

void mpqfs_stream_close(mpqfs_stream_t *stream)
{
	mpq_stream_close(stream);
}

mpqfs_error_code mpqfs_stream_read(mpqfs_stream_t *stream, void *buf,
    size_t count, size_t *outRead)
{
	return mpq_stream_read(stream, buf, count, outRead);
}

mpqfs_error_code mpqfs_stream_seek(mpqfs_stream_t *stream, int64_t offset,
    int whence, int64_t *outPosition)
{
	return mpq_stream_seek(stream, offset, whence, outPosition);
}

mpqfs_error_code mpqfs_stream_tell(mpqfs_stream_t *stream, int64_t *outPosition)
{
	return mpq_stream_tell(stream, outPosition);
}

mpqfs_error_code mpqfs_stream_size(mpqfs_stream_t *stream, size_t *outSize)
{
	return mpq_stream_size(stream, outSize);
}
