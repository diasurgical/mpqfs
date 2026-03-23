/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Public stream API wrappers.
 */

#include "mpq_archive.h"
#include "mpq_stream.h"
#include "../include/mpqfs/mpqfs.h"

#include <stdint.h>

mpqfs_stream_t *mpqfs_stream_open(mpqfs_archive_t *archive,
    const char *filename)
{
	if (!archive || !filename)
		return NULL;

	uint32_t bi = mpq_lookup_file(archive, filename);
	if (bi == UINT32_MAX) {
		mpq_set_error(archive, "mpqfs_stream_open: file '%s' not found", filename);
		return NULL;
	}

	return mpq_stream_open_named(archive, bi, filename);
}

mpqfs_stream_t *mpqfs_stream_open_from_hash(mpqfs_archive_t *archive,
    uint32_t hash)
{
	if (!archive)
		return NULL;

	if (hash >= archive->header.hash_table_count) {
		mpq_set_error(archive, "mpqfs_stream_open_from_hash: invalid hash %u", hash);
		return NULL;
	}

	uint32_t bi = archive->hash_table[hash].block_index;
	if (bi >= archive->header.block_table_count) {
		mpq_set_error(archive, "mpqfs_stream_open_from_hash: invalid block index");
		return NULL;
	}

	return mpq_stream_open(archive, bi);
}

void mpqfs_stream_close(mpqfs_stream_t *stream)
{
	mpq_stream_close(stream);
}

size_t mpqfs_stream_read(mpqfs_stream_t *stream, void *buf, size_t count)
{
	return mpq_stream_read(stream, buf, count);
}

int64_t mpqfs_stream_seek(mpqfs_stream_t *stream, int64_t offset, int whence)
{
	return mpq_stream_seek(stream, offset, whence);
}

int64_t mpqfs_stream_tell(mpqfs_stream_t *stream)
{
	return mpq_stream_tell(stream);
}

size_t mpqfs_stream_size(mpqfs_stream_t *stream)
{
	return mpq_stream_size(stream);
}