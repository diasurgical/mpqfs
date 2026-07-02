/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Error code -> human-readable message mapping.
 */

#include "mpqfs/mpqfs.h"

const char *mpqfs_error_message(mpqfs_error_code code)
{
	switch (code) {
	case MPQFS_OK:
		return "success";
	case MPQFS_ERR_INVALID_ARGUMENT:
		return "invalid argument";
	case MPQFS_ERR_OUT_OF_MEMORY:
		return "out of memory";
	case MPQFS_ERR_IO:
		return "I/O error";
	case MPQFS_ERR_NOT_MPQ:
		return "not a valid MPQ archive (signature not found)";
	case MPQFS_ERR_UNSUPPORTED_VERSION:
		return "unsupported MPQ format version";
	case MPQFS_ERR_CORRUPT_ARCHIVE:
		return "corrupt archive data";
	case MPQFS_ERR_FILE_NOT_FOUND:
		return "file not found";
	case MPQFS_ERR_INVALID_HASH:
		return "invalid hash table index";
	case MPQFS_ERR_ENCRYPTED_NO_KEY:
		return "file is encrypted but no filename was provided for key derivation";
	case MPQFS_ERR_UNSUPPORTED_COMPRESSION:
		return "unsupported or unavailable compression method";
	case MPQFS_ERR_DECOMPRESS_FAILED:
		return "decompression failed";
	case MPQFS_ERR_BUFFER_TOO_SMALL:
		return "destination buffer too small";
	case MPQFS_ERR_HASH_TABLE_FULL:
		return "writer hash table is full";
	case MPQFS_ERR_NO_PATH:
		return "archive has no known filesystem path";
	}

	return "unknown error";
}
