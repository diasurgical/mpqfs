/*
 * mpqfs — minimal MPQ v1 reader/writer
 * SPDX-License-Identifier: MIT
 * Internal header: Unicode aware fopen() replacement for Windows.
 */
#ifndef MPQFS_MPQ_FOPEN_H
#define MPQFS_MPQ_FOPEN_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens a file with a UTF-8 encoded filename and returns a FILE*.
 * Only "rb" and "wb" modes are supported.
 */
FILE *fopen_utf8(const char *path, const char *mode);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQ_FOPEN_H */
