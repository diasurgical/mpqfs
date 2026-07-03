/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Unicode aware fopen() replacement for Windows.
 */
#include "mpq_fopen.h"

#include <stdio.h>

#if !defined(MPQFS_WINDOWS_NO_WCHAR) && defined(_WIN32)
#if (defined(WINVER) && WINVER <= 0x0500 && !(defined(_WIN32_WINNT) && _WIN32_WINNT > 0))
// A legacy Windows platform without wide char APIs, e.g. Windows 98, original Xbox.
#define MPQFS_WINDOWS_NO_WCHAR
#endif
#endif

#if defined(_WIN32) && !defined(MPQFS_WINDOWS_NO_WCHAR)
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Suppress definitions of `min` and `max` macros by <windows.h>: */
#define NOMINMAX 1
#define WIN32_LEAN_AND_MEAN
#include <shlwapi.h>
#include <windows.h>
#endif

#if defined(_WIN32) && !defined(MPQFS_WINDOWS_NO_WCHAR)
static wchar_t *to_wide_char(const char *str)
{
	const size_t size = strlen(str);
	const uint32_t flags = MB_ERR_INVALID_CHARS;
	const int wide_size = MultiByteToWideChar(CP_UTF8, flags, str, size, NULL, 0);
	if (wide_size == 0)
		return NULL;
	wchar_t *result = malloc(sizeof(wchar_t) * (wide_size + 1));
	if (result == NULL) {
		return NULL;
	}
	if (MultiByteToWideChar(CP_UTF8, flags, str, size, result, wide_size) != wide_size) {
		free(result);
		return NULL;
	}
	result[wide_size] = L'\0';
	return result;
}
#endif

FILE *fopen_utf8(const char *filename, const char *mode)
{
#if defined(_WIN32) && !defined(MPQFS_WINDOWS_NO_WCHAR)
	wchar_t *filename_wide = to_wide_char(filename);
	if (filename_wide == NULL) return NULL;
	FILE *result = _wfopen(filename_wide, mode[0] == 'r' ? L"rb" : L"wb");
	free(filename_wide);
	filename_wide = NULL;
	return result;
#else
	return fopen(filename, mode);
#endif
}
