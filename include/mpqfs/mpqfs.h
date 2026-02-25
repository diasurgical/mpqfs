/*
 * mpqfs — Minimal MPQ v1 archive reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Public API header.
 *
 * This is the only header consumers need to include.  It provides:
 *   - Archive open / close
 *   - File existence and size queries
 *   - Whole-file reads into caller-allocated or library-allocated buffers
 *   - SDL streaming adapters (SDL_RWops for SDL 1.2 & 2, SDL_IOStream for SDL 3)
 *   - Error reporting
 */

#ifndef MPQFS_MPQFS_H
#define MPQFS_MPQFS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * SDL header inclusion (driven by CMake -DMPQFS_USE_SDLx=1)
 * ----------------------------------------------------------------------- */

#if defined(MPQFS_USE_SDL3) && MPQFS_USE_SDL3
#   include <SDL3/SDL_iostream.h>
#   include <SDL3/SDL.h>
#elif defined(MPQFS_USE_SDL2) && MPQFS_USE_SDL2
#   include <SDL2/SDL_rwops.h>
#   include <SDL2/SDL.h>
#elif defined(MPQFS_USE_SDL1) && MPQFS_USE_SDL1
#   include <SDL/SDL_rwops.h>
#   include <SDL/SDL.h>
#endif

/* -----------------------------------------------------------------------
 * Visibility macros
 * ----------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)
#   ifdef MPQFS_BUILDING
#       define MPQFS_API __declspec(dllexport)
#   else
#       define MPQFS_API __declspec(dllimport)
#   endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define MPQFS_API __attribute__((visibility("default")))
#else
#   define MPQFS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Opaque archive handle
 *
 * All API functions that take an archive pointer require a non-NULL
 * handle previously obtained from mpqfs_open() or mpqfs_open_fd().
 * ----------------------------------------------------------------------- */

typedef struct mpqfs_archive mpqfs_archive_t;

/* -----------------------------------------------------------------------
 * Archive lifecycle
 * ----------------------------------------------------------------------- */

/**
 * Open an MPQ archive from a filesystem path.
 *
 * The archive file is kept open for the lifetime of the returned handle;
 * call mpqfs_close() when done.
 *
 * @param path  Filesystem path to the .mpq file (e.g. "DIABDAT.MPQ").
 * @return      Opaque archive handle, or NULL on error (see mpqfs_last_error()).
 */
MPQFS_API mpqfs_archive_t *mpqfs_open(const char *path);

/**
 * Open an MPQ archive from an already-open file descriptor.
 *
 * The library takes ownership of the descriptor — it will be closed when
 * mpqfs_close() is called on the returned handle.
 *
 * @param fd  A readable file descriptor positioned anywhere; the library
 *            will scan for the MPQ header.
 * @return    Opaque archive handle, or NULL on error.
 */
MPQFS_API mpqfs_archive_t *mpqfs_open_fd(int fd);

/**
 * Close an archive and free all associated resources.
 *
 * Any SDL streams (SDL_RWops / SDL_IOStream) created from this archive
 * must be closed *before* the archive itself.
 *
 * @param archive  Handle to close (NULL is safely ignored).
 */
MPQFS_API void mpqfs_close(mpqfs_archive_t *archive);

/* -----------------------------------------------------------------------
 * File queries
 * ----------------------------------------------------------------------- */

/**
 * Check whether a named file exists in the archive.
 *
 * Filenames use backslash (`\`) separators and are matched
 * case-insensitively, following MPQ conventions.  Forward slashes are
 * normalised automatically.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path (e.g. "levels\\l1data\\l1.min").
 * @return          true if the file exists, false otherwise.
 */
MPQFS_API bool mpqfs_has_file(mpqfs_archive_t *archive, const char *filename);

/**
 * Return the uncompressed size of a file in the archive.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @return          Uncompressed size in bytes, or 0 if the file is not found.
 */
MPQFS_API size_t mpqfs_file_size(mpqfs_archive_t *archive, const char *filename);

/* -----------------------------------------------------------------------
 * Whole-file reads
 * ----------------------------------------------------------------------- */

/**
 * Read an entire file into a newly allocated buffer.
 *
 * The caller is responsible for calling free() on the returned pointer.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @param out_size  If non-NULL, receives the number of bytes read.
 * @return          Pointer to the file data, or NULL on error.
 */
MPQFS_API void *mpqfs_read_file(mpqfs_archive_t *archive, const char *filename,
                                size_t *out_size);

/**
 * Read an entire file into a caller-supplied buffer.
 *
 * @param archive     Open archive handle.
 * @param filename    Archive-relative path.
 * @param buffer      Destination buffer.
 * @param buffer_size Size of the destination buffer in bytes.
 * @return            Number of bytes written to the buffer, or 0 on error.
 */
MPQFS_API size_t mpqfs_read_file_into(mpqfs_archive_t *archive,
                                      const char *filename,
                                      void *buffer, size_t buffer_size);

/* -----------------------------------------------------------------------
 * SDL streaming adapters
 *
 * These functions create a seekable, read-only stream backed by a single
 * file inside the archive.  Writes always fail.
 *
 * Closing the stream frees its internal resources but does NOT close the
 * parent archive.  The archive must remain open for the lifetime of the
 * stream.
 * ----------------------------------------------------------------------- */

#if defined(MPQFS_USE_SDL3) && MPQFS_USE_SDL3

/**
 * Create an SDL 3 IOStream for a file in the archive.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_IOStream, or NULL on error.
 */
MPQFS_API SDL_IOStream *mpqfs_open_io(mpqfs_archive_t *archive,
                                      const char *filename);

#endif /* MPQFS_USE_SDL3 */

#if defined(MPQFS_USE_SDL2) && MPQFS_USE_SDL2

/**
 * Create an SDL 2 RWops for a file in the archive.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops(mpqfs_archive_t *archive,
                                      const char *filename);

#endif /* MPQFS_USE_SDL2 */

#if defined(MPQFS_USE_SDL1) && MPQFS_USE_SDL1

/**
 * Create an SDL 1.2 RWops for a file in the archive.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops(mpqfs_archive_t *archive,
                                      const char *filename);

#endif /* MPQFS_USE_SDL1 */

/* -----------------------------------------------------------------------
 * Error handling
 * ----------------------------------------------------------------------- */

/**
 * Return a human-readable description of the last error that occurred
 * on the calling thread, or NULL if no error has been recorded.
 *
 * The returned pointer is valid until the next mpqfs call on the same
 * thread.
 */
MPQFS_API const char *mpqfs_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQFS_H */