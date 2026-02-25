/*
 * mpqfs — Minimal MPQ v1 archive reader/writer with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * Public API header.
 *
 * This is the only header consumers need to include.  It provides:
 *   - Archive open / close (reading)
 *   - File existence and size queries
 *   - Whole-file reads into caller-allocated or library-allocated buffers
 *   - Archive creation / writing (Diablo 1 save-game compatible)
 *   - SDL streaming adapters (SDL_RWops for SDL 1.2 & 2, SDL_IOStream for SDL 3)
 *   - Error reporting
 *
 * The library is written in C99 and compiles cleanly as C++11 or later
 * (up to C++20).  All public symbols use C linkage.
 */

#ifndef MPQFS_MPQFS_H
#define MPQFS_MPQFS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>  /* FILE* for mpqfs_open_fp */

/* -----------------------------------------------------------------------
 * Portability: bool
 *
 * In C++ bool is a keyword.  In C99 we need <stdbool.h>.
 * ----------------------------------------------------------------------- */

#ifndef __cplusplus
#  include <stdbool.h>
#endif

/* -----------------------------------------------------------------------
 * MPQFS_HAS_FDOPEN — mirrors the detection in the internal platform
 * header so that the public API can conditionally declare mpqfs_open_fd.
 * ----------------------------------------------------------------------- */

#ifndef MPQFS_HAS_FDOPEN
#  if defined(__PS2__) || defined(_3DS) || defined(__vita__) \
      || defined(__NX__) /* Nintendo Switch (devkitPro) */
#    define MPQFS_HAS_FDOPEN 0
#  elif defined(_MSC_VER) || defined(__DJGPP__) || defined(__unix__) \
        || defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__) \
        || defined(__EMSCRIPTEN__) || defined(__CYGWIN__) || defined(__HAIKU__)
#    define MPQFS_HAS_FDOPEN 1
#  else
#    define MPQFS_HAS_FDOPEN 0
#  endif
#endif

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
 *
 * When the library is built as a static archive (the common case for
 * game engines), MPQFS_API expands to nothing.  For shared-library
 * builds, define MPQFS_SHARED before including this header.
 * ----------------------------------------------------------------------- */

#ifndef MPQFS_API
#  if defined(MPQFS_SHARED)
#    if defined(_WIN32) || defined(__CYGWIN__)
#      ifdef MPQFS_BUILDING
#        define MPQFS_API __declspec(dllexport)
#      else
#        define MPQFS_API __declspec(dllimport)
#      endif
#    elif defined(__GNUC__) && __GNUC__ >= 4
#      define MPQFS_API __attribute__((visibility("default")))
#    else
#      define MPQFS_API
#    endif
#  else
     /* Static library — no special annotation needed. */
#    define MPQFS_API
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Opaque handles
 *
 * All API functions that take an archive pointer require a non-NULL
 * handle previously obtained from one of the mpqfs_open*() functions.
 *
 * The writer handle is obtained from mpqfs_writer_create*() and is
 * consumed by mpqfs_writer_close() or mpqfs_writer_discard().
 * ----------------------------------------------------------------------- */

typedef struct mpqfs_archive mpqfs_archive_t;
typedef struct mpqfs_writer  mpqfs_writer_t;

/* -----------------------------------------------------------------------
 * Archive lifecycle (reading)
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
 * Open an MPQ archive from an already-open FILE pointer.
 *
 * This is the most portable open variant — FILE* is available on every
 * platform.  The library does NOT take ownership of the FILE*; the caller
 * must ensure it remains valid for the lifetime of the returned handle
 * and must fclose() it after calling mpqfs_close().
 *
 * @param fp  A readable FILE* positioned anywhere; the library will scan
 *            for the MPQ header.
 * @return    Opaque archive handle, or NULL on error.
 */
MPQFS_API mpqfs_archive_t *mpqfs_open_fp(FILE *fp);

#if MPQFS_HAS_FDOPEN

/**
 * Open an MPQ archive from an already-open file descriptor.
 *
 * The library takes ownership of the descriptor — it will be closed when
 * mpqfs_close() is called on the returned handle.
 *
 * This function is only available on platforms that provide fdopen()
 * (POSIX, Windows via _fdopen, DJGPP).  Check MPQFS_HAS_FDOPEN.
 *
 * @param fd  A readable file descriptor positioned anywhere; the library
 *            will scan for the MPQ header.
 * @return    Opaque archive handle, or NULL on error.
 */
MPQFS_API mpqfs_archive_t *mpqfs_open_fd(int fd);

#endif /* MPQFS_HAS_FDOPEN */

/**
 * Close an archive and free all associated resources.
 *
 * Any SDL streams (SDL_RWops / SDL_IOStream) created from this archive
 * must be closed *before* the archive itself.
 *
 * If the archive was opened with mpqfs_open() or mpqfs_open_fd(), the
 * underlying file is closed.  If opened with mpqfs_open_fp(), the FILE*
 * is NOT closed — the caller retains ownership.
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
 * Archive writing (Diablo 1 save-game compatible)
 *
 * The writer creates MPQ v1 archives in the style used by DevilutionX
 * for its save-game (.sv / .hsv) files:
 *
 *   - PKWARE DCL implode compression (sector-based, with offset tables)
 *   - Falls back to uncompressed storage when compression doesn't help
 *   - No file-level encryption
 *   - Hash and block tables encrypted with standard MPQ keys
 *   - Both tables are hash_table_size entries (block table padded with zeros)
 *   - Tables placed immediately after header, before file data
 *
 * Produced layout:
 *
 *   [MPQ Header  — 32 bytes]
 *   [Block table — hash_table_size × 16 bytes, encrypted]
 *   [Hash table  — hash_table_size × 16 bytes, encrypted]
 *   [File data   — PKWARE implode compressed, with sector offset tables]
 *
 * Typical usage:
 *
 *   mpqfs_writer_t *w = mpqfs_writer_create("save.sv", 16);
 *   mpqfs_writer_add_file(w, "hero", hero_data, hero_size);
 *   mpqfs_writer_add_file(w, "game", game_data, game_size);
 *   mpqfs_writer_close(w);          // finalises and frees the writer
 *
 * If an error occurs before close, call mpqfs_writer_discard() to
 * release all resources without writing.
 *
 * The writer makes owned copies of all filenames and data passed to
 * mpqfs_writer_add_file(), so the caller may free them immediately.
 * ----------------------------------------------------------------------- */

/**
 * Create a new MPQ archive writer targeting a filesystem path.
 *
 * The file is opened for writing (truncated if it exists).  The writer
 * takes ownership of the file and will close it on mpqfs_writer_close()
 * or mpqfs_writer_discard().
 *
 * @param path             Filesystem path for the new archive.
 * @param hash_table_size  Desired number of hash table entries.  Will be
 *                         rounded up to the next power of two (minimum 4).
 *                         Must be larger than the number of files to add.
 * @return                 Writer handle, or NULL on error (see mpqfs_last_error()).
 */
MPQFS_API mpqfs_writer_t *mpqfs_writer_create(const char *path,
                                              uint32_t hash_table_size);

/**
 * Create a new MPQ archive writer targeting an already-open FILE pointer.
 *
 * The library does NOT take ownership of the FILE*; the caller must
 * ensure it remains valid until mpqfs_writer_close() or
 * mpqfs_writer_discard() is called, and must fclose() it afterwards.
 *
 * @param fp               A writable FILE* positioned at the desired
 *                         archive start (typically offset 0).
 * @param hash_table_size  Desired number of hash table entries (see above).
 * @return                 Writer handle, or NULL on error.
 */
MPQFS_API mpqfs_writer_t *mpqfs_writer_create_fp(FILE *fp,
                                                 uint32_t hash_table_size);

#if MPQFS_HAS_FDOPEN

/**
 * Create a new MPQ archive writer targeting a file descriptor.
 *
 * The library takes ownership of the descriptor — it will be closed
 * when mpqfs_writer_close() or mpqfs_writer_discard() is called.
 *
 * @param fd               A writable file descriptor.
 * @param hash_table_size  Desired number of hash table entries (see above).
 * @return                 Writer handle, or NULL on error.
 */
MPQFS_API mpqfs_writer_t *mpqfs_writer_create_fd(int fd,
                                                 uint32_t hash_table_size);

#endif /* MPQFS_HAS_FDOPEN */

/**
 * Add a file to the archive being constructed.
 *
 * The writer makes owned copies of both the filename and the data, so
 * the caller may free them immediately after this call returns.
 *
 * Files are compressed with PKWARE DCL implode (sector-based) and
 * stored without file-level encryption, matching the DevilutionX save
 * format.  If compression does not reduce the file size, it is stored
 * uncompressed.  The block table entry will have the MPQ_FILE_EXISTS
 * flag, and additionally MPQ_FILE_IMPLODE if any sector compressed.
 *
 * @param writer    Writer handle.
 * @param filename  Archive-relative path (e.g. "hero" or "game\\0.dun").
 *                  Uses backslash separators per MPQ convention; forward
 *                  slashes are accepted and normalised during hashing.
 * @param data      Pointer to the file data (may be NULL if size is 0).
 * @param size      Size of the file data in bytes.
 * @return          true on success, false on error.
 */
MPQFS_API bool mpqfs_writer_add_file(mpqfs_writer_t *writer,
                                     const char *filename,
                                     const void *data, size_t size);

/**
 * Finalise the archive and close the writer.
 *
 * This writes the MPQ header, all file data, and the encrypted hash
 * and block tables to the output file, then frees all resources held
 * by the writer.
 *
 * After this call the writer handle is invalid (freed) regardless of
 * whether the call succeeded or failed.
 *
 * @param writer  Writer handle (consumed — do not use after this call).
 * @return        true on success, false if writing failed.
 */
MPQFS_API bool mpqfs_writer_close(mpqfs_writer_t *writer);

/**
 * Discard a writer without writing any archive data.
 *
 * All resources held by the writer are freed.  If the writer owns the
 * underlying file handle, it is closed.  No archive data is written.
 *
 * @param writer  Writer handle (consumed — do not use after this call).
 *                NULL is safely ignored.
 */
MPQFS_API void mpqfs_writer_discard(mpqfs_writer_t *writer);

/* -----------------------------------------------------------------------
 * Error handling
 * ----------------------------------------------------------------------- */

/**
 * Return a human-readable description of the last error that occurred
 * on the calling thread, or NULL if no error has been recorded.
 *
 * The returned pointer is valid until the next mpqfs call on the same
 * thread.  On single-threaded platforms (DOS, PS2, ...) it is a
 * process-global.
 */
MPQFS_API const char *mpqfs_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQFS_H */