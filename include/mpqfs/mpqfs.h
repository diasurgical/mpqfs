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
      || defined(__NX__) /* Nintendo Switch (devkitPro) */ \
      || defined(NXDK) /* original Xbox (nxdk) */ \
      || defined(__UWP__) /* Xbox UWP / Gaming Desktop */
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
#   include <SDL_rwops.h>
#   include <SDL.h>
#elif defined(MPQFS_USE_SDL1) && MPQFS_USE_SDL1
#   include <SDL_rwops.h>
#   include <SDL.h>
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

#ifndef MPQFS_ARCHIVE_T_DEFINED
typedef struct mpqfs_archive mpqfs_archive_t;
#endif
#ifndef MPQFS_WRITER_T_DEFINED
typedef struct mpqfs_writer  mpqfs_writer_t;
#endif

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
 * Create an independent clone of an open archive.
 *
 * The clone re-opens the underlying file so that it has its own FILE*
 * and can be read concurrently with the original.  The clone must be
 * closed independently with mpqfs_close().
 *
 * This is needed for thread-safe SDL streaming: the audio thread gets
 * a cloned archive so its fseek/fread calls don't race with the main
 * thread.
 *
 * Returns NULL on error (e.g. if the original was opened via
 * mpqfs_open_fp and the path is not known).
 *
 * @param archive  Handle to clone (must not be NULL).
 * @return         New archive handle, or NULL on error (see mpqfs_last_error()).
 */
MPQFS_API mpqfs_archive_t *mpqfs_clone(const mpqfs_archive_t *archive);

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
 * Look up a filename and return its hash table entry index.
 *
 * This performs the full hash-table probe (computing the table index,
 * name_a, and name_b hashes internally) and returns the position within
 * the archive's hash table where the matching entry was found.
 *
 * The returned value can be passed to mpqfs_has_file_hash(),
 * mpqfs_file_size_from_hash(), mpqfs_open_io_from_hash(), or
 * mpqfs_open_rwops_from_hash() to avoid redundant hashing on
 * subsequent operations for the same file.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path (e.g. "levels\\l1data\\l1.min").
 * @return          Hash table entry index, or UINT32_MAX if not found.
 */
MPQFS_API uint32_t mpqfs_find_hash(mpqfs_archive_t *archive, const char *filename);

/**
 * Check whether a hash table entry refers to a valid, existing file.
 *
 * The hash parameter is a hash table entry index — the position within
 * the archive's hash table where a file's entry was found (e.g. as
 * returned by an earlier lookup).  This allows callers that have already
 * resolved a filename to a hash table slot to skip redundant hashing.
 *
 * @param archive  Open archive handle.
 * @param hash     Hash table entry index.
 * @return         true if the entry refers to a valid, existing file.
 */
MPQFS_API bool mpqfs_has_file_hash(mpqfs_archive_t *archive, uint32_t hash);

/**
 * Return the uncompressed size of a file in the archive.
 *
 * @param archive   Open archive handle.
 * @param filename  Archive-relative path.
 * @return          Uncompressed size in bytes, or 0 if the file is not found.
 */
MPQFS_API size_t mpqfs_file_size(mpqfs_archive_t *archive, const char *filename);

/**
 * @brief Return the uncompressed size of the file identified by hash.
 *
 * This is the hash-based counterpart of mpqfs_file_size().  The @p hash
 * parameter is a hash table entry index obtained from mpqfs_find_hash().
 *
 * @param archive   Open archive handle.
 * @param hash      Hash table entry index.
 * @return          Uncompressed size in bytes, or 0 on error.
 */
MPQFS_API size_t mpqfs_file_size_from_hash(mpqfs_archive_t *archive, uint32_t hash);

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
 *
 * The "threadsafe" variants clone the archive internally so the returned
 * stream owns an independent FILE* and can be used from any thread
 * without racing with the original archive's reads.  The cloned archive
 * is closed automatically when the stream is closed.
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

/**
 * Create an SDL 3 IOStream for a file identified by hash table entry.
 *
 * This is the hash-based counterpart of mpqfs_open_io().  The hash
 * parameter is a hash table entry index (see mpqfs_has_file_hash()).
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle.
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_IOStream, or NULL on error.
 */
MPQFS_API SDL_IOStream *mpqfs_open_io_from_hash(mpqfs_archive_t *archive,
                                                uint32_t hash);

/**
 * Create an SDL 3 IOStream that owns an independent archive clone.
 *
 * The returned stream is fully self-contained and safe to use from any
 * thread.  Closing the stream closes the internal clone.
 *
 * @param archive   Open archive handle (used to clone).
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_IOStream, or NULL on error.
 */
MPQFS_API SDL_IOStream *mpqfs_open_io_threadsafe(mpqfs_archive_t *archive,
                                                 const char *filename);

/**
 * Create an SDL 3 IOStream that owns an independent archive clone,
 * using a pre-resolved hash table entry index.
 *
 * This is the hash-based counterpart of mpqfs_open_io_threadsafe().
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle (used to clone).
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_IOStream, or NULL on error.
 */
MPQFS_API SDL_IOStream *mpqfs_open_io_threadsafe_from_hash(
    mpqfs_archive_t *archive, uint32_t hash);

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

/**
 * Create an SDL 2 RWops for a file identified by hash table entry.
 *
 * This is the hash-based counterpart of mpqfs_open_rwops().  The hash
 * parameter is a hash table entry index (see mpqfs_has_file_hash()).
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle.
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_from_hash(mpqfs_archive_t *archive,
                                                uint32_t hash);

/**
 * Create an SDL 2 RWops that owns an independent archive clone.
 *
 * The returned stream is fully self-contained and safe to use from any
 * thread.  Closing the stream closes the internal clone.
 *
 * @param archive   Open archive handle (used to clone).
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_threadsafe(mpqfs_archive_t *archive,
                                                 const char *filename);

/**
 * Create an SDL 2 RWops that owns an independent archive clone,
 * using a pre-resolved hash table entry index.
 *
 * This is the hash-based counterpart of mpqfs_open_rwops_threadsafe().
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle (used to clone).
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_threadsafe_from_hash(
    mpqfs_archive_t *archive, uint32_t hash);

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

/**
 * Create an SDL 1.2 RWops for a file identified by hash table entry.
 *
 * This is the hash-based counterpart of mpqfs_open_rwops().  The hash
 * parameter is a hash table entry index (see mpqfs_has_file_hash()).
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle.
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_from_hash(mpqfs_archive_t *archive,
                                                uint32_t hash);

/**
 * Create an SDL 1.2 RWops that owns an independent archive clone.
 *
 * The returned stream is fully self-contained and safe to use from any
 * thread.  Closing the stream closes the internal clone.
 *
 * @param archive   Open archive handle (used to clone).
 * @param filename  Archive-relative path.
 * @return          A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_threadsafe(mpqfs_archive_t *archive,
                                                 const char *filename);

/**
 * Create an SDL 1.2 RWops that owns an independent archive clone,
 * using a pre-resolved hash table entry index.
 *
 * This is the hash-based counterpart of mpqfs_open_rwops_threadsafe().
 *
 * @note Encrypted files are NOT supported by this function because the
 *       filename is not available for key derivation.  For Diablo 1
 *       assets (which are never encrypted) this is not a limitation.
 *
 * @param archive  Open archive handle (used to clone).
 * @param hash     Hash table entry index.
 * @return         A seekable, read-only SDL_RWops, or NULL on error.
 */
MPQFS_API SDL_RWops *mpqfs_open_rwops_threadsafe_from_hash(
    mpqfs_archive_t *archive, uint32_t hash);

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

/* -----------------------------------------------------------------------
 * Crypto primitives
 *
 * These expose the internal MPQ cryptographic functions for use by
 * consumers that implement their own MPQ writer (e.g. DevilutionX's
 * MpqWriter).  Every function calls mpqfs_crypto_init() internally,
 * so explicit initialisation is never required.
 * ----------------------------------------------------------------------- */

/**
 * Initialise the global MPQ encryption table.
 *
 * Called automatically by mpqfs_open() / mpqfs_writer_create() and by
 * every other public crypto function.  Idempotent and thread-safe
 * after the first call.  Provided for consumers that want to be
 * explicit about initialisation order.
 */
MPQFS_API void mpqfs_crypto_init(void);

/**
 * Compute an MPQ hash for a NUL-terminated filename.
 *
 * hash_type is one of:
 *   MPQFS_HASH_TABLE_INDEX (0x000)
 *   MPQFS_HASH_NAME_A      (0x100)
 *   MPQFS_HASH_NAME_B      (0x200)
 *   MPQFS_HASH_FILE_KEY    (0x300)
 *
 * @param str        NUL-terminated string to hash.
 * @param hash_type  One of the MPQFS_HASH_* constants.
 * @return           The 32-bit hash value.
 */
MPQFS_API uint32_t mpqfs_hash_string(const char *str, uint32_t hash_type);

/**
 * Length-delimited variant (no NUL terminator required).
 *
 * @param str        Pointer to the string data.
 * @param len        Number of bytes to hash.
 * @param hash_type  One of the MPQFS_HASH_* constants.
 * @return           The 32-bit hash value.
 */
MPQFS_API uint32_t mpqfs_hash_string_s(const char *str, size_t len,
                                       uint32_t hash_type);

/**
 * Encrypt an array of uint32_t values in-place.
 *
 * Input data is in host byte order.  On big-endian systems the result
 * is byte-swapped to little-endian, ready for writing to an MPQ file.
 * On little-endian systems this is a no-op since host == LE.
 *
 * @param data   Pointer to the data to encrypt (host order in, LE out).
 * @param count  Number of uint32_t words (NOT bytes).
 * @param key    Encryption key.
 */
MPQFS_API void mpqfs_encrypt_block(uint32_t *data, size_t count, uint32_t key);

/**
 * Decrypt an array of uint32_t values in-place.
 *
 * Input data is little-endian (as read from an MPQ file).  On big-endian
 * systems the data is byte-swapped to host order before decryption.
 * On little-endian systems this is a no-op since host == LE.
 *
 * @param data   Pointer to the data to decrypt (LE in, host order out).
 * @param count  Number of uint32_t words (NOT bytes).
 * @param key    Decryption key.
 */
MPQFS_API void mpqfs_decrypt_block(uint32_t *data, size_t count, uint32_t key);

/* Hash-type constants */
#define MPQFS_HASH_TABLE_INDEX  0x000
#define MPQFS_HASH_NAME_A       0x100
#define MPQFS_HASH_NAME_B       0x200
#define MPQFS_HASH_FILE_KEY     0x300

/* Pre-calculated encryption keys for the block and hash tables.
 * These are hash("(block table)", MPQFS_HASH_FILE_KEY) and
 * hash("(hash table)", MPQFS_HASH_FILE_KEY) respectively.       */
#define MPQFS_BLOCK_TABLE_KEY   3968054179u
#define MPQFS_HASH_TABLE_KEY    3283040112u

/* -----------------------------------------------------------------------
 * Convenience: compute a file-hash triple
 *
 * DevilutionX pre-computes { hash_table_index, name_a, name_b } for
 * filenames and stores them for fast lookup.
 * ----------------------------------------------------------------------- */

/**
 * Compute the three MPQ hash values for a NUL-terminated filename.
 *
 * @param filename   NUL-terminated filename to hash.
 * @param out_index  Receives hash(filename, MPQFS_HASH_TABLE_INDEX).  May be NULL.
 * @param out_hash_a Receives hash(filename, MPQFS_HASH_NAME_A).  May be NULL.
 * @param out_hash_b Receives hash(filename, MPQFS_HASH_NAME_B).  May be NULL.
 */
MPQFS_API void mpqfs_file_hash(const char *filename,
                               uint32_t *out_index,
                               uint32_t *out_hash_a,
                               uint32_t *out_hash_b);

/**
 * Length-delimited variant (no NUL terminator required).
 *
 * @param filename   Pointer to the filename data.
 * @param len        Number of bytes.
 * @param out_index  Receives hash(filename, MPQFS_HASH_TABLE_INDEX).  May be NULL.
 * @param out_hash_a Receives hash(filename, MPQFS_HASH_NAME_A).  May be NULL.
 * @param out_hash_b Receives hash(filename, MPQFS_HASH_NAME_B).  May be NULL.
 */
MPQFS_API void mpqfs_file_hash_s(const char *filename, size_t len,
                                 uint32_t *out_index,
                                 uint32_t *out_hash_a,
                                 uint32_t *out_hash_b);

/* -----------------------------------------------------------------------
 * PKWARE DCL compress / decompress
 *
 * These expose the internal PKWARE Data Compression Library (DCL)
 * implode/explode routines as public API, allowing consumers to
 * compress and decompress arbitrary data without a separate PKWare
 * library.
 * ----------------------------------------------------------------------- */

/**
 * PKWARE DCL "implode" — compress src into dst.
 *
 * On entry *dst_size holds the capacity of dst.
 * On success *dst_size is updated to the compressed size.
 *
 * @param src        Source data to compress.
 * @param src_size   Size of source data in bytes.
 * @param dst        Destination buffer.
 * @param dst_size   In: capacity of dst.  Out: compressed size.
 * @param dict_bits  Dictionary size: 4 (1024), 5 (2048), or 6 (4096).
 * @return           0 on success, non-zero on error (output too small, etc.).
 */
MPQFS_API int mpqfs_pk_implode(const uint8_t *src, size_t src_size,
                               uint8_t *dst, size_t *dst_size,
                               int dict_bits);

/**
 * PKWARE DCL "explode" — decompress src into dst.
 *
 * On entry *dst_size holds the capacity of dst (expected uncompressed size).
 * On success *dst_size is updated to the actual decompressed size.
 *
 * @param src        Compressed source data.
 * @param src_size   Size of compressed data in bytes.
 * @param dst        Destination buffer.
 * @param dst_size   In: capacity of dst.  Out: decompressed size.
 * @return           0 on success, non-zero on error (corrupt input, etc.).
 */
MPQFS_API int mpqfs_pk_explode(const uint8_t *src, size_t src_size,
                               uint8_t *dst, size_t *dst_size);

#ifdef __cplusplus
}
#endif

#endif /* MPQFS_MPQFS_H */