/*
 * mpqfs — minimal MPQ v1 reader with SDL integration
 * SPDX-License-Identifier: MIT
 *
 * SDL adapter: wraps mpq_stream_t into SDL_RWops (SDL 1.2 / SDL 2)
 * or SDL_IOStream (SDL 3) so that files inside an MPQ archive can be
 * handed directly to SDL_mixer, SDL_image, or any other SDL-based API
 * that accepts a stream.
 *
 * The correct SDL version is selected at compile time via the
 * MPQFS_SDL_VERSION define (set by CMake).
 *
 * Thread-safe variants (mpqfs_open_rwops_threadsafe / mpqfs_open_io_threadsafe)
 * clone the archive so the returned stream owns an independent FILE* and can
 * be used from any thread without racing with the original archive's reads.
 */

#include "mpq_platform.h"
#include "mpq_archive.h"
#include "mpq_stream.h"
#include "mpq_crypto.h"
#include <mpqfs/mpqfs.h>

#include <stdlib.h>
#include <string.h>

/* Only compile this translation unit when an SDL version is selected. */
#if !defined(MPQFS_SDL_VERSION) || MPQFS_SDL_VERSION == 0
/* Nothing to compile — SDL integration disabled. */
#else

#if MPQFS_SDL_VERSION == 3
#include <SDL3/SDL.h>
#elif MPQFS_SDL_VERSION == 2
#include <SDL2/SDL.h>
#else
#include <SDL/SDL.h>
#include <SDL/SDL_rwops.h>
#endif

/* -----------------------------------------------------------------------
 * Internal wrapper: bundles a stream with an optionally-owned archive
 *
 * For normal (non-threadsafe) streams, owned_archive is NULL and the
 * stream's parent archive is NOT closed when the SDL stream closes.
 *
 * For threadsafe streams, owned_archive points to a clone created by
 * mpqfs_clone().  The close callback will close both the stream and
 * the cloned archive.
 * ----------------------------------------------------------------------- */

typedef struct mpqfs_sdl_ctx {
    mpq_stream_t      *stream;          /* Always non-NULL                  */
    mpqfs_archive_t   *owned_archive;   /* Non-NULL if we own the clone    */
} mpqfs_sdl_ctx_t;

static mpqfs_sdl_ctx_t *mpqfs_sdl_ctx_new(mpq_stream_t *stream,
                                           mpqfs_archive_t *owned_archive)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)malloc(sizeof(*ctx));
    if (!ctx) {
        mpq_stream_close(stream);
        if (owned_archive)
            mpqfs_close(owned_archive);
        return NULL;
    }
    ctx->stream         = stream;
    ctx->owned_archive  = owned_archive;
    return ctx;
}

static void mpqfs_sdl_ctx_free(mpqfs_sdl_ctx_t *ctx)
{
    if (!ctx)
        return;
    mpq_stream_close(ctx->stream);
    if (ctx->owned_archive)
        mpqfs_close(ctx->owned_archive);
    free(ctx);
}

/* ======================================================================
 * SDL 3 — SDL_IOStream interface
 * ====================================================================== */
#if MPQFS_SDL_VERSION == 3

static Sint64 SDLCALL mpqfs_sdl3_size(void *userdata)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)userdata;
    return (Sint64)mpq_stream_size(ctx->stream);
}

static Sint64 SDLCALL mpqfs_sdl3_seek(void *userdata, Sint64 offset, int whence)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)userdata;

    int w;
    switch (whence) {
    case SDL_IO_SEEK_SET: w = SEEK_SET; break;
    case SDL_IO_SEEK_CUR: w = SEEK_CUR; break;
    case SDL_IO_SEEK_END: w = SEEK_END; break;
    default:
        return -1;
    }

    int64_t pos = mpq_stream_seek(ctx->stream, (int64_t)offset, w);
    return (Sint64)pos;
}

static size_t SDLCALL mpqfs_sdl3_read(void *userdata, void *ptr, size_t size, SDL_IOStatus *status)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)userdata;

    if (size == 0) {
        if (status) *status = SDL_IO_STATUS_READY;
        return 0;
    }

    size_t n = mpq_stream_read(ctx->stream, ptr, size);
    if (n == (size_t)-1) {
        if (status) *status = SDL_IO_STATUS_ERROR;
        return 0;
    }
    if (n == 0) {
        if (status) *status = SDL_IO_STATUS_EOF;
        return 0;
    }

    if (status) *status = SDL_IO_STATUS_READY;
    return n;
}

static size_t SDLCALL mpqfs_sdl3_write(void *userdata, const void *ptr, size_t size, SDL_IOStatus *status)
{
    MPQFS_UNUSED(userdata);
    MPQFS_UNUSED(ptr);
    MPQFS_UNUSED(size);
    /* Read-only stream. */
    if (status) *status = SDL_IO_STATUS_ERROR;
    return 0;
}

static bool SDLCALL mpqfs_sdl3_close(void *userdata)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)userdata;
    mpqfs_sdl_ctx_free(ctx);
    return true;
}

/* Internal helper: create an SDL 3 IOStream from a ctx (takes ownership). */
static SDL_IOStream *mpqfs_sdl3_create_io(mpqfs_sdl_ctx_t *ctx,
                                           mpqfs_archive_t *err_archive)
{
    SDL_IOStreamInterface iface;
    SDL_INIT_INTERFACE(&iface);
    iface.size  = mpqfs_sdl3_size;
    iface.seek  = mpqfs_sdl3_seek;
    iface.read  = mpqfs_sdl3_read;
    iface.write = mpqfs_sdl3_write;
    iface.close = mpqfs_sdl3_close;

    SDL_IOStream *io = SDL_OpenIO(&iface, ctx);
    if (!io) {
        mpq_set_error(err_archive, "SDL_OpenIO failed: %s", SDL_GetError());
        mpqfs_sdl_ctx_free(ctx);
        return NULL;
    }

    return io;
}

SDL_IOStream *mpqfs_open_io(mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return NULL;

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_io: file '%s' not found", filename);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(archive, bi, filename);
    if (!stream)
        return NULL;

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, NULL);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_io: out of memory");
        return NULL;
    }

    return mpqfs_sdl3_create_io(ctx, archive);
}

SDL_IOStream *mpqfs_open_io_threadsafe(mpqfs_archive_t *archive,
                                       const char *filename)
{
    if (!archive || !filename)
        return NULL;

    mpqfs_archive_t *clone = mpqfs_clone(archive);
    if (!clone)
        return NULL;  /* error already set by mpqfs_clone */

    uint32_t bi = mpq_lookup_file(clone, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_io_threadsafe: file '%s' not found",
                      filename);
        mpqfs_close(clone);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(clone, bi, filename);
    if (!stream) {
        mpqfs_close(clone);
        return NULL;
    }

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, clone);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_io_threadsafe: out of memory");
        return NULL;
    }

    return mpqfs_sdl3_create_io(ctx, archive);
}

/* ======================================================================
 * SDL 2 — SDL_RWops interface
 * ====================================================================== */
#elif MPQFS_SDL_VERSION == 2

static Sint64 SDLCALL mpqfs_sdl2_size(SDL_RWops *rw)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;
    return (Sint64)mpq_stream_size(ctx->stream);
}

static Sint64 SDLCALL mpqfs_sdl2_seek(SDL_RWops *rw, Sint64 offset, int whence)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;

    int w;
    switch (whence) {
    case RW_SEEK_SET: w = SEEK_SET; break;
    case RW_SEEK_CUR: w = SEEK_CUR; break;
    case RW_SEEK_END: w = SEEK_END; break;
    default:
        return -1;
    }

    int64_t pos = mpq_stream_seek(ctx->stream, (int64_t)offset, w);
    return (Sint64)pos;
}

static size_t SDLCALL mpqfs_sdl2_read(SDL_RWops *rw, void *ptr,
                                       size_t size, size_t maxnum)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;

    size_t total = size * maxnum;
    if (total == 0)
        return 0;

    size_t n = mpq_stream_read(ctx->stream, ptr, total);
    if (n == (size_t)-1)
        return 0;

    /* SDL 2 expects the return value in units of `size`. */
    return n / size;
}

static size_t SDLCALL mpqfs_sdl2_write(SDL_RWops *rw, const void *ptr,
                                        size_t size, size_t num)
{
    MPQFS_UNUSED(rw);
    MPQFS_UNUSED(ptr);
    MPQFS_UNUSED(size);
    MPQFS_UNUSED(num);
    /* Read-only. */
    return 0;
}

static int SDLCALL mpqfs_sdl2_close(SDL_RWops *rw)
{
    if (rw) {
        mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;
        mpqfs_sdl_ctx_free(ctx);
        SDL_FreeRW(rw);
    }
    return 0;
}

/* Internal helper: create an SDL 2 RWops from a ctx (takes ownership). */
static SDL_RWops *mpqfs_sdl2_create_rwops(mpqfs_sdl_ctx_t *ctx,
                                           mpqfs_archive_t *err_archive)
{
    SDL_RWops *rw = SDL_AllocRW();
    if (!rw) {
        mpq_set_error(err_archive, "SDL_AllocRW failed");
        mpqfs_sdl_ctx_free(ctx);
        return NULL;
    }

    rw->type  = SDL_RWOPS_UNKNOWN;
    rw->size  = mpqfs_sdl2_size;
    rw->seek  = mpqfs_sdl2_seek;
    rw->read  = mpqfs_sdl2_read;
    rw->write = mpqfs_sdl2_write;
    rw->close = mpqfs_sdl2_close;
    rw->hidden.unknown.data1 = ctx;

    return rw;
}

SDL_RWops *mpqfs_open_rwops(mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return NULL;

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_rwops: file '%s' not found", filename);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(archive, bi, filename);
    if (!stream)
        return NULL;

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, NULL);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_rwops: out of memory");
        return NULL;
    }

    return mpqfs_sdl2_create_rwops(ctx, archive);
}

SDL_RWops *mpqfs_open_rwops_threadsafe(mpqfs_archive_t *archive,
                                       const char *filename)
{
    if (!archive || !filename)
        return NULL;

    mpqfs_archive_t *clone = mpqfs_clone(archive);
    if (!clone)
        return NULL;  /* error already set by mpqfs_clone */

    uint32_t bi = mpq_lookup_file(clone, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_rwops_threadsafe: file '%s' not found",
                      filename);
        mpqfs_close(clone);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(clone, bi, filename);
    if (!stream) {
        mpqfs_close(clone);
        return NULL;
    }

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, clone);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_rwops_threadsafe: out of memory");
        return NULL;
    }

    return mpqfs_sdl2_create_rwops(ctx, archive);
}

/* ======================================================================
 * SDL 1.2 — SDL_RWops interface
 *
 * SDL 1.2's SDL_RWops has a different layout from SDL 2:
 *   - seek returns int (not Sint64)
 *   - read/write take int counts (not size_t)
 *   - no size callback
 *   - no type field
 * ====================================================================== */
#elif MPQFS_SDL_VERSION == 1

static int SDLCALL mpqfs_sdl1_seek(SDL_RWops *rw, int offset, int whence)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;

    int64_t pos = mpq_stream_seek(ctx->stream, (int64_t)offset, whence);
    return (int)pos;
}

static int SDLCALL mpqfs_sdl1_read(SDL_RWops *rw, void *ptr,
                                    int size, int maxnum)
{
    mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;

    size_t total = (size_t)size * (size_t)maxnum;
    if (total == 0)
        return 0;

    size_t n = mpq_stream_read(ctx->stream, ptr, total);
    if (n == (size_t)-1)
        return -1;

    return (int)(n / (size_t)size);
}

static int SDLCALL mpqfs_sdl1_write(SDL_RWops *rw, const void *ptr,
                                     int size, int num)
{
    MPQFS_UNUSED(rw);
    MPQFS_UNUSED(ptr);
    MPQFS_UNUSED(size);
    MPQFS_UNUSED(num);
    return -1;
}

static int SDLCALL mpqfs_sdl1_close(SDL_RWops *rw)
{
    if (rw) {
        mpqfs_sdl_ctx_t *ctx = (mpqfs_sdl_ctx_t *)rw->hidden.unknown.data1;
        mpqfs_sdl_ctx_free(ctx);
        SDL_FreeRW(rw);
    }
    return 0;
}

/* Internal helper: create an SDL 1.2 RWops from a ctx (takes ownership). */
static SDL_RWops *mpqfs_sdl1_create_rwops(mpqfs_sdl_ctx_t *ctx,
                                           mpqfs_archive_t *err_archive)
{
    SDL_RWops *rw = SDL_AllocRW();
    if (!rw) {
        mpq_set_error(err_archive, "SDL_AllocRW failed");
        mpqfs_sdl_ctx_free(ctx);
        return NULL;
    }

    rw->seek  = mpqfs_sdl1_seek;
    rw->read  = mpqfs_sdl1_read;
    rw->write = mpqfs_sdl1_write;
    rw->close = mpqfs_sdl1_close;
    rw->hidden.unknown.data1 = ctx;

    return rw;
}

SDL_RWops *mpqfs_open_rwops(mpqfs_archive_t *archive, const char *filename)
{
    if (!archive || !filename)
        return NULL;

    uint32_t bi = mpq_lookup_file(archive, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_rwops: file '%s' not found", filename);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(archive, bi, filename);
    if (!stream)
        return NULL;

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, NULL);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_rwops: out of memory");
        return NULL;
    }

    return mpqfs_sdl1_create_rwops(ctx, archive);
}

SDL_RWops *mpqfs_open_rwops_threadsafe(mpqfs_archive_t *archive,
                                       const char *filename)
{
    if (!archive || !filename)
        return NULL;

    mpqfs_archive_t *clone = mpqfs_clone(archive);
    if (!clone)
        return NULL;  /* error already set by mpqfs_clone */

    uint32_t bi = mpq_lookup_file(clone, filename);
    if (bi == UINT32_MAX) {
        mpq_set_error(archive, "mpqfs_open_rwops_threadsafe: file '%s' not found",
                      filename);
        mpqfs_close(clone);
        return NULL;
    }

    mpq_stream_t *stream = mpq_stream_open_named(clone, bi, filename);
    if (!stream) {
        mpqfs_close(clone);
        return NULL;
    }

    mpqfs_sdl_ctx_t *ctx = mpqfs_sdl_ctx_new(stream, clone);
    if (!ctx) {
        mpq_set_error(archive, "mpqfs_open_rwops_threadsafe: out of memory");
        return NULL;
    }

    return mpqfs_sdl1_create_rwops(ctx, archive);
}

#endif /* MPQFS_SDL_VERSION */

#endif /* MPQFS_SDL_VERSION > 0 */
