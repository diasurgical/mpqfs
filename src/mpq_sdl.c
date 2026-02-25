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
 */

#include "mpq_archive.h"
#include "mpq_stream.h"
#include "mpq_crypto.h"

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

/* ======================================================================
 * SDL 3 — SDL_IOStream interface
 * ====================================================================== */
#if MPQFS_SDL_VERSION == 3

static Sint64 SDLCALL mpqfs_sdl3_size(void *userdata)
{
    mpq_stream_t *stream = (mpq_stream_t *)userdata;
    return (Sint64)mpq_stream_size(stream);
}

static Sint64 SDLCALL mpqfs_sdl3_seek(void *userdata, Sint64 offset, int whence)
{
    mpq_stream_t *stream = (mpq_stream_t *)userdata;

    int w;
    switch (whence) {
    case SDL_IO_SEEK_SET: w = SEEK_SET; break;
    case SDL_IO_SEEK_CUR: w = SEEK_CUR; break;
    case SDL_IO_SEEK_END: w = SEEK_END; break;
    default:
        return -1;
    }

    int64_t pos = mpq_stream_seek(stream, (int64_t)offset, w);
    return (Sint64)pos;
}

static size_t SDLCALL mpqfs_sdl3_read(void *userdata, void *ptr, size_t size, SDL_IOStatus *status)
{
    mpq_stream_t *stream = (mpq_stream_t *)userdata;

    if (size == 0) {
        if (status) *status = SDL_IO_STATUS_READY;
        return 0;
    }

    size_t n = mpq_stream_read(stream, ptr, size);
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
    (void)userdata;
    (void)ptr;
    (void)size;
    /* Read-only stream. */
    if (status) *status = SDL_IO_STATUS_ERROR;
    return 0;
}

static bool SDLCALL mpqfs_sdl3_close(void *userdata)
{
    mpq_stream_t *stream = (mpq_stream_t *)userdata;
    mpq_stream_close(stream);
    return true;
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

    mpq_stream_t *stream = mpq_stream_open(archive, bi);
    if (!stream)
        return NULL;

    SDL_IOStreamInterface iface;
    SDL_INIT_INTERFACE(&iface);
    iface.size  = mpqfs_sdl3_size;
    iface.seek  = mpqfs_sdl3_seek;
    iface.read  = mpqfs_sdl3_read;
    iface.write = mpqfs_sdl3_write;
    iface.close = mpqfs_sdl3_close;

    SDL_IOStream *io = SDL_OpenIO(&iface, stream);
    if (!io) {
        mpq_stream_close(stream);
        mpq_set_error(archive, "mpqfs_open_io: SDL_OpenIO failed: %s",
                      SDL_GetError());
        return NULL;
    }

    return io;
}

/* ======================================================================
 * SDL 2 — SDL_RWops interface
 * ====================================================================== */
#elif MPQFS_SDL_VERSION == 2

static Sint64 SDLCALL mpqfs_sdl2_size(SDL_RWops *ctx)
{
    mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;
    return (Sint64)mpq_stream_size(stream);
}

static Sint64 SDLCALL mpqfs_sdl2_seek(SDL_RWops *ctx, Sint64 offset, int whence)
{
    mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;

    int w;
    switch (whence) {
    case RW_SEEK_SET: w = SEEK_SET; break;
    case RW_SEEK_CUR: w = SEEK_CUR; break;
    case RW_SEEK_END: w = SEEK_END; break;
    default:
        return -1;
    }

    int64_t pos = mpq_stream_seek(stream, (int64_t)offset, w);
    return (Sint64)pos;
}

static size_t SDLCALL mpqfs_sdl2_read(SDL_RWops *ctx, void *ptr,
                                       size_t size, size_t maxnum)
{
    mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;

    size_t total = size * maxnum;
    if (total == 0)
        return 0;

    size_t n = mpq_stream_read(stream, ptr, total);
    if (n == (size_t)-1)
        return 0;

    /* SDL 2 expects the return value in units of `size`. */
    return n / size;
}

static size_t SDLCALL mpqfs_sdl2_write(SDL_RWops *ctx, const void *ptr,
                                        size_t size, size_t num)
{
    (void)ctx;
    (void)ptr;
    (void)size;
    (void)num;
    /* Read-only. */
    return 0;
}

static int SDLCALL mpqfs_sdl2_close(SDL_RWops *ctx)
{
    if (ctx) {
        mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;
        mpq_stream_close(stream);
        SDL_FreeRW(ctx);
    }
    return 0;
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

    mpq_stream_t *stream = mpq_stream_open(archive, bi);
    if (!stream)
        return NULL;

    SDL_RWops *rw = SDL_AllocRW();
    if (!rw) {
        mpq_stream_close(stream);
        mpq_set_error(archive, "mpqfs_open_rwops: SDL_AllocRW failed");
        return NULL;
    }

    rw->type  = SDL_RWOPS_UNKNOWN;
    rw->size  = mpqfs_sdl2_size;
    rw->seek  = mpqfs_sdl2_seek;
    rw->read  = mpqfs_sdl2_read;
    rw->write = mpqfs_sdl2_write;
    rw->close = mpqfs_sdl2_close;
    rw->hidden.unknown.data1 = stream;

    return rw;
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

static int SDLCALL mpqfs_sdl1_seek(SDL_RWops *ctx, int offset, int whence)
{
    mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;

    int64_t pos = mpq_stream_seek(stream, (int64_t)offset, whence);
    return (int)pos;
}

static int SDLCALL mpqfs_sdl1_read(SDL_RWops *ctx, void *ptr,
                                    int size, int maxnum)
{
    mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;

    size_t total = (size_t)size * (size_t)maxnum;
    if (total == 0)
        return 0;

    size_t n = mpq_stream_read(stream, ptr, total);
    if (n == (size_t)-1)
        return -1;

    return (int)(n / (size_t)size);
}

static int SDLCALL mpqfs_sdl1_write(SDL_RWops *ctx, const void *ptr,
                                     int size, int num)
{
    (void)ctx;
    (void)ptr;
    (void)size;
    (void)num;
    return -1;
}

static int SDLCALL mpqfs_sdl1_close(SDL_RWops *ctx)
{
    if (ctx) {
        mpq_stream_t *stream = (mpq_stream_t *)ctx->hidden.unknown.data1;
        mpq_stream_close(stream);
        SDL_FreeRW(ctx);
    }
    return 0;
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

    mpq_stream_t *stream = mpq_stream_open(archive, bi);
    if (!stream)
        return NULL;

    SDL_RWops *rw = SDL_AllocRW();
    if (!rw) {
        mpq_stream_close(stream);
        mpq_set_error(archive, "mpqfs_open_rwops: SDL_AllocRW failed");
        return NULL;
    }

    rw->seek  = mpqfs_sdl1_seek;
    rw->read  = mpqfs_sdl1_read;
    rw->write = mpqfs_sdl1_write;
    rw->close = mpqfs_sdl1_close;
    rw->hidden.unknown.data1 = stream;

    return rw;
}

#endif /* MPQFS_SDL_VERSION */

#endif /* MPQFS_SDL_VERSION > 0 */