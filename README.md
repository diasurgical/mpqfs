# mpqfs

A minimal, MIT-licensed C library for reading MPQ v1 archives (as used by Diablo 1), with native SDL 1.2 / SDL 2 / SDL 3 integration.

**mpqfs** provides a clean, read-only streaming interface to files inside MPQ archives, designed to slot directly into game engines via `SDL_RWops` (SDL 1.2 & 2) or `SDL_IOStream` (SDL 3).

## Features

- MPQ v1 format support (Diablo 1 `DIABDAT.MPQ`)
- PKWARE DCL (implode) decompression — the compression scheme used by Diablo 1
- SDL 1.2 / SDL 2 / SDL 3 adapter: expose archived files as seekable streams
- Zero-copy sector-based streaming (files are not fully decompressed up front)
- Pure C99, no dynamic allocations beyond the initial open calls
- MIT licensed — suitable for embedding in any engine

## Building

mpqfs uses CMake:

```sh
mkdir build && cd build
cmake .. -DMPQFS_SDL_VERSION=2   # or 1, or 3
cmake --build .
```

### CMake options

| Option              | Default | Description                                  |
|---------------------|---------|----------------------------------------------|
| `MPQFS_SDL_VERSION` | `AUTO`  | SDL major version to target (1, 2, 3, or AUTO) |
| `MPQFS_BUILD_TESTS` | `ON`    | Build the test executable                    |

### Linking

mpqfs installs a CMake package. In your project:

```cmake
find_package(mpqfs REQUIRED)
target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

## Quick start

```c
#include <mpqfs/mpqfs.h>

/* Open the archive */
mpqfs_archive_t *archive = mpqfs_open("DIABDAT.MPQ");
if (!archive) {
    fprintf(stderr, "failed to open archive: %s\n", mpqfs_last_error());
    return 1;
}

/* Check if a file exists */
if (mpqfs_has_file(archive, "levels\\l1data\\l1.min")) {
    printf("found it!\n");
}

/* Read a whole file into memory */
size_t size = 0;
void *data = mpqfs_read_file(archive, "ui_art\\title.pcx", &size);
if (data) {
    /* use data (size bytes) ... */
    free(data);
}

/* Or get an SDL stream for incremental / streaming reads */
SDL_RWops *rw = mpqfs_open_rwops(archive, "music\\dtowne.wav");
if (rw) {
    Mix_Music *mus = Mix_LoadMUS_RW(rw, 1); /* SDL_mixer takes ownership */
}

mpqfs_close(archive);
```

For SDL 3, use `mpqfs_open_io()` which returns an `SDL_IOStream *` instead.

## API reference

### Archive lifecycle

```c
/* Open an MPQ archive from a filesystem path. Returns NULL on error. */
mpqfs_archive_t *mpqfs_open(const char *path);

/* Open from an existing file descriptor (takes ownership). */
mpqfs_archive_t *mpqfs_open_fd(int fd);

/* Close the archive and free all associated resources. */
void mpqfs_close(mpqfs_archive_t *archive);
```

### File queries

```c
/* Returns true if the named file exists in the archive. */
bool mpqfs_has_file(mpqfs_archive_t *archive, const char *filename);

/* Returns the uncompressed size of a file, or 0 if not found. */
size_t mpqfs_file_size(mpqfs_archive_t *archive, const char *filename);
```

### Whole-file reads

```c
/*
 * Read an entire file into a newly allocated buffer.
 * Sets *out_size to the number of bytes read.
 * Returns NULL on error. Caller must free() the result.
 */
void *mpqfs_read_file(mpqfs_archive_t *archive, const char *filename, size_t *out_size);
```

### SDL streaming

```c
/* SDL 1.2 & SDL 2 — returns a seekable, read-only SDL_RWops. */
SDL_RWops *mpqfs_open_rwops(mpqfs_archive_t *archive, const char *filename);

/* SDL 3 — returns a seekable, read-only SDL_IOStream. */
SDL_IOStream *mpqfs_open_io(mpqfs_archive_t *archive, const char *filename);
```

All SDL streams are self-contained: closing the stream frees its internal
resources but does **not** close the parent archive.

### Error handling

```c
/* Returns a human-readable string describing the last error, or NULL. */
const char *mpqfs_last_error(void);
```

## MPQ format notes

Diablo 1's `DIABDAT.MPQ` is an MPQ v1 (format version 0) archive. Key details:

- **Header**: 32 bytes, signature `MPQ\x1a`
- **Sector size**: `512 << sector_shift` (typically 4096 bytes)
- **Hash table**: encrypted with the key `"(hash table)"`, used for filename lookup
- **Block table**: encrypted with the key `"(block table)"`, describes file extents
- **Compression**: PKWARE DCL implode (flag `0x00000100`)
- **No encryption** on individual files in `DIABDAT.MPQ`
- Filenames use **backslash** separators and are **case-insensitive**

## License

MIT — see [LICENSE](LICENSE) for details.