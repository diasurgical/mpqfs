# mpqfs

A minimal, MIT-licensed C99 library for reading MPQ v1 archives (as used by Diablo 1), with native SDL 1.2 / SDL 2 / SDL 3 integration.

**mpqfs** provides a clean, read-only streaming interface to files inside MPQ archives, designed to slot directly into game engines via `SDL_RWops` (SDL 1.2 & 2) or `SDL_IOStream` (SDL 3).

## Features

- **MPQ v1 format** support (Diablo 1 `DIABDAT.MPQ`)
- **PKWARE DCL** (implode) decompression — the compression scheme used by Diablo 1
- **SDL 1.2 / SDL 2 / SDL 3** adapter: expose archived files as seekable streams
- **Zero-copy sector-based streaming** (files are not fully decompressed up front)
- **Written in C99**, compiles cleanly as **C++11 through C++20**
- **No external dependencies** beyond the C standard library (and optionally SDL)
- **MIT licensed** — suitable for embedding in any engine

## Platform support

mpqfs is designed for extreme portability. It has been written to compile and run correctly on:

| Platform        | Toolchain          | Notes                                      |
|-----------------|--------------------|--------------------------------------------|
| Linux           | GCC / Clang        | Primary development platform               |
| Windows         | MSVC / MinGW       | Full support including `_fdopen`            |
| macOS / iOS     | Apple Clang        |                                             |
| Android         | NDK (Clang)        |                                             |
| DOS             | DJGPP (GCC)        | No threads — TLS degrades to static        |
| PS2             | ee-gcc             | No threads, no POSIX fd — use `mpqfs_open` or `mpqfs_open_fp` |
| 3DS / Vita      | devkitARM / vitasdk| No POSIX fd                                |
| Nintendo Switch | devkitA64          | No POSIX fd                                |
| Emscripten      | emcc               |                                             |

### Portability details

- **C99 baseline** — no C11 or C++ features are required to compile the library.
- **C++ safe** — all headers use `extern "C"` guards. The entire library compiles as C++20 with zero warnings under `-Wall -Wextra -Wpedantic`.
- **Endian safe** — all on-disk data is parsed via byte-level reads. Big-endian platforms are detected at compile time with byte-swap helpers ready (all current DevilutionX targets are little-endian).
- **No TLS requirement** — `thread_local` / `_Thread_local` / `__thread` is used when available but degrades to a plain `static` on single-threaded platforms.
- **No POSIX requirement** — `mpqfs_open(path)` uses only `fopen`/`fread`/`fseek`. The `mpqfs_open_fd()` variant is conditionally compiled only on platforms that provide `fdopen()`. A fully portable `mpqfs_open_fp(FILE*)` is always available.
- **Struct packing** — on-disk struct layouts are verified with compile-time size assertions. Both `#pragma pack` (MSVC) and `__attribute__((packed))` (GCC/Clang) are used.
- **Alignment safe** — no unaligned memory access. Multi-byte values are read byte-by-byte from raw buffers.

## Building

mpqfs uses CMake (>= 3.14):

```sh
cmake -S . -B build -DMPQFS_SDL_VERSION=AUTO
cmake --build build
```

### CMake options

| Option              | Default | Description                                        |
|---------------------|---------|----------------------------------------------------|
| `MPQFS_SDL_VERSION` | `AUTO`  | SDL major version to target (`1`, `2`, `3`, `AUTO`, or `0` to disable) |
| `MPQFS_BUILD_TESTS` | `ON`    | Build the test executable                          |
| `MPQFS_BUILD_SHARED`| `OFF`   | Build as shared library instead of static          |

When `MPQFS_SDL_VERSION` is `AUTO`, CMake probes for SDL3, then SDL2, then SDL 1.2. If none is found, the library builds without SDL integration (the core read API still works).

### Using mpqfs in your CMake project

#### As a subdirectory (recommended for game engines)

```cmake
add_subdirectory(vendor/mpqfs)
target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

#### Via find_package (after install)

```cmake
find_package(mpqfs REQUIRED)
target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

## Integration with DevilutionX

mpqfs is designed to integrate with [DevilutionX](https://github.com/AJenbo/devilutionX). Since DevilutionX uses CMake and C++20, integration is straightforward:

1. Add mpqfs as a subdirectory or fetch it via `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(mpqfs
    GIT_REPOSITORY https://github.com/AJenbo/mpqfs.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(mpqfs)

target_link_libraries(devilutionx PRIVATE mpqfs::mpqfs)
```

2. Use the library from C++ code — no special handling needed:

```cpp
#include <mpqfs/mpqfs.h>

// Open DIABDAT.MPQ
mpqfs_archive_t *archive = mpqfs_open("DIABDAT.MPQ");

// Get an SDL_RWops (SDL2) or SDL_IOStream (SDL3) for streaming
SDL_RWops *rw = mpqfs_open_rwops(archive, "music\\dtowne.wav");
Mix_Music *mus = Mix_LoadMUS_RW(rw, 1);

// Or read a whole file into memory
size_t size = 0;
void *data = mpqfs_read_file(archive, "ui_art\\title.pcx", &size);
// ... use data ...
free(data);

mpqfs_close(archive);
```

3. On platforms without POSIX file descriptors (PS2, 3DS, etc.), use the `FILE*` variant:

```cpp
FILE *fp = /* platform-specific file open */;
mpqfs_archive_t *archive = mpqfs_open_fp(fp);
// ... use archive ...
mpqfs_close(archive);
fclose(fp);  // caller retains ownership of the FILE*
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

/* Open from an existing FILE* (does NOT take ownership). */
mpqfs_archive_t *mpqfs_open_fp(FILE *fp);

/* Open from a file descriptor (takes ownership).
 * Only available when MPQFS_HAS_FDOPEN is 1. */
mpqfs_archive_t *mpqfs_open_fd(int fd);

/* Close the archive and free all associated resources.
 * If opened with mpqfs_open_fp(), the FILE* is NOT closed. */
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
/* Read an entire file into a newly allocated buffer.
 * Sets *out_size to the number of bytes read.
 * Returns NULL on error. Caller must free() the result. */
void *mpqfs_read_file(mpqfs_archive_t *archive, const char *filename,
                      size_t *out_size);

/* Read an entire file into a caller-supplied buffer.
 * Returns the number of bytes written, or 0 on error. */
size_t mpqfs_read_file_into(mpqfs_archive_t *archive, const char *filename,
                            void *buffer, size_t buffer_size);
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
/* Returns a human-readable string describing the last error, or NULL.
 * Thread-safe on platforms with TLS; process-global on single-threaded platforms. */
const char *mpqfs_last_error(void);
```

## MPQ format notes

Diablo 1's `DIABDAT.MPQ` is an MPQ v1 (format version 0) archive. Key details:

- **Header**: 32 bytes, signature `MPQ\x1a`, located on a 512-byte boundary
- **Sector size**: `512 << sector_shift` (typically 4096 bytes)
- **Hash table**: encrypted with the key `"(hash table)"`, used for filename lookup
- **Block table**: encrypted with the key `"(block table)"`, describes file extents
- **Compression**: PKWARE DCL implode (flag `0x00000100`)
- **No encryption** on individual files in `DIABDAT.MPQ`
- Filenames use **backslash** separators and are **case-insensitive**

## Running tests

```sh
cmake --build build
./build/mpqfs_test                           # run unit tests
./build/mpqfs_test DIABDAT.MPQ               # open a real MPQ and print info
./build/mpqfs_test DIABDAT.MPQ "file\\name"  # extract a file to stdout
```

The unit tests include a synthetic MPQ round-trip: the test constructs a valid MPQ archive in memory (with encrypted hash/block tables), writes it to a temp file, opens it, and verifies file lookup, size queries, reads, and seeking all produce correct results.

## License

MIT — see [LICENSE](LICENSE) for details.