# mpqfs

A minimal, MIT-licensed C99 library for reading and writing MPQ v1 archives (as used by Diablo 1), with native SDL 1.2 / SDL 2 / SDL 3 integration.

**mpqfs** provides a clean streaming interface to files inside MPQ archives, designed to slot directly into game engines via `SDL_RWops` (SDL 1.2 & 2) or `SDL_IOStream` (SDL 3). It also supports creating MPQ archives in the basic style used by Diablo 1 for its save-game files.

## Features

- **MPQ v1 format** support (Diablo 1 `DIABDAT.MPQ`)
- **PKWARE DCL** (implode) decompression — the compression scheme used by Diablo 1
- **PKWARE DCL** (implode) compression — sector-based, for save-game writing
- **MPQ v1 writing** — create archives compatible with DevilutionX's save-game format
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

### Reading an archive

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

### Writing an archive (Diablo 1 save-game format)

```c
#include <mpqfs/mpqfs.h>

/* Create a new MPQ archive */
mpqfs_writer_t *writer = mpqfs_writer_create("save.sv", 16);
if (!writer) {
    fprintf(stderr, "failed to create archive: %s\n", mpqfs_last_error());
    return 1;
}

/* Add files — data is copied, so buffers can be freed immediately */
mpqfs_writer_add_file(writer, "hero", hero_data, hero_size);
mpqfs_writer_add_file(writer, "game", game_data, game_size);
mpqfs_writer_add_file(writer, "levels\\town.dun", dun_data, dun_size);

/* Finalise — writes header, file data, and encrypted tables */
if (!mpqfs_writer_close(writer)) {
    fprintf(stderr, "failed to write archive: %s\n", mpqfs_last_error());
    return 1;
}
/* writer is freed by close — do not use it after this point */
```

The writer produces archives that are layout-compatible with DevilutionX's
save-game format: PKWARE DCL implode compressed files, no file-level encryption,
with standard encrypted hash and block tables placed before file data.

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

### Archive writing

```c
/* Create a new MPQ archive at the given path.
 * hash_table_size is rounded up to the next power of two (minimum 4).
 * Must be larger than the number of files to add. */
mpqfs_writer_t *mpqfs_writer_create(const char *path,
                                    uint32_t hash_table_size);

/* Create from an existing FILE* (does NOT take ownership). */
mpqfs_writer_t *mpqfs_writer_create_fp(FILE *fp,
                                       uint32_t hash_table_size);

/* Create from a file descriptor (takes ownership).
 * Only available when MPQFS_HAS_FDOPEN is 1. */
mpqfs_writer_t *mpqfs_writer_create_fd(int fd,
                                       uint32_t hash_table_size);

/* Add a file to the archive. Makes owned copies of filename and data.
 * Files are PKWARE implode compressed without encryption (DevilutionX style). */
bool mpqfs_writer_add_file(mpqfs_writer_t *writer, const char *filename,
                           const void *data, size_t size);

/* Finalise the archive: writes header, file data, and encrypted
 * hash/block tables. Frees the writer regardless of success/failure. */
bool mpqfs_writer_close(mpqfs_writer_t *writer);

/* Discard a writer without writing. Frees all resources. */
void mpqfs_writer_discard(mpqfs_writer_t *writer);
```

The writer produces the following on-disk layout (matching DevilutionX):

| Section     | Size                              | Notes                           |
|-------------|-----------------------------------|---------------------------------|
| MPQ Header  | 32 bytes                          | Signature, offsets, counts      |
| Block table | `hash_table_size × 16` bytes      | Encrypted with standard key     |
| Hash table  | `hash_table_size × 16` bytes      | Encrypted with standard key     |
| File data   | Variable (compressed)             | PKWARE implode, sector offset tables |

Both the block table and hash table have `hash_table_size` entries.
Unused block table entries are zeroed. This layout is compatible with
DevilutionX's save-game format, where block and hash tables are placed
immediately after the header, before file data.

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

### Save-game format

Diablo 1 and DevilutionX use MPQ v1 archives for their save-game files (`.sv` / `.hsv`). These are simpler than `DIABDAT.MPQ`:

- **PKWARE DCL implode compression** — sector-based, with sector offset tables
- **No file-level encryption** — only the hash and block tables are encrypted
- **Small file count** — typically just a handful of files (`hero`, `game`, dungeon levels)
- **Hash and block tables** are both `hash_table_size` entries (a power-of-two), with unused block entries zeroed
- **Tables before data** — block table and hash table are placed immediately after the 32-byte header, before file data

The `mpqfs_writer_*` API produces archives with the same on-disk layout and compression as DevilutionX (`[Header][Block table][Hash table][Compressed file data]`). Files are compressed with PKWARE DCL implode; sectors that don't benefit from compression are stored raw. These archives are readable by both the mpqfs reader and DevilutionX's reader.

## Running tests

```sh
cmake --build build
./build/mpqfs_test                           # run unit tests
./build/mpqfs_test DIABDAT.MPQ               # open a real MPQ and print info
./build/mpqfs_test DIABDAT.MPQ "file\\name"  # extract a file to stdout
```

The unit tests include:
- A synthetic MPQ round-trip: constructs a valid MPQ archive in memory (with encrypted hash/block tables), writes it to a temp file, opens it, and verifies file lookup, size queries, reads, and seeking all produce correct results.
- Writer round-trip tests: creates archives via the `mpqfs_writer_*` API, reads them back with the reader API, and verifies all files are intact. Covers single files, multiple files, empty archives, zero-length files, FILE* variants, hash table auto-sizing, and PKWARE implode compression with both compressible and incompressible data.
- DevilutionX save file layout validation: verifies the on-disk layout matches DevilutionX (block table at offset 0x20, both table counts equal, tables before data).
- Real save file regression test: reads `share_0.sv` (a real DevilutionX save with PKWARE implode compressed files) and extracts all files.

## License

MIT — see [LICENSE](LICENSE) for details.