# mpqfs

A minimal, MIT-licensed C99 library for reading and writing MPQ v1 archives (as used by Diablo 1).

**mpqfs** provides a clean streaming interface to files inside MPQ archives, designed to slot directly into game engines. It also supports creating MPQ archives in the style used by Diablo 1 for its save-game files.

## Features

- **MPQ v1 format** support (Diablo 1 `DIABDAT.MPQ`)
- **PKWARE DCL** (implode) decompression and compression — the scheme used by Diablo 1
- **zlib and bzip2** decompression — for MPQ archives that use multi-method compression (e.g. Warcraft III), optionally compiled in
- **MPQ v1 writing** — create archives compatible with Diablo 1's save-game format
- **Zero-copy sector-based streaming** (files are not fully decompressed up front)
- **Archive cloning** for thread-safe concurrent reads
- **Carry-forward** — copy files between archives without recompression
- **Written in C99**, compiles cleanly as **C++11 through C++20**
- **MIT licensed** — suitable for embedding in any engine

## Building

mpqfs uses CMake (>= 3.14):

```sh
cmake -S . -B build
cmake --build build
```

### CMake options

| Option               | Default | Description                                                |
|----------------------|---------|------------------------------------------------------------|
| `BUILD_TESTING`      | `ON`    | Build the test executable                                  |
| `BUILD_SHARED_LIBS`  | `OFF`   | Build as shared library instead of static                  |
| `MPQFS_USE_ZLIB`     | `ON`    | Enable zlib decompression for `MPQ_FILE_COMPRESS` sectors  |
| `MPQFS_USE_BZIP2`    | `ON`    | Enable bzip2 decompression for `MPQ_FILE_COMPRESS` sectors |

PKWARE DCL (implode/explode) is always built in — it has no external dependencies. zlib and bzip2 are only needed for MPQ archives that use the multi-method compression flag, which is common in Warcraft III but not in Diablo 1. On platforms where these libraries are unavailable, set `MPQFS_USE_ZLIB=OFF` and/or `MPQFS_USE_BZIP2=OFF`.

### Using mpqfs in your CMake project

#### As a subdirectory

```cmake
add_subdirectory(vendor/mpqfs)
target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

#### Via FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(mpqfs
    GIT_REPOSITORY https://github.com/AJenbo/mpqfs.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(mpqfs)

target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

#### Via find_package (after install)

```cmake
find_package(mpqfs REQUIRED CONFIG)
target_link_libraries(my_game PRIVATE mpqfs::mpqfs)
```

## Quick start

### Reading an archive

```c
#include <mpqfs/mpqfs.h>

mpqfs_archive_t *archive;
mpqfs_error_code rc = mpqfs_open("DIABDAT.MPQ", &archive);
if (rc != MPQFS_OK) {
    fprintf(stderr, "failed to open archive: %s\n", mpqfs_error_message(rc));
    return 1;
}

/* Check if a file exists */
if (mpqfs_has_file(archive, "levels\\l1data\\l1.min")) {
    printf("found it!\n");
}

/* Read a whole file into memory */
void *data;
size_t size;
if (mpqfs_read_file(archive, "ui_art\\title.pcx", &data, &size) == MPQFS_OK) {
    /* use data (size bytes) ... */
    free(data);
}

mpqfs_close(archive);
```

### Writing an archive

```c
#include <mpqfs/mpqfs.h>

mpqfs_writer_t *writer;
mpqfs_error_code rc = mpqfs_writer_create("save.sv", 16, &writer);
if (rc != MPQFS_OK) {
    fprintf(stderr, "failed to create archive: %s\n", mpqfs_error_message(rc));
    return 1;
}

mpqfs_writer_add_file(writer, "hero", hero_data, hero_size);
mpqfs_writer_add_file(writer, "game", game_data, game_size);

rc = mpqfs_writer_close(writer);
if (rc != MPQFS_OK) {
    fprintf(stderr, "failed to write archive: %s\n", mpqfs_error_message(rc));
    return 1;
}
/* writer is freed by close — do not use it after this point */
```

### Streaming (large files)

```c
mpqfs_stream_t *stream;
if (mpqfs_stream_open(archive, "sfx\\misc\\fire01.wav", &stream) != MPQFS_OK) {
    /* handle error */
}

uint8_t buf[4096];
size_t n;
while (mpqfs_stream_read(stream, buf, sizeof(buf), &n) == MPQFS_OK && n > 0) {
    /* process chunk ... */
}

mpqfs_stream_close(stream);
```

## Platform support

mpqfs is designed for extreme portability:

| Platform        | Toolchain          | Notes                                          |
|-----------------|--------------------|-------------------------------------------------|
| Linux           | GCC / Clang        | Primary development platform                    |
| Windows         | MSVC / MinGW       | Full support including `_fdopen`                |
| macOS / iOS     | Apple Clang        |                                                 |
| Android         | NDK (Clang)        |                                                 |
| DOS             | DJGPP (GCC)        | No threads — TLS degrades to static             |
| Xbox (nxdk)     | nxdk               | No POSIX fd, no zlib/bzip2 by default           |
| Xbox UWP        | MSVC               | No POSIX fd                                     |
| PS2             | ee-gcc             | No threads, no POSIX fd                         |
| 3DS / Vita      | devkitARM / vitasdk| No POSIX fd                                     |
| Nintendo Switch | devkitA64          | No POSIX fd                                     |
| Emscripten      | emcc               |                                                 |

On platforms without POSIX file descriptors, use `mpqfs_open_fp(FILE*)` or `mpqfs_open(path)` instead of `mpqfs_open_fd(int fd)`. The same applies to the writer variants.

Key portability properties:

- **C99 baseline** — no C11 or C++ features required.
- **C++ safe** — `extern "C"` guards on all headers; compiles as C++20 with zero warnings under `-Wall -Wextra -Wpedantic`.
- **Endian safe** — all on-disk data is parsed via byte-level reads.
- **Alignment safe** — no unaligned memory access.
- **No TLS requirement** — degrades to a plain `static` on single-threaded platforms.

## API reference

The public API is defined in a single header: `<mpqfs/mpqfs.h>`. See the header for full doc-comments on every function.

Every fallible function returns an `mpqfs_error_code` (`MPQFS_OK` on success); the value it used to return directly is now written through a trailing out-parameter. Existence-style queries (`mpqfs_has_file`, `mpqfs_has_file_hash`, `mpqfs_writer_has_file`, `mpqfs_find_hash`) are unaffected — they still return their result directly, since "not found" isn't an error.

### Archive lifecycle

| Function | Description |
|----------|-------------|
| `mpqfs_open(path, &archive)` | Open from a filesystem path. |
| `mpqfs_open_fp(fp, &archive)` | Open from a `FILE*` (caller retains ownership). |
| `mpqfs_open_fd(fd, &archive)` | Open from a file descriptor (library takes ownership). Only on platforms with `fdopen`. |
| `mpqfs_clone(archive, &clone)` | Create an independent clone with its own `FILE*` for thread-safe concurrent reads. |
| `mpqfs_close(archive)` | Close and free all resources. NULL-safe. |

### File queries

| Function | Description |
|----------|-------------|
| `mpqfs_has_file(archive, filename)` | Check if a file exists. Returns `bool` directly. |
| `mpqfs_file_size(archive, filename, &size)` | Get uncompressed size. |
| `mpqfs_find_hash(archive, filename)` | Look up a file and return its hash table index (`UINT32_MAX` if not found). Returns `uint32_t` directly. |
| `mpqfs_has_file_hash(archive, hash)` | Check existence by hash table index. Returns `bool` directly. |
| `mpqfs_file_size_from_hash(archive, hash, &size)` | Get size by hash table index. |

### Reading files

| Function | Description |
|----------|-------------|
| `mpqfs_read_file(archive, filename, &data, &size)` | Read entire file into a `malloc`'d buffer. Caller must `free()`. |
| `mpqfs_read_file_into(archive, filename, buf, buf_size, &bytes_read)` | Read entire file into a caller-supplied buffer. |

### Streaming

| Function | Description |
|----------|-------------|
| `mpqfs_stream_open(archive, filename, &stream)` | Open a seekable read-only stream. Only one sector is held in memory. |
| `mpqfs_stream_open_from_hash(archive, hash, &stream)` | Open a stream by hash table index (avoids rehashing). |
| `mpqfs_stream_read(stream, buf, count, &bytes_read)` | Read up to `count` bytes. |
| `mpqfs_stream_seek(stream, offset, whence, &position)` | Seek (`SEEK_SET` / `SEEK_CUR` / `SEEK_END`). |
| `mpqfs_stream_tell(stream, &position)` | Current read position. |
| `mpqfs_stream_size(stream, &size)` | Total uncompressed size. |
| `mpqfs_stream_close(stream)` | Close stream. NULL-safe. Does not close the archive. |

### Writing archives

| Function | Description |
|----------|-------------|
| `mpqfs_writer_create(path, hash_table_size, &writer)` | Create a writer targeting a filesystem path. |
| `mpqfs_writer_create_fp(fp, hash_table_size, &writer)` | Create from a `FILE*` (caller retains ownership). |
| `mpqfs_writer_create_fd(fd, hash_table_size, &writer)` | Create from a file descriptor. Only on platforms with `fdopen`. |
| `mpqfs_writer_add_file(writer, filename, data, size)` | Add a file (data is copied). Compressed with PKWARE DCL implode. |
| `mpqfs_writer_has_file(writer, filename)` | Check if a file has been added. Returns `bool` directly. |
| `mpqfs_writer_rename_file(writer, old, new)` | Rename a previously added file. |
| `mpqfs_writer_remove_file(writer, filename)` | Remove a previously added file. |
| `mpqfs_writer_carry_forward(writer, filename, archive, block_index)` | Copy a file from an existing archive without recompression. |
| `mpqfs_writer_carry_forward_all(writer, archive)` | Copy all files from an existing archive without recompression. |
| `mpqfs_writer_close(writer)` | Finalise and free the writer. The handle is invalid after this call. |
| `mpqfs_writer_discard(writer)` | Discard without writing. NULL-safe. |

`hash_table_size` is rounded up to the next power of two (minimum 4) and must be larger than the number of files to add.

### Crypto and compression primitives

These are exposed for consumers that need low-level MPQ operations:

| Function | Description |
|----------|-------------|
| `mpqfs_crypto_init()` | Initialise the encryption table. Called automatically; provided for explicit control. |
| `mpqfs_hash_string(str, hash_type)` | Compute an MPQ hash. Types: `MPQFS_HASH_TABLE_INDEX`, `_NAME_A`, `_NAME_B`, `_FILE_KEY`. |
| `mpqfs_hash_string_s(str, len, hash_type)` | Length-delimited variant. |
| `mpqfs_encrypt_block(data, count, key)` | Encrypt uint32 array in-place. |
| `mpqfs_decrypt_block(data, count, key)` | Decrypt uint32 array in-place. |
| `mpqfs_file_hash(filename, &index, &hash_a, &hash_b)` | Compute the three MPQ hashes for a filename. |
| `mpqfs_file_hash_s(filename, len, &index, &hash_a, &hash_b)` | Length-delimited variant. |
| `mpqfs_pk_implode(src, src_size, dst, &dst_size, dict_bits)` | PKWARE DCL compress. |
| `mpqfs_pk_explode(src, src_size, dst, &dst_size)` | PKWARE DCL decompress. |

### Error handling

Every fallible function returns an `mpqfs_error_code`. `MPQFS_OK` (0) means success; any other value is an error and no output parameter is valid. Use `mpqfs_error_message()` to get a static, human-readable description of a code — it does not carry call-specific detail (e.g. which filename or errno was involved), only the general category of failure.

| Function | Description |
|----------|-------------|
| `mpqfs_error_message(code)` | Returns a static, human-readable description of an `mpqfs_error_code`. Never NULL. |

Error codes: `MPQFS_OK`, `MPQFS_ERR_INVALID_ARGUMENT`, `MPQFS_ERR_OUT_OF_MEMORY`, `MPQFS_ERR_IO`, `MPQFS_ERR_NOT_MPQ`, `MPQFS_ERR_UNSUPPORTED_VERSION`, `MPQFS_ERR_CORRUPT_ARCHIVE`, `MPQFS_ERR_FILE_NOT_FOUND`, `MPQFS_ERR_INVALID_HASH`, `MPQFS_ERR_ENCRYPTED_NO_KEY`, `MPQFS_ERR_UNSUPPORTED_COMPRESSION`, `MPQFS_ERR_DECOMPRESS_FAILED`, `MPQFS_ERR_BUFFER_TOO_SMALL`, `MPQFS_ERR_HASH_TABLE_FULL`, `MPQFS_ERR_NO_PATH`.

## Running tests

```sh
cmake --build build
./build/mpqfs_test                           # run unit tests
./build/mpqfs_test DIABDAT.MPQ               # open a real MPQ and print info
./build/mpqfs_test DIABDAT.MPQ "file\\name"  # extract a file to stdout
```

## License

MIT — see [LICENSE](LICENSE) for details.
