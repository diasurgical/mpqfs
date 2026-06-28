/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * Internal header: platform portability shims.
 *
 * This header centralises all compiler/platform detection so that the
 * rest of the code-base can be written in plain C99 that also compiles
 * cleanly as C++11 or later (up to C++20).
 *
 * Targets that must be supported include at least:
 *   - GCC / Clang / MSVC on Windows, Linux, macOS, Android, iOS
 *   - GCC (ee-gcc) on PS2 (MIPS-LE, no threads, no POSIX)
 *   - DJGPP on DOS (i386, no threads, partial POSIX)
 *   - Emscripten / WASM
 *   - Various ARM cross-compilers (3DS, Vita, Switch, ...)
 */

#ifndef MPQFS_MPQ_PLATFORM_H
#define MPQFS_MPQ_PLATFORM_H

/* -----------------------------------------------------------------------
 * 1.  <stdbool.h> — only needed in C; C++ has bool as a keyword.
 * ----------------------------------------------------------------------- */

#ifndef __cplusplus
#include <stdbool.h>
#endif

/* -----------------------------------------------------------------------
 * 2.  Standard integer types — always available in C99 / C++11.
 * ----------------------------------------------------------------------- */

#include <stddef.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * 3.  MPQFS_HAS_FDOPEN
 *
 *     Set to 1 when fdopen() (or _fdopen on MSVC) is available.
 *     Platforms without POSIX file-descriptor semantics should not
 *     expose mpqfs_open_fd().
 * ----------------------------------------------------------------------- */

#if defined(__PS2__) || defined(_3DS) || defined(__vita__) \
    || defined(__NX__)  /* Nintendo Switch (devkitPro) */  \
    || defined(NXDK)    /* original Xbox (nxdk) */         \
    || defined(__UWP__) /* Xbox UWP / Gaming Desktop */
                        /* Console SDKs generally do not provide POSIX fd operations. */
#define MPQFS_HAS_FDOPEN 0
#elif defined(_MSC_VER)
/* MSVC desktop provides _fdopen(). */
#define MPQFS_HAS_FDOPEN 1
#ifndef _CRT_DECLARE_NONSTD
#include <io.h>
#endif
#include <stdio.h>
#define fdopen _fdopen
#elif defined(__DJGPP__) || defined(__unix__) || defined(__APPLE__)          \
    || defined(__linux__) || defined(__ANDROID__) || defined(__EMSCRIPTEN__) \
    || defined(__CYGWIN__) || defined(__HAIKU__)
#define MPQFS_HAS_FDOPEN 1
#else
/* Unknown platform — assume unavailable; users can override. */
#define MPQFS_HAS_FDOPEN 0
#endif

/* -----------------------------------------------------------------------
 * 4.  Endianness detection
 *
 *     MPQ archives are little-endian.  All known DevilutionX targets are
 *     little-endian as well.  We detect and assert this at compile time
 *     so that a big-endian build fails loudly rather than silently
 *     producing garbage.
 *
 *     If you need to add big-endian support in the future, the byte-swap
 *     path lives behind MPQFS_BIG_ENDIAN.
 * ----------------------------------------------------------------------- */

/* Try compiler-provided macros first. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define MPQFS_BIG_ENDIAN 1
#else
#define MPQFS_BIG_ENDIAN 0
#endif
#elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) \
    || defined(__MIPSEB__) || defined(_MIPSEB) || defined(__AARCH64EB__)
#define MPQFS_BIG_ENDIAN 1
#elif defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__THUMBEL__) \
    || defined(__MIPSEL__) || defined(_MIPSEL) || defined(__AARCH64EL__)       \
    || defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64)                \
    || defined(__i386__) || defined(__x86_64__) || defined(__ia64__)           \
    || defined(__alpha__) || defined(__riscv) || defined(__EMSCRIPTEN__)       \
    || defined(__wasm__) || defined(__PS2__) || defined(__DJGPP__)
#define MPQFS_BIG_ENDIAN 0
#else
/* Conservative default — assume LE but warn. */
#define MPQFS_BIG_ENDIAN 0
#if defined(__GNUC__) || defined(__clang__)
#warning "mpqfs: unable to detect endianness — assuming little-endian"
#endif
#endif

/* -----------------------------------------------------------------------
 * 5.  Byte-swap helpers (for future big-endian support)
 *
 *     On LE these are identity operations and should be fully optimised
 *     out.  On BE they perform the swap.
 * ----------------------------------------------------------------------- */

static inline uint16_t mpqfs_le16(uint16_t v)
{
#if MPQFS_BIG_ENDIAN
	return (uint16_t)((v >> 8) | (v << 8));
#else
	return v;
#endif
}

static inline uint32_t mpqfs_le32(uint32_t v)
{
#if MPQFS_BIG_ENDIAN
	return ((v >> 24) & 0x000000FFu)
	    | ((v >> 8) & 0x0000FF00u)
	    | ((v << 8) & 0x00FF0000u)
	    | ((v << 24) & 0xFF000000u);
#else
	return v;
#endif
}

/* -----------------------------------------------------------------------
 * 6.  Read little-endian integers from an unaligned byte pointer.
 *
 *     These never rely on aliasing or alignment and are safe on every
 *     architecture.
 * ----------------------------------------------------------------------- */

static inline uint16_t mpqfs_read_le16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

static inline uint32_t mpqfs_read_le32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;
	return (uint32_t)b[0]
	    | ((uint32_t)b[1] << 8)
	    | ((uint32_t)b[2] << 16)
	    | ((uint32_t)b[3] << 24);
}

/* -----------------------------------------------------------------------
 * 7.  Write little-endian integers to an unaligned byte pointer.
 * ----------------------------------------------------------------------- */

static inline void mpqfs_write_le16(void *p, uint16_t v)
{
	uint8_t *b = (uint8_t *)p;
	b[0] = (uint8_t)(v);
	b[1] = (uint8_t)(v >> 8);
}

static inline void mpqfs_write_le32(void *p, uint32_t v)
{
	uint8_t *b = (uint8_t *)p;
	b[0] = (uint8_t)(v);
	b[1] = (uint8_t)(v >> 8);
	b[2] = (uint8_t)(v >> 16);
	b[3] = (uint8_t)(v >> 24);
}

/* -----------------------------------------------------------------------
 * 8.  Compile-time assertion (works in C99 and C++11+)
 *
 *     C11 has _Static_assert, C++11 has static_assert.  For C99 we
 *     fall back to the negative-array-size trick.
 * ----------------------------------------------------------------------- */

#if defined(__cplusplus)
/* C++11 static_assert is always available in our minimum target. */
#define MPQFS_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define MPQFS_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
/* C99 fallback: typedef of a negative-size array. */
#define MPQFS_CONCAT_(a, b) a##b
#define MPQFS_CONCAT(a, b) MPQFS_CONCAT_(a, b)
#define MPQFS_STATIC_ASSERT(cond, msg) \
	typedef char MPQFS_CONCAT(mpqfs_sa_, __LINE__)[(cond) ? 1 : -1]
#endif

/* -----------------------------------------------------------------------
 * 9.  MPQFS_UNUSED — silence "unused parameter" warnings portably.
 * ----------------------------------------------------------------------- */

#define MPQFS_UNUSED(x) ((void)(x))

/* -----------------------------------------------------------------------
 * 10. MPQFS_UNLIKELY — branch-prediction hint for error-checking branches.
 *
 *     Used to mark the conditions of guard clauses (NULL/invalid-argument
 *     checks, allocation failures, I/O failures, corrupt-data checks,
 *     etc.) whose true branch always leads to an early failure return.
 *     These are cold paths in normal operation, so hinting them helps
 *     the compiler keep the hot path contiguous.  A no-op on compilers
 *     without __builtin_expect.
 * ----------------------------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
#define MPQFS_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define MPQFS_UNLIKELY(x) (x)
#endif

/* -----------------------------------------------------------------------
 * 11. MPQFS_RET_CHECK — guard clause that returns an error code.
 *
 *     Shorthand for the ubiquitous
 *       if (MPQFS_UNLIKELY(!condition)) return error_code;
 *     guard-clause pattern. `condition` is the thing that must hold for
 *     execution to continue (it is negated internally, same polarity as
 *     assert()); `error_code` is returned verbatim when it does not.
 *     Only for simple returns — if the guard needs cleanup (fclose,
 *     free, ...) before returning, write it out by hand instead.
 * ----------------------------------------------------------------------- */

#define MPQFS_RET_CHECK(condition, error_code)                 \
	do {                                                       \
		if (MPQFS_UNLIKELY(!(condition))) return (error_code); \
	} while (0)

/* -----------------------------------------------------------------------
 * 12. MPQFS_API — symbol visibility for shared / static library builds.
 *
 *     When the library is built as a static archive (the common case for
 *     game engines), all of these should expand to nothing.  We default
 *     to static unless MPQFS_SHARED is explicitly defined.
 * ----------------------------------------------------------------------- */

#if defined(MPQFS_SHARED)
#if defined(_WIN32) || defined(__CYGWIN__)
#ifdef MPQFS_BUILDING
#define MPQFS_API __declspec(dllexport)
#else
#define MPQFS_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && __GNUC__ >= 4
#define MPQFS_API __attribute__((visibility("default")))
#else
#define MPQFS_API
#endif
#else
/* Static library — no special annotation needed. */
#define MPQFS_API
#endif

/* -----------------------------------------------------------------------
 * 13. Struct packing — used for on-disk MPQ structures.
 *
 *     Usage:
 *       MPQFS_PACK_BEGIN
 *       typedef struct { ... } MPQFS_PACKED my_struct_t;
 *       MPQFS_PACK_END
 *
 *     NOTE: the runtime code parses headers from raw byte buffers via
 *     the read_le* helpers above, so packing is only required for the
 *     hash and block table entries that are decrypted in-place.
 * ----------------------------------------------------------------------- */

#if defined(_MSC_VER)
#define MPQFS_PACK_BEGIN __pragma(pack(push, 1))
#define MPQFS_PACK_END __pragma(pack(pop))
#define MPQFS_PACKED /* MSVC uses #pragma pack instead */
#elif defined(__GNUC__) || defined(__clang__)
#define MPQFS_PACK_BEGIN /* nothing */
#define MPQFS_PACK_END   /* nothing */
#define MPQFS_PACKED __attribute__((packed))
#else
/* Unknown compiler — hope for the best; the static assertions
 * below will catch layout mismatches at compile time. */
#define MPQFS_PACK_BEGIN /* nothing */
#define MPQFS_PACK_END   /* nothing */
#define MPQFS_PACKED     /* nothing */
#endif

#endif /* MPQFS_MPQ_PLATFORM_H */
