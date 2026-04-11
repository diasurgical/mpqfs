cmake_minimum_required(VERSION 3.14)

project(mpqfs
    VERSION 0.1.0
    DESCRIPTION "Minimal MPQ v1 archive reader/writer"
    LANGUAGES C
)

# Allow consumers to enable C++ compilation if they prefer.
# By default we compile as C99 for maximum portability (PS2 ee-gcc, DJGPP, etc.)
option(MPQFS_BUILD_TESTS    "Build test executables"                         ON)
option(MPQFS_BUILD_SHARED   "Build as a shared library instead of static"    OFF)

# --- C standard ---
# C99 is the baseline — it works on every toolchain DevilutionX targets,
# including PS2 (ee-gcc), DJGPP (DOS), and Emscripten.
# Extensions are ON (-std=gnu99) because strict C99 (-std=c99) defines
# __STRICT_ANSI__ on GCC, which hides POSIX types like off_t.  zlib's
# zconf.h defines z_off_t as off_t, so including <zlib.h> fails under
# strict C99 on platforms such as DJGPP (DOS).
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# --- zlib and bzip2 (optional, for MPQ_FILE_COMPRESS sector decompression) ---
#
# Diablo 1 / Hellfire MPQ files only use PKWARE DCL implode (MPQ_FILE_IMPLODE),
# which is always built in.  zlib and bzip2 are only needed for MPQ archives
# that use the multi-method compression flag (MPQ_FILE_COMPRESS), which is
# common in Warcraft III / WoW but not in Diablo.
#
# On platforms where zlib or bzip2 are unavailable (e.g. original Xbox / nxdk),
# set MPQFS_USE_ZLIB=OFF and/or MPQFS_USE_BZIP2=OFF.  If an MPQ file using
# those methods is encountered at runtime, a clear error is reported.

option(MPQFS_USE_ZLIB  "Enable zlib decompression for MPQ_FILE_COMPRESS sectors"  ON)
option(MPQFS_USE_BZIP2 "Enable bzip2 decompression for MPQ_FILE_COMPRESS sectors" ON)

if(MPQFS_USE_ZLIB)
    if(NOT TARGET ZLIB::ZLIB)
        find_package(ZLIB REQUIRED)
    endif()
endif()
if(MPQFS_USE_BZIP2)
    if(NOT TARGET BZip2::BZip2)
        find_package(BZip2 REQUIRED)
    endif()
endif()

# --- Library target ---

set(MPQFS_SOURCES
    src/mpq_archive.c
    src/mpq_crypto.c
    src/mpq_pkware.c
    src/mpq_stream.c
    src/mpq_stream_api.c
    src/mpq_writer.c
)

if(MPQFS_BUILD_SHARED)
    add_library(mpqfs SHARED ${MPQFS_SOURCES})
    target_compile_definitions(mpqfs
        PRIVATE MPQFS_BUILDING=1
        PUBLIC  MPQFS_SHARED=1
    )
else()
    add_library(mpqfs STATIC ${MPQFS_SOURCES})
endif()

add_library(mpqfs::mpqfs ALIAS mpqfs)

target_include_directories(mpqfs
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# zlib and bzip2 linkage (when enabled)
# When mpqfs is built as a static library (the default), consumers need
# the transitive dependency to resolve symbols at link time.
if(MPQFS_USE_ZLIB)
    target_compile_definitions(mpqfs PUBLIC MPQFS_HAS_ZLIB=1)
    if(MPQFS_BUILD_SHARED)
        target_link_libraries(mpqfs PRIVATE ZLIB::ZLIB)
    else()
        target_link_libraries(mpqfs PUBLIC ZLIB::ZLIB)
    endif()
endif()
if(MPQFS_USE_BZIP2)
    target_compile_definitions(mpqfs PUBLIC MPQFS_HAS_BZIP2=1)
    if(MPQFS_BUILD_SHARED)
        target_link_libraries(mpqfs PRIVATE BZip2::BZip2)
    else()
        target_link_libraries(mpqfs PUBLIC BZip2::BZip2)
    endif()
endif()

# --- Compiler warnings (platform-aware) ---

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mpqfs PRIVATE
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wno-unused-function        # static inline helpers in headers
    )
    # Ensure the library compiles cleanly as C++ when included by a C++ TU.
    # This doesn't change the library's own language, just validates compat.
elseif(MSVC)
    target_compile_options(mpqfs PRIVATE
        /W4
        /wd4100   # unreferenced formal parameter (same as -Wno-unused-parameter)
        /wd4244   # possible loss of data (narrowing)
    )
endif()

# --- Tests ---

if(MPQFS_BUILD_TESTS)
    add_executable(mpqfs_test tests/test_mpqfs.c)
    target_link_libraries(mpqfs_test PRIVATE mpqfs::mpqfs)
    target_include_directories(mpqfs_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    # Suppress warnings in test code that are intentional (e.g. sign conversion
    # in the synthetic MPQ builder).
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(mpqfs_test PRIVATE
            -Wall -Wextra
            -Wno-sign-conversion -Wno-conversion
        )
    endif()
endif()

# --- Install ---
#
# Install rules are only useful when mpqfs is the top-level project.
# When embedded via add_subdirectory / FetchContent, the install export
# would fail if mpqfs's private dependencies (zlib, bzip2) are
# also built from source and not part of any export set.

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS mpqfs
    EXPORT mpqfsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/mpqfs
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT mpqfsTargets
    FILE mpqfsTargets.cmake
    NAMESPACE mpqfs::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpqfs
)

# Generate mpqfsConfig.cmake so that find_package(mpqfs) works.
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/mpqfsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/mpqfsConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpqfs
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/mpqfsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/mpqfsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/mpqfsConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mpqfs
)

endif()