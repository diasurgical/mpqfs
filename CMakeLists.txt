cmake_minimum_required(VERSION 3.14)

project(mpqfs
    VERSION 0.1.0
    DESCRIPTION "Minimal MPQ v1 archive reader with SDL integration"
    LANGUAGES C
)

# Allow consumers to enable C++ compilation if they prefer.
# By default we compile as C99 for maximum portability (PS2 ee-gcc, DJGPP, etc.)
option(MPQFS_BUILD_TESTS    "Build test executables"                         ON)
option(MPQFS_BUILD_SHARED   "Build as a shared library instead of static"    OFF)
option(MPQFS_SDL_VERSION    "SDL version to build against (1, 2, 3, or AUTO)" "AUTO")

# --- C standard ---
# C99 is the baseline — it works on every toolchain DevilutionX targets,
# including PS2 (ee-gcc), DJGPP (DOS), and Emscripten.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# --- SDL detection ---
#
# When embedded via add_subdirectory / FetchContent the parent project may
# have already created SDL targets without using find_package (e.g. by
# building SDL from source).  We check for existing targets first so that
# find_package is only called when necessary.

if(MPQFS_SDL_VERSION STREQUAL "AUTO")
    if(TARGET SDL3::SDL3)
        set(_MPQFS_SDL_VER 3)
        message(STATUS "mpqfs: Found SDL3 (target)")
    elseif(TARGET SDL2::SDL2 OR TARGET SDL2::SDL2-static)
        set(_MPQFS_SDL_VER 2)
        message(STATUS "mpqfs: Found SDL2 (target)")
    else()
        find_package(SDL3 QUIET)
        if(SDL3_FOUND)
            set(_MPQFS_SDL_VER 3)
            message(STATUS "mpqfs: Found SDL3")
        else()
            find_package(SDL2 QUIET)
            if(SDL2_FOUND)
                set(_MPQFS_SDL_VER 2)
                message(STATUS "mpqfs: Found SDL2")
            else()
                find_package(SDL QUIET)
                if(SDL_FOUND)
                    set(_MPQFS_SDL_VER 1)
                    message(STATUS "mpqfs: Found SDL 1.2")
                else()
                    set(_MPQFS_SDL_VER 0)
                    message(STATUS "mpqfs: No SDL found, building without SDL integration")
                endif()
            endif()
        endif()
    endif()
elseif(MPQFS_SDL_VERSION STREQUAL "3")
    if(NOT TARGET SDL3::SDL3)
        find_package(SDL3 REQUIRED)
    endif()
    set(_MPQFS_SDL_VER 3)
elseif(MPQFS_SDL_VERSION STREQUAL "2")
    if(NOT TARGET SDL2::SDL2 AND NOT TARGET SDL2::SDL2-static)
        find_package(SDL2 REQUIRED)
    endif()
    set(_MPQFS_SDL_VER 2)
elseif(MPQFS_SDL_VERSION STREQUAL "1")
    find_package(SDL REQUIRED)
    set(_MPQFS_SDL_VER 1)
else()
    set(_MPQFS_SDL_VER 0)
    message(STATUS "mpqfs: SDL integration disabled")
endif()

# --- zlib and bzip2 (required for MPQ sector decompression) ---
if(NOT TARGET ZLIB::ZLIB)
    find_package(ZLIB REQUIRED)
endif()
if(NOT TARGET BZip2::BZip2)
    find_package(BZip2 REQUIRED)
endif()

# --- Library target ---

set(MPQFS_SOURCES
    src/mpq_archive.c
    src/mpq_crypto.c
    src/mpq_pkware.c
    src/mpq_stream.c
    src/mpq_writer.c
)

if(_MPQFS_SDL_VER GREATER 0)
    list(APPEND MPQFS_SOURCES src/mpq_sdl.c)
endif()

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

# SDL version define (used internally by mpq_sdl.c)
target_compile_definitions(mpqfs PRIVATE MPQFS_SDL_VERSION=${_MPQFS_SDL_VER})

# zlib and bzip2 linkage
target_link_libraries(mpqfs PRIVATE ZLIB::ZLIB BZip2::BZip2)

# SDL linkage
if(_MPQFS_SDL_VER EQUAL 3)
    target_link_libraries(mpqfs PUBLIC SDL3::SDL3)
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL3=1)
elseif(_MPQFS_SDL_VER EQUAL 2)
    if(TARGET SDL2::SDL2)
        target_link_libraries(mpqfs PUBLIC SDL2::SDL2)
    elseif(TARGET SDL2::SDL2-static)
        target_link_libraries(mpqfs PUBLIC SDL2::SDL2-static)
    endif()
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL2=1)
elseif(_MPQFS_SDL_VER EQUAL 1)
    target_include_directories(mpqfs PUBLIC ${SDL_INCLUDE_DIR})
    target_link_libraries(mpqfs PUBLIC ${SDL_LIBRARY})
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL1=1)
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