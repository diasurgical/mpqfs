cmake_minimum_required(VERSION 3.14)

project(mpqfs
    VERSION 0.1.0
    DESCRIPTION "Minimal MPQ archive reader with SDL integration"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(MPQFS_BUILD_TESTS "Build test executables" ON)
option(MPQFS_SDL_VERSION "SDL version to build against (1, 2, 3, or AUTO)" "AUTO")

# --- Dependencies ---

# SDL detection
if(MPQFS_SDL_VERSION STREQUAL "AUTO")
    # Try SDL3 first, then SDL2, then SDL1
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
elseif(MPQFS_SDL_VERSION STREQUAL "3")
    find_package(SDL3 REQUIRED)
    set(_MPQFS_SDL_VER 3)
elseif(MPQFS_SDL_VERSION STREQUAL "2")
    find_package(SDL2 REQUIRED)
    set(_MPQFS_SDL_VER 2)
elseif(MPQFS_SDL_VERSION STREQUAL "1")
    find_package(SDL REQUIRED)
    set(_MPQFS_SDL_VER 1)
else()
    set(_MPQFS_SDL_VER 0)
    message(STATUS "mpqfs: SDL integration disabled")
endif()

# --- Library ---

set(MPQFS_SOURCES
    src/mpq_archive.c
    src/mpq_crypto.c
    src/mpq_stream.c
)

if(_MPQFS_SDL_VER GREATER 0)
    list(APPEND MPQFS_SOURCES src/mpq_sdl.c)
endif()

add_library(mpqfs ${MPQFS_SOURCES})
add_library(mpqfs::mpqfs ALIAS mpqfs)

target_include_directories(mpqfs
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)



target_compile_definitions(mpqfs PRIVATE MPQFS_SDL_VERSION=${_MPQFS_SDL_VER})

if(_MPQFS_SDL_VER EQUAL 3)
    target_link_libraries(mpqfs PUBLIC SDL3::SDL3)
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL3=1)
elseif(_MPQFS_SDL_VER EQUAL 2)
    target_link_libraries(mpqfs PUBLIC SDL2::SDL2)
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL2=1)
elseif(_MPQFS_SDL_VER EQUAL 1)
    target_include_directories(mpqfs PUBLIC ${SDL_INCLUDE_DIR})
    target_link_libraries(mpqfs PUBLIC ${SDL_LIBRARY})
    target_compile_definitions(mpqfs PUBLIC MPQFS_USE_SDL1=1)
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mpqfs PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(mpqfs PRIVATE /W4)
endif()

# --- Tests ---

if(MPQFS_BUILD_TESTS)
    add_executable(mpqfs_test tests/test_mpqfs.c)
    target_link_libraries(mpqfs_test PRIVATE mpqfs::mpqfs)
    target_include_directories(mpqfs_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

# --- Install ---

include(GNUInstallDirs)

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