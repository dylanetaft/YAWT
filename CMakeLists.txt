cmake_minimum_required(VERSION 3.14)
project(yawt_superbuild)
include(ExternalProject)

# Allow users to override the install prefix (e.g. for system install or staging)
set(USER_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install"
    CACHE PATH "Installation prefix for all dependencies and yawt itself")

option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(YAWT_ENABLE_FUZZ_CORPUS "Enable fuzz corpus collection at parse boundaries" OFF)
option(BUILD_FUZZ "Build fuzz harness targets (requires clang with -fsanitize=fuzzer)" ON)
option(YAWT_ENABLE_LOGGING "Enable debug logging" ON)
set(YAWT_LOG_LEVEL 0 CACHE STRING "Set log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)")

set(MY_INSTALL_PREFIX ${USER_INSTALL_PREFIX})

# --- AllocNBuffer: user's own library, fetched and built ---
ExternalProject_Add(
  AllocNBuffer
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/dylanetaft/Alloc-N-Buffer
  GIT_TAG main
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${MY_INSTALL_PREFIX}
)

# --- uthash: header-only, no build needed ---
ExternalProject_Add(
  uthash
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/troydhanson/uthash.git
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory ${MY_INSTALL_PREFIX}/include/uthash
          COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src ${MY_INSTALL_PREFIX}/include/uthash
)

# --- libev: not available as system package on all distros ---
ExternalProject_add(
  libev
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/dylanetaft/libev.git
  GIT_TAG main
  CONFIGURE_COMMAND ${CMAKE_BINARY_DIR}/libev-prefix/src/libev/configure
    --enable-static --disable-shared --prefix=${MY_INSTALL_PREFIX}
)

# GnuTLS is expected to come from the system (use system package manager: apt/rpm/brew)

# --- yawt: the main project ---
ExternalProject_Add(
    yawt
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/src
    DEPENDS libev AllocNBuffer uthash
    CMAKE_ARGS
      -DCMAKE_INSTALL_PREFIX=${MY_INSTALL_PREFIX}
      -DCMAKE_PREFIX_PATH=${MY_INSTALL_PREFIX}
      -DBUILD_TESTS=${BUILD_TESTS}
      -DBUILD_EXAMPLES=${BUILD_EXAMPLES}
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      -DYAWT_ENABLE_FUZZ_CORPUS=${YAWT_ENABLE_FUZZ_CORPUS}
      -DBUILD_FUZZ=${BUILD_FUZZ}
      -DYAWT_ENABLE_LOGGING=${YAWT_ENABLE_LOGGING}
      -DYAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
)
