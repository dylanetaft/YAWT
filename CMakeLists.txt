cmake_minimum_required(VERSION 3.10)
project(yawt_superbuild)
include (ExternalProject)
set(MY_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)


ExternalProject_add(
  libev
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/dylanetaft/libev.git
  GIT_TAG main
  CONFIGURE_COMMAND ${CMAKE_BINARY_DIR}/libev-prefix/src/libev/configure --enable-static --disable-shared --prefix=${MY_INSTALL_PREFIX}
)


ExternalProject_Add(
  AllocNBuffer
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/df00znet-dev/Alloc-N-Buffer
  GIT_TAG main
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${MY_INSTALL_PREFIX}
)


ExternalProject_Add(
  uthash
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://github.com/troydhanson/uthash.git
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory ${MY_INSTALL_PREFIX}/include/uthash
          COMMAND ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR>/src ${MY_INSTALL_PREFIX}/include/uthash
)

ExternalProject_Add(
  gnutls
  UPDATE_DISCONNECTED True
  GIT_REPOSITORY https://gitlab.com/gnutls/gnutls
  GIT_TAG "3.8.12"
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env GTKDOCIZE=true ./bootstrap && ./configure --prefix=${MY_INSTALL_PREFIX} --without-p11-kit --without-tpm2 --disable-shared --enable-static --disable-doc --disable-gtk-doc --disable-tests --disable-tools --disable-cxx --disable-nls --disable-guile
  BUILD_COMMAND make -j$(nproc)
  INSTALL_COMMAND make install
)

ExternalProject_Add(
    yawt 
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/src
    DEPENDS libev AllocNBuffer uthash gnutls
    CMAKE_ARGS
      -DCMAKE_INSTALL_PREFIX=${MY_INSTALL_PREFIX}
      -DCMAKE_PREFIX_PATH=${MY_INSTALL_PREFIX}
      -DBUILD_TESTS=${BUILD_TESTS}
      -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

