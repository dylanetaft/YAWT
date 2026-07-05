# Build Instructions

## Prerequisites

System packages required (GnuTLS is consumed as a system library):
- `libgnutls28-dev` (Debian/Ubuntu) or `gnutls-devel` (RPM/Fedora)

## Build

```bash
# First build (or if CMakeCache.txt doesn't exist):
cmake -S . -B build && make -j32 -C build

# Subsequent rebuilds (avoid cached/stale yawt artifacts):
rm -rf build/yawt-prefix && make -j32 -C build
```

### Override install prefix

All dependencies and yawt itself install to `build/install/` by default. Override with:

```bash
cmake -S . -B build -DUSER_INSTALL_PREFIX=/custom/path && make -C build
```

## Test

```bash
ctest --test-dir build/yawt-prefix/src/yawt-build --output-on-failure
```

## Run servers

From the install prefix (adjust if you set a custom USER_INSTALL_PREFIX):

```bash
timeout 30 ./build/install/bin/examples/h3_server > /tmp/h3.log &
timeout 30 ./build/install/bin/examples/h3_client > /tmp/h3.log &
```

The servers run in the foreground, they don't exit, it is not a hang.

## Dependency layout

The superbuild manages these dependencies:

| Dep | Method | Source |
|-----|--------|--------|
| AllocNBuffer | ExternalProject + CMake find_package | github.com/dylanetaft/Alloc-N-Buffer |
| uthash | ExternalProject (headers only) | github.com/troydhanson/uthash |
| libev | ExternalProject (autotools) | github.com/dylanetaft/libev |
| GnuTLS | **System package** (pkg-config) | System package manager |
| Unity | ExternalProject + find_package (tests only) | github.com/ThrowTheSwitch/Unity |
