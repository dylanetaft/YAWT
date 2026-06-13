# Build Instructions

- Always run `rm -rf build/yawt-prefix` before `cmake` and `make` in the `build/` directory to avoid cached/stale artifacts.
- Build sequence: `rm -rf build/yawt-prefix && cd build && cmake . && make -j32`
