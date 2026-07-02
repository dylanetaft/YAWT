# Build Instructions

- Always run `rm -rf build/yawt-prefix` before `cmake` and `make` in the `build/` directory to avoid cached/stale artifacts.
- Build sequence: `rm -rf build/yawt-prefix && cd build && cmake . && make -j32`
- Test sequence, from build dir : ctest --test-dir yawt-prefix/src/yawt-build --output-on-failure

If you need to run the servers, do so from the build directory with a command like
timeout 30 ./install/bin/examples/h3_server > /tmp/h3.log &
The servers run in the foreground, they don't exit, it is not a hang 
