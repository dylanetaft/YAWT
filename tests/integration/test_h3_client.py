#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import tempfile
import time


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def generate_certs(tmpdir):
    cert = os.path.join(tmpdir, "cert.pem")
    key = os.path.join(tmpdir, "key.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key, "-out", cert,
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True,
    )
    return cert, key


def main():
    build_dir = os.environ.get("YAWT_BUILD_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "build"))
    server_bin = os.path.join(build_dir, "install", "bin", "examples", "h3_server")
    client_bin = os.path.join(build_dir, "install", "bin", "examples", "h3_client")

    if not os.path.isfile(server_bin):
        print(f"FAIL: h3_server not found at {server_bin}", file=sys.stderr)
        return 1

    if not os.path.isfile(client_bin):
        print(f"FAIL: h3_client not found at {client_bin}", file=sys.stderr)
        return 1

    port = find_free_port()

    with tempfile.TemporaryDirectory(prefix="yawt_test_") as tmpdir:
        cert, key = generate_certs(tmpdir)

        server_proc = subprocess.Popen(
            [server_bin, cert, key, str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        try:
            time.sleep(0.5)

            result = subprocess.run(
                [client_bin, f"https://localhost:{port}/", cert],
                capture_output=True, text=True, timeout=10,
            )

            if result.returncode != 0:
                print(f"FAIL: h3_client exited {result.returncode}", file=sys.stderr)
                print(f"stdout: {result.stdout[:500]}", file=sys.stderr)
                print(f"stderr: {result.stderr[:500]}", file=sys.stderr)
                return 1

            if "HTTP/3 200" not in result.stdout:
                print(f"FAIL: expected HTTP/3 200, got: {result.stdout[:200]!r}", file=sys.stderr)
                return 1

            if "Hello, HTTP/3!" not in result.stdout:
                print(f"FAIL: response body missing expected content", file=sys.stderr)
                return 1

            print("PASS: h3_client integration test")
            return 0

        except subprocess.TimeoutExpired:
            print("FAIL: h3_client timed out", file=sys.stderr)
            return 1
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
