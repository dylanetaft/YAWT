#!/usr/bin/env python3
import subprocess
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <filename>")
    sys.exit(1)

filename = sys.argv[1]

with open(filename) as f:
    lines = [line.strip() for line in f if line.strip()]

for i, line in enumerate(lines, 1):
    print(f"[{i}/{len(lines)}] Running: opencode --agent rfc-reviewer run '{line}'")
    cmd = f"opencode --agent rfc-reviewer run '{line}'"
    result = subprocess.run(cmd, shell=True, capture_output = False)
    if result.returncode != 0:
        print(f"[{i}/{len(lines)}] Failed with exit code {result.returncode}")
