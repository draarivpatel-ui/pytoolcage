"""Shared test helpers."""
import subprocess
import sys


def add_case(cls, name, function):
    safe = "".join(ch if ch.isalnum() else "_" for ch in name.lower()).strip("_")
    while "__" in safe:
        safe = safe.replace("__", "_")
    setattr(cls, "test_" + safe, function)


def run_cli(args, cwd, input_bytes=None):
    return subprocess.run(
        [sys.executable, "-m", "pytoolcage"] + list(args),
        cwd=str(cwd),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
