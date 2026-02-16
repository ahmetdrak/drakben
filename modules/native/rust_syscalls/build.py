#!/usr/bin/env python3
"""Build helper for the Drakben Rust Syscall Engine.

This script compiles the Rust ``drakben_syscalls`` crate into a shared
library (``.dll`` on Windows, ``.so`` on Linux) and copies the artefact
to the expected location used by :mod:`modules.native.syscall_loader`.

Requirements:
    - Rust toolchain (``rustup`` + ``cargo``) must be installed and on PATH.
    - On Windows cross-compilation from Linux/WSL:
      ``rustup target add x86_64-pc-windows-msvc``

Usage::

    python modules/native/rust_syscalls/build.py          # release build
    python modules/native/rust_syscalls/build.py --debug   # debug build

The resulting DLL/SO is placed at::

    modules/native/rust_syscalls/target/<profile>/drakben_syscalls.{dll,so}
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

CRATE_DIR = Path(__file__).resolve().parent
TARGET_DIR = CRATE_DIR / "target"

# Expected library names per platform
_LIB_NAMES = {
    "Windows": "drakben_syscalls.dll",
    "Linux": "libdrakben_syscalls.so",
    "Darwin": "libdrakben_syscalls.dylib",
}


def _check_cargo() -> str:
    """Return the path to ``cargo`` or exit with an error."""
    cargo = shutil.which("cargo")
    if cargo is None:
        print(
            "ERROR: 'cargo' not found on PATH. Install the Rust toolchain:\n"
            "  https://rustup.rs/",
            file=sys.stderr,
        )
        sys.exit(1)
    return cargo


def build(*, release: bool = True) -> Path:
    """Compile the crate and return the path to the output library.

    Args:
        release: Build in release mode (optimised). Set ``False`` for debug.

    Returns:
        :class:`pathlib.Path` to the compiled shared library.

    Raises:
        subprocess.CalledProcessError: If ``cargo build`` fails.
    """
    cargo = _check_cargo()
    profile = "release" if release else "debug"

    cmd = [cargo, "build"]
    if release:
        cmd.append("--release")

    print(f"[*] Building drakben_syscalls ({profile})…")
    subprocess.check_call(cmd, cwd=str(CRATE_DIR))

    lib_name = _LIB_NAMES.get(platform.system(), _LIB_NAMES["Linux"])
    artifact = TARGET_DIR / profile / lib_name

    if not artifact.exists():
        print(f"ERROR: Expected artefact not found at {artifact}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Build successful: {artifact}")
    print(f"    Size: {artifact.stat().st_size / 1024:.1f} KB")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Drakben Rust Syscall Engine")
    parser.add_argument(
        "--debug", action="store_true", help="Build in debug mode (unoptimised)",
    )
    args = parser.parse_args()
    build(release=not args.debug)


if __name__ == "__main__":
    main()
