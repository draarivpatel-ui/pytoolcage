#!/usr/bin/env python3
"""Verify pytoolcage wheel and source distribution contents."""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List


def _check_wheel(path: Path, errors: List[str]) -> None:
    with zipfile.ZipFile(str(path), "r") as archive:
        names = archive.namelist()
        if "pytoolcage/py.typed" not in names:
            errors.append("wheel is missing pytoolcage/py.typed")
        if not any(name.startswith("pytoolcage/") and name.endswith("__init__.py") for name in names):
            errors.append("wheel is missing the pytoolcage package")
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.startswith("tests/") or "/tests/" in normalized:
                errors.append("wheel contains test files: " + normalized)
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                errors.append("wheel contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                errors.append("wheel contains key-like content: " + normalized)
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            errors.append("wheel must contain exactly one METADATA file")
        else:
            metadata = archive.read(metadata_names[0]).decode("utf-8", "replace")
            if "Name: pytoolcage" not in metadata:
                errors.append("wheel METADATA has the wrong package name")
            if "Requires-Python: >=3.9" not in metadata:
                errors.append("wheel METADATA is missing Requires-Python >=3.9")
            if "Requires-Dist:" in metadata:
                errors.append("wheel declares a runtime dependency")
            if ("/" + "Users" + "/") in metadata or ("\\" + "Users" + "\\") in metadata:
                errors.append("wheel metadata contains a local user path")


def _check_sdist(path: Path, errors: List[str]) -> None:
    with tarfile.open(str(path), "r:gz") as archive:
        names = archive.getnames()
        required_suffixes = ["/pyproject.toml", "/README.md", "/src/pytoolcage/__init__.py", "/src/pytoolcage/py.typed", "/tests/test_schema_matrix.py"]
        for suffix in required_suffixes:
            if not any(name.endswith(suffix) for name in names):
                errors.append("sdist is missing " + suffix)
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                errors.append("sdist contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                errors.append("sdist contains key-like content: " + normalized)
        pkg_info_names = [name for name in names if len(name.split("/")) == 2 and name.endswith("/PKG-INFO")]
        if len(pkg_info_names) != 1:
            errors.append("sdist must contain exactly one PKG-INFO file")
        else:
            extracted = archive.extractfile(pkg_info_names[0])
            metadata = extracted.read().decode("utf-8", "replace") if extracted else ""
            if "Name: pytoolcage" not in metadata:
                errors.append("sdist PKG-INFO has the wrong package name")
            if "Requires-Python: >=3.9" not in metadata:
                errors.append("sdist PKG-INFO is missing Requires-Python >=3.9")
            if "Requires-Dist:" in metadata:
                errors.append("sdist declares a runtime dependency")


def check_dist(dist: Path) -> List[str]:
    errors: List[str] = []
    wheels = sorted(dist.glob("*.whl")) if dist.is_dir() else []
    sdists = sorted(dist.glob("*.tar.gz")) if dist.is_dir() else []
    if len(wheels) != 1:
        errors.append("expected exactly one wheel, found " + str(len(wheels)))
    if len(sdists) != 1:
        errors.append("expected exactly one sdist, found " + str(len(sdists)))
    if wheels:
        _check_wheel(wheels[0], errors)
    if sdists:
        _check_sdist(sdists[0], errors)
    return errors


def main(argv: List[str]) -> int:
    errors = check_dist(Path(argv[1]) if len(argv) > 1 else Path("dist"))
    if errors:
        for error in errors:
            print("check_dist: " + error, file=sys.stderr)
        return 1
    print("distribution contents verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
