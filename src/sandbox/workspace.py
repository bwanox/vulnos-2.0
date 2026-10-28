"""Creation and cleanup of disposable source workspaces."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from src.sandbox.models import WorkspacePair

_IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}


def _copy_regular_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True)

    for current, directory_names, file_names in os.walk(
        source,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_directory = destination / relative
        target_directory.mkdir(parents=True, exist_ok=True)
        retained_directories = []
        for name in directory_names:
            if name in _IGNORED_DIRECTORIES:
                continue
            if (current_path / name).is_symlink():
                raise ValueError(
                    f"Source tree contains an unsupported symlink: {current_path / name}"
                )
            retained_directories.append(name)
        directory_names[:] = sorted(retained_directories)

        for name in sorted(file_names):
            source_file = current_path / name
            file_mode = source_file.lstat().st_mode
            if stat.S_ISLNK(file_mode):
                raise ValueError(f"Source tree contains an unsupported symlink: {source_file}")
            if not stat.S_ISREG(file_mode):
                raise OSError(f"Unsupported non-regular source file: {source_file}")
            shutil.copyfile(source_file, target_directory / name)


@contextmanager
def temporary_workspaces(source_path: str | Path) -> Generator[WorkspacePair, None, None]:
    """Yield isolated copies of a local source tree and always remove them."""
    source = Path(source_path).expanduser().resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"Source path is not a directory: {source}")

    with tempfile.TemporaryDirectory(prefix="vulnos-sandbox-") as temporary_root:
        root = Path(temporary_root)
        original = root / "original"
        patched = root / "patched"
        _copy_regular_tree(source, original)
        _copy_regular_tree(source, patched)
        getuid = getattr(os, "getuid", None)
        if getuid is not None and getuid() == 0:
            _assign_non_root_ownership(root)
        yield WorkspacePair(
            original_path=original,
            patched_path=patched,
            root_path=root,
        )


def _assign_non_root_ownership(root: Path) -> None:
    for current, directory_names, file_names in os.walk(root):
        current_path = Path(current)
        os.chown(current_path, 65532, 65532)
        for name in directory_names + file_names:
            os.chown(current_path / name, 65532, 65532)


def _raise_walk_error(error: OSError) -> None:
    raise error
