from pathlib import Path
from fastapi import HTTPException

from .config import data_directories


USER_DATADIR = data_directories.user_data


def make_data_dirs():
    path: Path
    for key, path in data_directories:
        path.mkdir(mode=0o755, exist_ok=True)


def get_user_datadir(username: str) -> Path:
    user_datadir = (USER_DATADIR / username).resolve()

    if not user_datadir.is_dir():
        raise RuntimeError(f"data directory for user '{username}' is invalid")

    if not user_datadir.is_relative_to(USER_DATADIR):
        raise RuntimeError(f"{username}'s data directory is not relative to {USER_DATADIR}")

    return user_datadir


def convert_and_verify(path: Path, user_datadir: Path) -> Path:
    if any(path == '..' for path in path.parts):
        raise HTTPException(status_code=403, detail="Invalid file path")

    path = path.resolve()

    if not path.is_relative_to(user_datadir) or path == user_datadir:
        raise HTTPException(status_code=403, detail="Invalid file path")

    if not path.parent.exists():
        raise HTTPException(status_code=400, detail="Parent folder not found")

    return path
