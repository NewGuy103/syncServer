from pathlib import PurePosixPath
from pydantic import BaseModel


class FolderContents(BaseModel):
    folder_path: PurePosixPath
    files: list[PurePosixPath]
    folders: list[PurePosixPath]
