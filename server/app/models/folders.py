from pydantic import BaseModel


class FolderContents(BaseModel):
    folder_path: str
    files: list[str]
    folders: list[str]
