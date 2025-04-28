from enum import StrEnum, auto
from typing import Annotated, Literal
from pydantic import AwareDatetime, BaseModel, FutureDatetime
from pathlib import Path, PurePosixPath


# Controller state
class FileListWidgetData(BaseModel):
    data_type: Literal['file', 'folder']
    path: PurePosixPath


class UploadStartedState(BaseModel):
    random_id: str
    local_path: Path
    server_path: PurePosixPath


class DownloadStartedState(BaseModel):
    random_id: str
    local_path: Path
    server_path: PurePosixPath


class DeletedFileVersionState(BaseModel):
    index: int
    deleted_on: AwareDatetime


class GenericSuccess(BaseModel):
    success: Literal[True]


# Authentication Models
class AccessTokenErrorCodes(StrEnum):
    invalid_request = auto()
    invalid_client = auto()
    invalid_grant = auto()
    invalid_scope = auto()

    unauthorized_client = auto()
    unsupported_grant_type = auto()


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class AccessTokenError(BaseModel):
    error: AccessTokenErrorCodes
    error_description: str


# API Key Models
class ValidPermissions(StrEnum):
    create = auto()
    read = auto()
    update = auto()
    delete = auto()


class APIKeyBase(BaseModel):
    key_name: str
    expiry_date: AwareDatetime
    key_permissions: set[ValidPermissions]


class APIKeyCreate(APIKeyBase):
    expiry_date: Annotated[AwareDatetime, FutureDatetime]


class APIKeyInfo(APIKeyBase):
    expired: bool


# File and folder models
class FolderContents(BaseModel):
    folder_path: PurePosixPath
    files: list[PurePosixPath]
    folders: list[PurePosixPath]


class DeletedFilesGet(BaseModel):
    deleted_on: AwareDatetime
