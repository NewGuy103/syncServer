from pathlib import Path, PurePosixPath
from typing import Annotated
from fastapi import APIRouter, Body, HTTPException
from pydantic import NonNegativeInt, PositiveInt

from ..deps import (
    UserAuthDep, LoggerDep, SessionDep,
    KeyPermRead, KeyPermUpdate, KeyPermDelete
)
from ..internal import ospaths
from ..internal.database import database
from ..internal.constants import DBReturnValues
from ..models.common import GenericSuccess, HTTPStatusError
from ..models.files import DeletedFilesGet


router = APIRouter(
    prefix='/deleted',
    responses={
        403: {
            'model': HTTPStatusError,
            'description': '`X-API-Key` header lacks a specific permission.'
        }
    }
)


@router.get('/', response_model=list[PurePosixPath])
async def retrieve_files_with_deletes(
    session: SessionDep, user: UserAuthDep,
    api_key: KeyPermRead
) -> list[PurePosixPath]:
    res = await database.files.deleted_files.show_files_with_deletes(
        session, user.username
    )
    return res


@router.get(
    '/{file_path:path}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "File path provided is a folder."
        },
        404: {
            'model': HTTPStatusError,
            'description': "File path was not found, or parent folder was not found."
        },
    },
    response_model=list[DeletedFilesGet]
)
async def retrieve_deleted_file_versions(
    file_path: str, session: SessionDep,
    user: UserAuthDep, logger: LoggerDep,
    
    api_key: KeyPermRead,
    amount: PositiveInt = 100,
    offset: NonNegativeInt = 0
) -> list[DeletedFilesGet]:
    """Returns an ordered list with newest entry first and oldest entry last."""
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    file_exists: bool = await database.files.lookup_database_for_file(session, user.username, os_filepath)
    if not file_exists:
        raise HTTPException(status_code=404, detail="File not found")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    res = await database.files.deleted_files.show_deleted_versions(
        session, user.username, 
        os_filepath, amount=amount, 
        offset=offset
    )
    return res


@router.delete('/', response_model=GenericSuccess)
async def empty_trashbin(
    session: SessionDep, user: UserAuthDep, 
    logger: LoggerDep, api_key: KeyPermDelete
) -> GenericSuccess:
    """Removes all instances of deleted files."""
    await database.files.deleted_files.empty_trashbin(
        session, user.username
    )
    return {'success': True}


@router.delete(
    '/{file_path:path}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "File path provided is a folder, or delete offset is invalid."
        },
        404: {
            'model': HTTPStatusError,
            'description': """
Either:

- File was not found
- Parent folder was not found
- File has no delete entries
            """
        }
    },
    response_model=GenericSuccess
)
async def delete_file_versions(
    file_path: str, session: SessionDep,
    user: UserAuthDep, logger: LoggerDep,
    api_key: KeyPermDelete,
    offset: NonNegativeInt = 0,
    delete_all: bool = False
) -> GenericSuccess:
    """Remove versions of a deleted file.
    
    Setting `delete_all` to `true` will remove all versions of this file.
    `delete_all` will cause `offset` to be ignored.
    """
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    file_exists: bool = await database.files.lookup_database_for_file(session, user.username, os_filepath)
    if not file_exists:
        raise HTTPException(status_code=404, detail="File not found")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    delete_entry_exists: bool = await database.files.deleted_files.lookup_deleted_exists(
        session, user.username, os_filepath
    )
    if not delete_entry_exists:
        raise HTTPException(status_code=404, detail="File has no delete entries")
    
    if delete_all:
        is_deleted: bool = await database.files.deleted_files.delete_all_versions(
            session, user.username, os_filepath
        )
    else:
        is_deleted: bool | str = await database.files.deleted_files.delete_version(
            session, user.username, 
            os_filepath, offset
        )
    match is_deleted:
        case True:
            pass
        case DBReturnValues.OFFSET_INVALID:
            raise HTTPException(status_code=400, detail="Delete offset is invalid")
        case _:
            logger.error("Invalid data: %s", is_deleted)
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    return {'success': True}


@router.put(
    '/{file_path:path}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "File path provided is a folder, or restore offset is invalid."
        },
        404: {
            'model': HTTPStatusError,
            'description': "File not found, or parent folder was not found."
        },
        409: {
            'model': HTTPStatusError,
            'description': 'A non-deleted file version already exists.'
        }
    },
    response_model=GenericSuccess
)
async def restore_file_version(
    file_path: str, session: SessionDep,
    user: UserAuthDep, logger: LoggerDep,
    api_key: KeyPermUpdate,
    offset: Annotated[NonNegativeInt, Body(embed=True)] = 0
) -> GenericSuccess:
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    if os_filepath.is_file():
        raise HTTPException(status_code=409, detail="Non-deleted file exists")
    
    file_exists: bool = await database.files.lookup_database_for_file(session, user.username, os_filepath)
    if not file_exists:
        raise HTTPException(status_code=404, detail="File path not found")
    
    file_restored = await database.files.deleted_files.restore_version(
        session, user.username, 
        os_filepath, offset
    )
    match file_restored:
        case True:
            pass
        case DBReturnValues.OFFSET_INVALID:
            raise HTTPException(status_code=400, detail="Restore offset is invalid")
        case _:
            logger.error("Invalid data: %s", file_restored)
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    return {'success': True}