from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Body

from ..internal import ospaths
from ..internal.database import database

from ..deps import (
    UserAuthDep, LoggerDep, SessionDep, KeyPermCreate,
    KeyPermRead, KeyPermUpdate, KeyPermDelete
)
from ..models.folders import FolderContents
from ..models.common import GenericSuccess, HTTPStatusError

# TODO: Find a way to turn parent checks into a reusable function
router = APIRouter(
    prefix='/folders', 
    tags=['Folder Management'],
    responses={
        403: {
            'model': HTTPStatusError,
            'description': '`X-API-Key` header lacks a specific permission.'
        }
    }
)


@router.get('/', response_model=FolderContents)
async def list_root_folder_contents(
    user: UserAuthDep, session: SessionDep, 
    api_key: KeyPermRead
) -> FolderContents:
    """Always returns `FolderContents` for the root path."""
    # No convert and verify since the directory is not user provided
    user_datadir: Path = ospaths.get_user_datadir(user.username)

    folder_contents = await database.folders.list_folder_data(session, user.username, user_datadir)
    folder_contents.folder_path = '/'

    return folder_contents


@router.post(
    '/{folder_path:path}',
    responses={
        409: {
            'model': HTTPStatusError,
            'description': "Folder path provided is a folder, or folder already exists."
        },
        400: {
            'model': HTTPStatusError,
            'description': "Parent folder was not found."
        },
    },
    response_model=GenericSuccess
)
async def create_folder(
    folder_path: str, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep,
    api_key: KeyPermCreate
) -> GenericSuccess:
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    # Database and filesystem checks
    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath)
    if os_folderpath.is_dir() or folder_exists:
        if folder_exists and not os_folderpath.is_dir():
            logger.warning("Folder '%s' exists in the filesystem without a database entry", os_folderpath)
        
        raise HTTPException(status_code=409, detail="Folder exists")

    parent_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath.parent)
    if not parent_exists:
        logger.warning(
            "Parent folder '%s' for folder '%s' exists without a database entry",
            os_folderpath.parent, os_folderpath
        )
        raise HTTPException(status_code=400, detail="Parent folder not found")
    
    # Actual logic
    await database.folders.create_folder(session, user.username, os_folderpath)
    return {'success': True}


@router.get(
    '/{folder_path:path}', 
    responses={
        404: {
            'model': HTTPStatusError,
            'description': "Folder does not exist."
        },
        400: {
            'model': HTTPStatusError,
            'description': "Parent folder was not found."
        },
        409: {
            'model': HTTPStatusError,
            'description': "Folder path provided was a file."
        }
    },
    response_model=FolderContents
)
async def list_folder_contents(
    folder_path: str, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep,
    api_key: KeyPermRead
) -> FolderContents:
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    # Database and filesystem checks
    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath)
    if not os_folderpath.is_dir() or not folder_exists:
        raise HTTPException(status_code=404, detail="Folder does not exist")

    parent_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath.parent)
    if not parent_exists:
        logger.warning(
            "Parent folder '%s' for folder '%s' exists without a database entry",
            os_folderpath.parent, os_folderpath
        )
        raise HTTPException(status_code=400, detail="Parent folder not found")

    folder_contents = await database.folders.list_folder_data(session, user.username, os_folderpath)
    return folder_contents


@router.delete(
    '/{folder_path:path}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "Parent folder was not found."
        },
        404: {
            'model': HTTPStatusError,
            'description': "Folder does not exist."
        },
        409: {
            'model': HTTPStatusError,
            'description': "Folder path provided was a file."
        }
    },
    response_model=GenericSuccess
)
async def remove_folder(
    folder_path: str, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep,
    api_key: KeyPermDelete
) -> GenericSuccess:
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    # Database and filesystem checks
    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath)
    if not os_folderpath.is_dir() or not folder_exists:
        raise HTTPException(status_code=404, detail="Folder does not exist")
    
    parent_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath.parent)
    if not parent_exists:
        logger.warning(
            "Parent folder '%s' for folder '%s' exists without a database entry",
            os_folderpath.parent, os_folderpath
        )
        raise HTTPException(status_code=400, detail="Parent folder not found")

    await database.folders.remove_folder(session, user.username, os_folderpath)
    return {'success': True}


@router.put(
    '/{folder_path:path}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "Parent folder for folder path was not found."
        },
        404: {
            'model': HTTPStatusError,
            'description': "Old folder does not exist."
        },
        409: {
            'model': HTTPStatusError,
            'description': """
Either:

- Old folder path provided is a file
- New folder path provided is a file
- New folder path already exists
            """
        }
    },
    response_model=GenericSuccess
)
async def rename_folder(
    folder_path: str, 
    new_name: Annotated[str, Body(embed=True)], 
    user: UserAuthDep,
    
    session: SessionDep,
    logger: LoggerDep,
    api_key: KeyPermUpdate
) -> GenericSuccess:
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    # Database and filesystem checks
    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Old folder path provided is a file")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath)
    if not os_folderpath.is_dir() or not folder_exists:
        raise HTTPException(status_code=404, detail="Old folder does not exist")
    
    parent_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath.parent)
    if not parent_exists:
        logger.warning(
            "Parent folder '%s' for folder '%s' exists without a database entry",
            os_folderpath.parent, os_folderpath
        )
        raise HTTPException(status_code=400, detail="Parent folder for old path not found")

    new_path: Path = ospaths.convert_and_verify(os_folderpath.parent / new_name, user_datadir)
    if new_path.is_file():
        raise HTTPException(status_code=409, detail="New folder path provided is a file")

    new_folder_exists: bool = await database.folders.check_folder_exists(session, user.username, new_path)
    if new_path.is_dir() or new_folder_exists:
        raise HTTPException(status_code=409, detail="New folder path already exists")
    
    new_parent_exists: bool = await database.folders.check_folder_exists(session, user.username, new_path.parent)
    if not new_parent_exists:
        logger.warning(
            "Parent folder '%s' for folder '%s' exists without a database entry",
            new_path.parent, new_path
        )
        raise HTTPException(status_code=400, detail="Parent folder for new path not found")
    
    await database.folders.rename_folder(
        session, user.username, 
        os_folderpath, new_path
    )
    return {'success': True}
