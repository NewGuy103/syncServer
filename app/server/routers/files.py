from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, UploadFile
from fastapi.responses import FileResponse

from ..internal import ospaths
from ..internal.database import database
from ..models.common import GenericSuccess
from ..deps import (
    UserAuthDep, LoggerDep, SessionDep, KeyPermCreate,
    KeyPermRead, KeyPermUpdate, KeyPermDelete
)


router = APIRouter(prefix='/file')


@router.post('/{file_path:path}')
async def upload_file(
    file_path: str, file: UploadFile, 
    user: UserAuthDep, session: SessionDep,
    logger: LoggerDep, api_key: KeyPermCreate
) -> GenericSuccess:
    if file.size is None:
        raise HTTPException(status_code=400, detail="Invalid file stream")
    
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")
    
    file_exists: bool = await database.files.check_file_exists(session, user.username, os_filepath)
    if os_filepath.is_file() and file_exists:
        raise HTTPException(status_code=409, detail="File exists")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    file_saved: bool | str = await database.files.save_file(session, user.username, os_filepath, file)
    match file_saved:
        case True:
            pass
        case _:
            logger.error("Invalid data: %s", file_saved)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    return {'success': True}


@router.get('/{file_path:path}')
async def retrieve_file(
    file_path: str, user: UserAuthDep, 
    logger: LoggerDep, session: SessionDep, 
    api_key: KeyPermRead
) -> FileResponse:
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    
    if not os_filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")

    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    file_exists: bool = await database.files.check_file_exists(session, user.username, os_filepath)
    if file_exists:
        return FileResponse(os_filepath, filename=file_path)
    
    # Don't reach this point...
    logger.error("Hit unreachable point in code, file_exists: %s", file_exists)
    raise HTTPException(status_code=500, detail="Internal Server Error")


@router.put('/{file_path:path}')
async def update_file(
    file_path: str, file: UploadFile, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep, api_key: KeyPermUpdate
) -> GenericSuccess:
    if file.size is None:
        raise HTTPException(status_code=400, detail="Invalid file stream")
    
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    file_exists: bool = await database.files.check_file_exists(session, user.username, os_filepath)
    if not os_filepath.is_file() and not file_exists:
        raise HTTPException(status_code=404, detail="File not found")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    file_updated: bool = await database.files.update_file(session, user.username, os_filepath, file)
    match file_updated:
        case True:
            pass
        case _:
            logger.error("Invalid data: %s", file_updated)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    return {'success': True}


@router.delete('/{file_path:path}')
async def delete_file(
    file_path: str, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep, api_key: KeyPermDelete
) -> GenericSuccess:
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    file_exists: bool = await database.files.check_file_exists(session, user.username, os_filepath)
    if not os_filepath.is_file() and not file_exists:
        raise HTTPException(status_code=404, detail="File not found")

    file_deleted: bool | str = await database.files.delete_file(session, user.username, os_filepath)
    match file_deleted:
        case True:
            pass
        case _:
            logger.error("Invalid data: %s", file_deleted)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    return {'success': True}


@router.patch('/{file_path:path}')
async def rename_file(
    file_path: str, new_name: Annotated[str, Body(embed=True)], 
    user: UserAuthDep, session: SessionDep, logger: LoggerDep,
    api_key: KeyPermUpdate
) -> GenericSuccess:
    user_datadir: Path = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / file_path

    os_filepath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)
    
    if os_filepath.is_dir():
        raise HTTPException(status_code=400, detail="File path provided is a folder")

    file_exists: bool = await database.files.check_file_exists(session, user.username, os_filepath)
    if not os_filepath.is_file() and not file_exists:
        raise HTTPException(status_code=404, detail="File not found")

    new_path: Path = ospaths.convert_and_verify(os_filepath.parent / new_name, user_datadir)
    new_file_exists: bool = await database.files.check_file_exists(session, user.username, new_path)
    
    if new_path.is_dir():
        raise HTTPException(status_code=409, detail="New file path provided is a folder")
    
    if new_path.is_file() and new_file_exists:
        raise HTTPException(status_code=409, detail="File with the same name already exists")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_filepath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")

    file_renamed: bool | str = await database.files.rename_file(session, user.username, os_filepath, new_path)
    match file_renamed:
        case True:
            pass
        case _:
            logger.error("Invalid data: %s", file_renamed)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    return {'success': True}
