import shutil

from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Body

from ..internal import ospaths
from ..internal.database import database

from ..deps import UserAuthDep, SessionDep
from ..models.folders import FolderContents

router = APIRouter(prefix='/folders', tags=['Folder Management'])


@router.get('/')
async def list_root_folder_contents(user: UserAuthDep) -> FolderContents:
    # No convert and verify since the directory is not user provided
    user_datadir = ospaths.get_user_datadir(user.username)
    files: list[str] = [file.name for file in user_datadir.rglob('*') if file.is_file()]

    folders: list[str] = [folder.name for folder in user_datadir.rglob('*') if folder.is_dir()]
    return FolderContents(folder_path='/', files=files, folders=folders)


@router.post('/{folder_path:path}')
async def create_folder(folder_path: str, user: UserAuthDep, session: SessionDep):
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    if os_folderpath.is_dir():
        raise HTTPException(status_code=409, detail="Folder exists")

    folder_exists: bool = await database.folders.check_folder_exists(session, user.username, os_folderpath.parent)
    if not folder_exists:
        raise HTTPException(status_code=404, detail="Parent folder not found")
    
    await database.folders.create_folder(session, user.username, os_folderpath)
    return {'success': True}


@router.get('/{folder_path:path}')
async def list_folder_contents(folder_path: str, user: UserAuthDep) -> FolderContents:
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    if not os_folderpath.is_dir():
        raise HTTPException(status_code=409, detail="Folder not found")

    files: list[str] = [file.name for file in os_folderpath.rglob('*') if file.is_file()]
    folders: list[str] = [folder.name for folder in os_folderpath.rglob('*') if folder.is_dir()]

    return FolderContents(folder_path=folder_path, files=files, folders=folders)


@router.delete('/{folder_path:path}')
async def remove_folder(folder_path: str, user: UserAuthDep):
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    if not os_folderpath.is_dir():
        raise HTTPException(status_code=409, detail="Folder not found")

    shutil.rmtree(os_folderpath, ignore_errors=False)
    return {'success': True}


@router.put('/{folder_path:path}')
async def rename_folder(folder_path: str, new_name: Annotated[str, Body(embed=True)], user: UserAuthDep):
    user_datadir = ospaths.get_user_datadir(user.username)
    unsanitized_path: Path = user_datadir / folder_path

    os_folderpath: Path = ospaths.convert_and_verify(unsanitized_path, user_datadir)

    if os_folderpath.is_file():
        raise HTTPException(status_code=409, detail="Folder path provided is a file")

    if not os_folderpath.is_dir():
        raise HTTPException(status_code=409, detail="Folder not found")

    new_path: Path = ospaths.convert_and_verify(os_folderpath.parent / new_name, user_datadir)
    if new_path.is_file():
        raise HTTPException(status_code=409, detail="New folder path provided is a file")
    
    if new_path.is_dir():
        raise HTTPException(status_code=409, detail="Folder with the same name already exists")
    
    os_folderpath.rename(new_path)
    return {'success': True}
