from pathlib import PurePosixPath
import pytest
import aiofiles

from starlette.datastructures import UploadFile
from sqlmodel.ext.asyncio.session import AsyncSession
from app.server.internal.database import database
from app.server.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def test_create_folder_direct(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_folders_user', 'test_password')
    assert isinstance(user_created, bool) and user_created  # user_created is True and not USER_EXISTS

    user_model = await database.get_user(session, 'test_folders_user')
    assert user_model

    mock_folder_path = data_directories.user_data / 'test_folders_user' / 'direct_database_test'
    folder_created = await database.folders.create_folder(
        session, 'test_folders_user', mock_folder_path
    )

    assert mock_folder_path.is_dir()
    assert folder_created

    folder = await database.folders.get_folder(session, 'test_folders_user', mock_folder_path)
    assert folder


async def test_create_folder_exists(session: AsyncSession):
    mock_folder_path = data_directories.user_data / 'test_folders_user' / 'direct_database_test'
    try:
        await database.folders.create_folder(
            session, 'test_folders_user', mock_folder_path
        )
    except ValueError:
        return
    
    assert False, "Folder was created even if there is a conflict"


async def test_list_folder_data_direct(session: AsyncSession):
    mock_folder_path = data_directories.user_data / 'test_folders_user' / 'direct_database_test'
    folder_data = await database.folders.list_folder_data(
        session, 'test_folders_user', mock_folder_path
    )

    assert folder_data.folder_path == PurePosixPath('/direct_database_test')
    assert folder_data.files == []
    assert folder_data.folders == []


async def test_upload_into_folder(session: AsyncSession):
    file_path = data_directories.temp_files / 'test_folder_fileupload_direct'
    mock_file_path = (
        data_directories.user_data / 
        'test_folders_user' / 
        'direct_database_test' / 
        'test_fileupload_direct'
    )

    file_data: bytes = b"HelloWorld" * 10

    async with aiofiles.open(file_path, "wb+") as file:
        await file.write(file_data)
    
    with open(file_path, 'rb') as file:
        uploadfile = UploadFile(
            file, 
            filename=file_path.name,
            size=len(file_data)
        )

        uploaded = await database.files.save_file(
            session, 'test_folders_user',
            mock_file_path, uploadfile
        )
        assert uploaded

    mock_folder_path = data_directories.user_data / 'test_folders_user' / 'direct_database_test'
    folder_data = await database.folders.list_folder_data(
        session, 'test_folders_user', mock_folder_path
    )

    assert folder_data.folder_path == PurePosixPath('/direct_database_test')
    assert folder_data.files == [PurePosixPath('/direct_database_test/test_fileupload_direct')]
    assert folder_data.folders == []


async def test_nested_folder_create_direct(session: AsyncSession):
    mock_folder_path = (
        data_directories.user_data / 
        'test_folders_user' / 
        'direct_database_test' / 
        'nested_folder'
    )
    folder_created = await database.folders.create_folder(
        session, 'test_folders_user', mock_folder_path
    )

    assert mock_folder_path.is_dir()
    assert folder_created

    mock_parent_path = data_directories.user_data / 'test_folders_user' / 'direct_database_test'
    folder_data = await database.folders.list_folder_data(
        session, 'test_folders_user', mock_parent_path
    )

    assert folder_data.folder_path == PurePosixPath('/direct_database_test')
    assert folder_data.files == [PurePosixPath('/direct_database_test/test_fileupload_direct')]
    assert folder_data.folders == [PurePosixPath('/direct_database_test/nested_folder')]


async def test_rename_folder_direct(session: AsyncSession):
    mock_folder_path = (
        data_directories.user_data / 
        'test_folders_user' / 
        'direct_database_test'
    )
    mock_new_path = (
        data_directories.user_data / 
        'test_folders_user' / 
        'direct_database_test_rename'
    )
    folder_renamed = await database.folders.rename_folder(
        session, 'test_folders_user',
        mock_folder_path, mock_new_path
    )
    assert not mock_folder_path.is_dir()
    assert mock_new_path.is_dir()

    assert folder_renamed

    folder_data = await database.folders.list_folder_data(
        session, 'test_folders_user', mock_new_path
    )

    assert folder_data.folder_path == PurePosixPath('/direct_database_test_rename')
    assert folder_data.files == [PurePosixPath('/direct_database_test_rename/test_fileupload_direct')]
    assert folder_data.folders == [PurePosixPath('/direct_database_test_rename/nested_folder')]


async def test_delete_folder_direct(session: AsyncSession):
    mock_folder_path = (
        data_directories.user_data / 
        'test_folders_user' / 
        'direct_database_test_rename'
    )

    folder_deleted = await database.folders.remove_folder(
        session, 'test_folders_user', mock_folder_path
    )

    assert not mock_folder_path.is_dir()
    assert folder_deleted

    folder_exists = await database.folders.check_folder_exists(
        session, 'test_folders_user', mock_folder_path
    )
    assert not folder_exists
