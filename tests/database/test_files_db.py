import pytest
import aiofiles

from starlette.datastructures import UploadFile

from sqlmodel.ext.asyncio.session import AsyncSession
from app.server.internal.database import database
from app.server.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def test_file_upload_direct(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_files_user', 'test_password')
    assert isinstance(user_created, bool) and user_created  # user_created is True and not USER_EXISTS

    user_model = await database.get_user(session, 'test_files_user')
    assert user_model

    file_path = data_directories.temp_files / 'test_fileupload_direct'
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_fileupload_direct'

    file_data: bytes = b"HelloWorld" * 10

    async with aiofiles.open(file_path, "wb+") as file:
        await file.write(file_data)
    
    with open(file_path, 'rb') as file:
        uploadfile = UploadFile(
            file, 
            filename='test_fileupload_direct',
            size=len(file_data)
        )

        uploaded = await database.files.save_file(
            session, 'test_files_user',
            mock_file_path, uploadfile
        )
        assert uploaded

    assert mock_file_path.is_file()
    assert mock_file_path.read_bytes() == file_data


async def test_file_modify_direct(session: AsyncSession):
    file_path = data_directories.temp_files / 'test_filemodify_direct'
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_fileupload_direct'

    file_data: bytes = b"WorldHello" * 10
    async with aiofiles.open(file_path, "wb+") as file:
        await file.write(file_data)
    
    with open(file_path, 'rb') as file:
        uploadfile = UploadFile(
            file, 
            filename='test_filemodify_direct',
            size=len(file_data)
        )

        uploaded = await database.files.update_file(
            session, 'test_files_user',
            mock_file_path, uploadfile
        )
        assert uploaded

    assert mock_file_path.is_file()
    assert mock_file_path.read_bytes() == file_data


async def test_check_file_exists(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_fileupload_direct'
    file_exists = await database.files.check_file_exists(
        session, 'test_files_user', mock_file_path
    )

    assert mock_file_path.is_file()
    assert file_exists


async def test_check_file_exists_invalid(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_invalid_file'
    file_exists = await database.files.check_file_exists(
        session, 'test_files_user', mock_file_path
    )

    assert not mock_file_path.is_file()
    assert not file_exists


async def test_file_rename_direct(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_fileupload_direct'
    mock_new_path = data_directories.user_data / 'test_files_user' / 'test_filerename_direct'

    file_renamed = await database.files.rename_file(
        session, 'test_files_user', mock_file_path,
        mock_new_path
    )
    assert not mock_file_path.is_file()
    assert mock_new_path.is_file()

    assert file_renamed


async def test_file_delete_direct(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_files_user' / 'test_filerename_direct'
    file_deleted = await database.files.delete_file(session, 'test_files_user', mock_file_path)

    assert not mock_file_path.is_file()
    assert file_deleted
