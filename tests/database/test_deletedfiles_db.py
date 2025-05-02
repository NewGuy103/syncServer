import pytest
import aiofiles

from pydantic import TypeAdapter
from starlette.datastructures import UploadFile

from sqlmodel.ext.asyncio.session import AsyncSession
from app.server.models.files import DeletedFilesGet
from app.server.internal.database import database
from app.server.internal.constants import DBReturnValues
from app.server.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def reusable_upload_delete(session: AsyncSession):
    file_path = data_directories.temp_files / 'test_deletedfiles_upload_direct'
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'

    file_data: bytes = b"HelloWorld" * 10

    async with aiofiles.open(file_path, "wb+") as file:
        await file.write(file_data)
    
    with open(file_path, 'rb') as file:
        uploadfile = UploadFile(
            file, 
            filename='test_deletedfiles_upload_direct',
            size=len(file_data)
        )

        uploaded = await database.files.save_file(
            session, 'test_deletedfiles_user',
            mock_file_path, uploadfile
        )
        assert uploaded

    assert mock_file_path.is_file()
    assert mock_file_path.read_bytes() == file_data

    file_deleted = await database.files.delete_file(
        session, 'test_deletedfiles_user', mock_file_path
    )
    assert file_deleted


async def test_delete_file(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_deletedfiles_user', 'test_password')
    assert isinstance(user_created, bool) and user_created  # user_created is True and not USER_EXISTS

    user_model = await database.get_user(session, 'test_deletedfiles_user')
    assert user_model

    # Make 3 versions
    for _ in range(0, 3):
        await reusable_upload_delete(session)


async def test_show_files_with_deletes(session: AsyncSession):
    files_with_deletes = await database.files.deleted_files.show_files_with_deletes(
        session, 'test_deletedfiles_user'
    )

    assert isinstance(files_with_deletes, list)
    assert '/test_deletedfiles_upload_direct' in files_with_deletes


async def test_show_file_deleted_versions(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'
    delete_versions = await database.files.deleted_files.show_deleted_versions(
        session, 'test_deletedfiles_user',
        mock_file_path
    )

    ta = TypeAdapter(list[DeletedFilesGet])
    ta.validate_python(delete_versions)
    
    assert len(delete_versions) == 3


async def test_delete_file_version(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'
    file_deleted = await database.files.deleted_files.delete_version(
        session, 'test_deletedfiles_user',
        mock_file_path, offset=0
    )

    assert file_deleted


async def test_delete_file_version_invalid_offset(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'
    file_deleted = await database.files.deleted_files.delete_version(
        session, 'test_deletedfiles_user',
        mock_file_path, offset=42
    )

    assert file_deleted == DBReturnValues.OFFSET_INVALID


async def test_restore_file_version(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'

    file_restored = await database.files.deleted_files.restore_version(
        session, 'test_deletedfiles_user',
        mock_file_path, offset=0
    )

    assert file_restored
    assert mock_file_path.is_file()

    assert mock_file_path.read_text() == ("HelloWorld" * 10)


async def test_delete_all_versions(session: AsyncSession):
    mock_file_path = data_directories.user_data / 'test_deletedfiles_user' / 'test_deletedfiles_upload_direct'

    file_deleted = await database.files.delete_file(
        session, 'test_deletedfiles_user', mock_file_path
    )
    assert file_deleted

    all_versions_deleted = await database.files.deleted_files.delete_all_versions(
        session, 'test_deletedfiles_user',
        mock_file_path
    )
    assert all_versions_deleted
    
    files_with_deletes = await database.files.deleted_files.show_files_with_deletes(
        session, 'test_deletedfiles_user'
    )

    assert isinstance(files_with_deletes, list)
    assert '/test_deletedfiles_upload_direct' not in files_with_deletes


async def test_empty_trashbin(session: AsyncSession):
    for _ in range(0, 3):
        await reusable_upload_delete(session)

    trashbin_emptied = await database.files.deleted_files.empty_trashbin(
        session, 'test_deletedfiles_user'
    )
    assert trashbin_emptied

    files_with_deletes = await database.files.deleted_files.show_files_with_deletes(
        session, 'test_deletedfiles_user'
    )

    assert isinstance(files_with_deletes, list)
    assert len(files_with_deletes) == 0
