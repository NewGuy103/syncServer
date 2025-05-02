from pathlib import PurePosixPath
import pytest
import aiofiles

from pydantic import ValidationError
from sqlmodel.ext.asyncio.session import AsyncSession
from httpx import AsyncClient

from app.server.models.folders import FolderContents
from app.server.internal.database import database
from app.server.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def test_create_folder(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    res = await client.post('/api/folders/test_folder', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder'
    assert database_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        database_path
    )
    assert folder_exists


async def test_create_folder_exists(client: AsyncClient, admin_headers: dict):
    res = await client.post('/api/folders/test_folder', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 409
    assert res_json == {'detail': 'Folder exists'}


async def test_create_folder_no_parent(client: AsyncClient, admin_headers: dict):
    res = await client.post('/api/folders/invalid/test_folder', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 400
    assert res_json == {'detail': 'Parent folder not found'}


async def test_create_nested_folder(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    res = await client.post('/api/folders/test_folder/test_nested', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}


    database_path = (data_directories.user_data / admin_userinfo.username / 'test_folder') / 'test_nested'
    assert database_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        database_path
    )
    assert folder_exists


async def test_file_upload_folder(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload_folder'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")

    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/test_folder/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = (data_directories.user_data / admin_userinfo.username / 'test_folder') / 'file1'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists

    assert database_path.read_text() == 'HelloWorld'


async def test_file_upload_path_provided_is_folder(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload_folder'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")

    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/test_folder',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 400
        assert res_json == {'detail': "File path provided is a folder"}


async def test_read_root_folder(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/folders/', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    try:
        folder_contents = FolderContents(**res_json)
    except ValidationError as e:
        assert False, e

    assert folder_contents.folder_path == PurePosixPath('/')
    assert PurePosixPath('/test_folder') in folder_contents.folders


async def test_read_folder(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/folders/test_folder', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    try:
        folder_contents = FolderContents(**res_json)
    except ValidationError as e:
        assert False, e

    assert folder_contents.folder_path == PurePosixPath('/test_folder')
    assert PurePosixPath('/test_folder/file1') in folder_contents.files


async def test_rename_folder(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    post_data = {'new_name': 'test_folder_renamed'}
    res = await client.put('/api/folders/test_folder', headers=admin_headers, json=post_data)

    res_json = res.json()
    assert res.status_code == 200

    assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder'
    assert not database_path.is_dir()

    new_path = data_directories.user_data / admin_userinfo.username / 'test_folder_renamed'
    assert new_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        database_path
    )
    assert not folder_exists

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        new_path
    )
    assert folder_exists


async def test_get_file_after_rename(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_renamed/file1', headers=admin_headers)
    res_body = res.text

    assert res.status_code == 200
    assert res_body == "HelloWorld"


async def test_delete_folder(client: AsyncClient, admin_headers: dict, admin_userinfo, session: AsyncSession):
    res = await client.delete('/api/folders/test_folder_renamed', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}

    database_path = (data_directories.user_data / admin_userinfo.username) / 'test_folder_renamed'
    assert not database_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username, database_path
    )
    assert not folder_exists


async def test_get_file_after_delete(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_renamed/file1', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 400
    assert res_json == {'detail': "Parent folder not found"}
    

# File tests on a folder
async def test_folder_file_upload(
    client: AsyncClient, 
    admin_headers: dict, 
    admin_userinfo,
    session: AsyncSession
):
    res = await client.post('/api/folders/test_folder_files', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder_files'
    assert database_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        database_path
    )
    assert folder_exists

    file_path = data_directories.temp_files / 'test_fileupload_folder'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")

    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res2 = await client.post(
            '/api/files/file/test_folder_files/file1',
            files=files,
            headers=admin_headers
        )

        res2_json = res2.json()

        assert res2.status_code == 200
        assert res2_json == {'success': True}


async def test_folder_file_upload_conflict(client: AsyncClient, admin_headers: dict):
    file_path = data_directories.temp_files / 'test_fileupload_folder'
    
    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/test_folder_files/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 409
        assert res_json == {'detail': 'File exists'}


async def test_folder_file_retrieve(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_files/file1', headers=admin_headers)
    res_body = res.text

    assert res.status_code == 200
    assert res_body == "HelloWorld"


async def test_folder_file_retrieve_invalid(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_files/fileNull', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 404
    assert res_json == {'detail': 'File not found'}


async def test_folder_file_update(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_folder_fileupdate'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"WorldHello")

    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.put(
            '/api/files/file/test_folder_files/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder_files' / 'file1'
    assert database_path.is_file()

    assert database_path.read_text() == 'WorldHello'


async def test_folder_file_update_invalid(client: AsyncClient, admin_headers: dict):
    file_path = data_directories.temp_files / 'test_folder_fileupdate'
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.put(
            '/api/files/file/test_folder_files/fileNull',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 404
        assert res_json == {'detail': 'File not found'}


async def test_folder_file_retrieve_updated(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_files/file1', headers=admin_headers)
    res_body = res.text

    assert res.status_code == 200
    assert res_body == "WorldHello"


async def test_folder_file_rename(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    post_data = {'new_name': 'fileRenamed'}
    res = await client.patch('/api/files/file/test_folder_files/file1', headers=admin_headers, json=post_data)

    res_json = res.json()
    assert res.status_code == 200

    assert res_json == {'success': True}
    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder_files' /'file1'

    assert not database_path.is_file()
    new_path = data_directories.user_data / admin_userinfo.username / 'test_folder_files' / 'fileRenamed'

    assert new_path.is_file()
    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        new_path
    )
    assert file_exists

    assert new_path.read_text() == 'WorldHello'


async def test_folder_file_delete(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    res = await client.delete('/api/files/file/test_folder_files/fileRenamed', headers=admin_headers)
    res_json = res.json()

    assert res_json == {'success': True}
    assert res.status_code == 200
    
    database_path = data_directories.user_data / admin_userinfo.username / 'test_folder_files' / 'fileRenamed'
    assert not database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert not file_exists


async def test_folder_file_retrieve_deleted(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/test_folder_files/fileRenamed', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 404
    assert res_json == {'detail': "File not found"}


async def test_folder_file_rename_deleted(client: AsyncClient, admin_headers: dict):
    post_data = {'new_name': 'fileDoubleRenamed'}
    res = await client.patch(
        '/api/files/file/test_folder_files/fileRenamed', 
        headers=admin_headers,
        json=post_data
    )

    res_json = res.json()

    assert res.status_code == 404
    assert res_json == {'detail': "File not found"}
