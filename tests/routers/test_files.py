import pytest
import aiofiles

from sqlmodel.ext.asyncio.session import AsyncSession
from httpx import AsyncClient
from app.internal.database import database
from app.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def test_file_upload(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")

    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'file1'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists


async def test_file_upload_conflict(client: AsyncClient, admin_headers: dict):
    file_path = data_directories.temp_files / 'test_fileupload'
    
    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 409
        assert res_json == {'detail': 'File exists'}


async def test_file_retrieve(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/file1', headers=admin_headers)
    res_body = res.text

    assert res.status_code == 200
    assert res_body == "HelloWorld"


async def test_file_retrieve_invalid(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/fileNull', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 404
    assert res_json == {'detail': 'File not found'}


async def test_file_update(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupdate'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"WorldHello")

    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.put(
            '/api/files/file/file1',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'file1'
    assert database_path.is_file()


async def test_file_update_invalid(client: AsyncClient, admin_headers: dict):
    file_path = data_directories.temp_files / 'test_fileupdate'
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.put(
            '/api/files/file/fileNull',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 404
        assert res_json == {'detail': 'File not found'}


async def test_file_retrieve_updated(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/file1', headers=admin_headers)
    res_body = res.text

    assert res.status_code == 200
    assert res_body == "WorldHello"


async def test_file_rename(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    post_data = {'new_name': 'fileRenamed'}
    res = await client.patch('/api/files/file/file1', headers=admin_headers, json=post_data)

    res_json = res.json()
    assert res.status_code == 200

    assert res_json == {'success': True}
    database_path = data_directories.user_data / admin_userinfo.username / 'file1'

    assert not database_path.is_file()
    new_path = data_directories.user_data / admin_userinfo.username / 'fileRenamed'

    assert new_path.is_file()
    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        new_path
    )
    assert file_exists


async def test_file_delete(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    res = await client.delete('/api/files/file/fileRenamed', headers=admin_headers)
    res_json = res.json()

    assert res_json == {'success': True}
    assert res.status_code == 200
    
    database_path = data_directories.user_data / admin_userinfo.username / 'fileRenamed'
    assert not database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert not file_exists


async def test_file_retrieve_deleted(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/file/fileRenamed', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 404
    assert res_json == {'detail': "File not found"}
