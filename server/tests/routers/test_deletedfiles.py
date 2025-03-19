import pytest
import aiofiles

from sqlmodel.ext.asyncio.session import AsyncSession
from httpx import AsyncClient
from app.internal.database import database
from app.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def reusable_upload_delete(
        file_path, client: AsyncClient,
        admin_headers: dict, 
        admin_userinfo,
        session: AsyncSession,
        http_filename: str
):
    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            f'/api/files/file/delete_folder/{http_filename}',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'delete_folder' / f'{http_filename}'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists

    res2 = await client.delete(f'/api/files/file/delete_folder/{http_filename}', headers=admin_headers)
    res2_json = res2.json()

    assert res2_json == {'success': True}
    assert res2.status_code == 200


async def test_create_folders(
        client: AsyncClient, admin_headers: dict, 
        session: AsyncSession, admin_userinfo
):
    res = await client.post('/api/folders/delete_folder', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'delete_folder'
    assert database_path.is_dir()

    folder_exists = await database.folders.check_folder_exists(
        session, admin_userinfo.username,
        database_path
    )
    assert folder_exists


async def test_upload_to_delete(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload_deleted'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")

    # TODO: Use aiofiles once httpx supports it
    with open(file_path, 'rb') as file:
        files = {'file': (file)}
        res = await client.post(
            '/api/files/file/delete_folder/delete_test',
            files=files,
            headers=admin_headers
        )

        res_json = res.json()

        assert res.status_code == 200
        assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'delete_folder' / 'delete_test'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists

    res2 = await client.delete('/api/files/file/delete_folder/delete_test', headers=admin_headers)
    res2_json = res2.json()

    assert res2_json == {'success': True}
    assert res2.status_code == 200


async def test_show_files_with_deletes(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/deleted/', headers=admin_headers)
    assert res.status_code == 200

    assert '/delete_folder/delete_test' in res.json()


async def test_show_delete_versions(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/deleted/delete_folder/delete_test', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    
    # look for deleted_on
    assert res_json[0]['deleted_on']


async def test_restore_delete_version(
        client: AsyncClient, 
        admin_headers: dict, 
        session: AsyncSession, 
        admin_userinfo
):
    post_data = {'offset': 0}
    res = await client.put(
        '/api/files/deleted/delete_folder/delete_test', 
        headers=admin_headers,
        json=post_data
    )

    res_json = res.json()

    assert res.status_code == 200
    assert res_json == {'success': True}

    database_path = data_directories.user_data / admin_userinfo.username / 'delete_folder' / 'delete_test'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists

    res2 = await client.delete('/api/files/file/delete_folder/delete_test', headers=admin_headers)
    res2_json = res2.json()

    assert res2_json == {'success': True}
    assert res2.status_code == 200

    assert not database_path.is_file()


async def test_restore_delete_version_invalid_offset(client: AsyncClient, admin_headers: dict):
    post_data = {'offset': 42}
    res = await client.put(
        '/api/files/deleted/delete_folder/delete_test', 
        headers=admin_headers,
        json=post_data
    )

    assert res.status_code == 400
    assert res.json() == {'detail': 'Restore offset is invalid'}


async def test_delete_file_version_invalid_offset(client: AsyncClient, admin_headers: dict):
    post_data = {'offset': 42}
    res = await client.delete(
        '/api/files/deleted/delete_folder/delete_test', 
        headers=admin_headers,
        params=post_data
    )

    assert res.status_code == 400
    assert res.json() == {'detail': 'Delete offset is invalid'}


async def test_delete_file_version(
        client: AsyncClient, 
        admin_headers: dict,
):
    post_data = {'offset': 0}
    res = await client.delete(
        '/api/files/deleted/delete_folder/delete_test', 
        headers=admin_headers,
        params=post_data
    )

    assert res.status_code == 200
    assert res.json() == {'success': True}


async def test_upload_and_delete_batched(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload_deleted'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")
    
    for index in range(0, 5):
        await reusable_upload_delete(
            file_path, client, admin_headers,
            admin_userinfo, session,
            'delete_test_multiple'
        )


async def test_show_multiple_delete_versions(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/files/deleted/delete_folder/delete_test_multiple', headers=admin_headers)
    assert res.status_code == 200

    assert len(res.json()) == 5


async def test_show_multiple_delete_versions_with_amount(client: AsyncClient, admin_headers: dict):
    res = await client.get(
        '/api/files/deleted/delete_folder/delete_test_multiple', 
        headers=admin_headers,
        params={'amount': 3}
    )
    assert res.status_code == 200

    assert len(res.json()) == 3


async def test_restore_using_offset_from_multiple(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    res = await client.put(
        '/api/files/deleted/delete_folder/delete_test_multiple', 
        headers=admin_headers,
        json={'offset': 3}
    )
    assert res.status_code == 200
    assert res.json() == {'success': True}


    database_path = data_directories.user_data / admin_userinfo.username / 'delete_folder' / 'delete_test_multiple'
    assert database_path.is_file()

    file_exists = await database.files.check_file_exists(
        session, 
        admin_userinfo.username, 
        database_path
    )
    assert file_exists


async def test_delete_all_versions_from_multiple(client: AsyncClient, admin_headers: dict):
    res = await client.delete(
        '/api/files/deleted/delete_folder/delete_test_multiple', 
        headers=admin_headers,
        params={'delete_all': True}
    )

    assert res.status_code == 200
    assert res.json() == {'success': True}

    res2 = await client.get(
        '/api/files/deleted/delete_folder/delete_test_multiple', 
        headers=admin_headers
    )
    assert res2.status_code == 200

    assert len(res2.json()) == 0


async def test_empty_trashbin(
        client: AsyncClient, session: AsyncSession, 
        admin_headers: dict, admin_userinfo
):
    file_path = data_directories.temp_files / 'test_fileupload_deleted'
    async with aiofiles.open(file_path, "wb") as file:
        await file.write(b"HelloWorld")
    
    for index in range(0, 2):
        for _ in range(0, 2):
            await reusable_upload_delete(
                file_path, client, admin_headers,
                admin_userinfo, session,
                f'trashbin_empty_multiple_{index}'
            )

    res2 = await client.delete(
        '/api/files/deleted/',
        headers=admin_headers
    )
    assert res2.status_code == 200
    assert res2.json() == {'success': True}

    res3 = await client.get(
        '/api/files/deleted/', 
        headers=admin_headers
    )
    assert res3.status_code == 200
    assert len(res3.json()) == 0
