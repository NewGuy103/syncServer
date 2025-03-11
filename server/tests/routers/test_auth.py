import pytest

from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models.common import UserInfo
from app.internal.database import database
from app.internal.config import settings


pytestmark = pytest.mark.anyio
async def test_token_login(client: AsyncClient, session: AsyncSession):
    auth_data: dict = {
        'grant_type': 'password',
        'username': settings.FIRST_USER_NAME,
        'password': settings.FIRST_USER_PASSWORD
    }
    res = await client.post('/api/auth/token', data=auth_data)
    assert res.status_code == 200
    resp_json = res.json()

    assert isinstance(resp_json, dict)

    access_token: str | None = resp_json.get('access_token')
    assert access_token is not None

    db_result: UserInfo = await database.sessions.get_token_info(session, access_token)
    assert isinstance(db_result, UserInfo)

    assert db_result.username == settings.FIRST_USER_NAME
    assert db_result.auth_type == 'token'


async def test_token_login_invalid(client: AsyncClient):
    auth_data: dict = {
        'grant_type': 'password',
        'username': settings.FIRST_USER_NAME,
        'password': "invalid"
    }
    res = await client.post('/api/auth/token', data=auth_data)
    assert res.status_code == 401


async def test_username_too_long(client: AsyncClient):
    auth_data: dict = {
        'grant_type': 'password',
        'username': "123456789012345678901234567890x",
        'password': "any"
    }
    res = await client.post('/api/auth/token', data=auth_data)
    assert res.status_code == 400


async def test_token_revoke(client: AsyncClient, admin_headers: dict, session: AsyncSession):
    auth_data: dict = {
        'grant_type': 'password',
        'username': settings.FIRST_USER_NAME,
        'password': settings.FIRST_USER_PASSWORD
    }
    res = await client.post('/api/auth/token', data=auth_data)
    resp_json = res.json()

    res = await client.post(
        '/api/auth/revoke', 
        headers=admin_headers,
        data={'token': resp_json['access_token']}
    )
    assert res.status_code == 200
    assert res.json() is None


async def test_token_auth(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/auth/test_auth', headers=admin_headers)
    res_json: dict = res.json()

    assert res.status_code == 200
    assert res_json.get('username') == settings.FIRST_USER_NAME
    assert res_json.get('auth_type') == 'token'


async def test_create_api_key(client: AsyncClient, admin_headers: dict, session: AsyncSession):
    expiry_date = datetime.now(timezone.utc) + timedelta(days=1)
    post_data = {
        'key_name': 'test-apikey',
        'key_permissions': ['create', 'read', 'update', 'delete'],
        'expiry_date': expiry_date.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    }
    res = await client.post(
        '/api/auth/api_keys',
        headers=admin_headers,
        json=post_data
    )
    res_json: str = res.json()

    assert res.status_code == 200
    assert res_json.startswith('syncserver-')

    db_result: UserInfo = await database.api_keys.get_user_info(session, res_json)
    assert isinstance(db_result, UserInfo)

    assert db_result.username == settings.FIRST_USER_NAME
    assert db_result.auth_type == 'api_key'


async def test_create_existing_api_key(client: AsyncClient, admin_headers: dict):
    expiry_date = datetime.now(timezone.utc) + timedelta(days=1)
    post_data = {
        'key_name': 'test-apikey',
        'key_permissions': ['create', 'read', 'update', 'delete'],
        'expiry_date': expiry_date.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    }
    res = await client.post(
        '/api/auth/api_keys',
        headers=admin_headers,
        json=post_data
    )
    assert res.status_code == 409


async def test_list_api_keys(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/auth/api_keys', headers=admin_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert isinstance(res_json, list)


async def test_delete_api_key(client: AsyncClient, admin_headers: dict):
    res = await client.delete('/api/auth/api_keys/test-apikey', headers=admin_headers)

    assert res.status_code == 200
    assert res.json() == {'success': True}


async def test_delete_invalid_api_key(client: AsyncClient, admin_headers: dict):
    res = await client.delete('/api/auth/api_keys/test-apikey', headers=admin_headers)
    assert res.status_code == 404


async def test_apikey_auth(client: AsyncClient, admin_apikey_headers: dict):
    res = await client.get('/api/auth/test_auth', headers=admin_apikey_headers)
    res_json = res.json()

    assert res.status_code == 200
    assert res_json.get('username') == settings.FIRST_USER_NAME
    assert res_json.get('auth_type') == 'api_key'
