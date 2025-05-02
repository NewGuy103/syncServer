import pytest

from httpx import AsyncClient
from app.server.internal.config import data_directories

pytestmark = pytest.mark.anyio


async def test_admin_get_users(client: AsyncClient, admin_headers: dict):
    res = await client.get('/api/users/', headers=admin_headers)
    res_json: list[dict] = res.json()

    assert res.status_code == 200
    assert res_json[0].get('username') == 'admin'


async def test_admin_create_user(client: AsyncClient, admin_headers: dict):
    post_data = {'username': 'test_user_routes', 'password': 'test_password'}

    res = await client.post('/api/users/', headers=admin_headers, json=post_data)
    res_json: dict = res.json()

    assert res.status_code == 200
    assert res_json.get('username') == 'test_user_routes'

    assert (data_directories.user_data / 'test_user_routes').is_dir()


async def test_admin_create_user_conflict(client: AsyncClient, admin_headers: dict):
    post_data = {'username': 'test_user_routes', 'password': 'test_password'}

    res = await client.post('/api/users/', headers=admin_headers, json=post_data)
    res_json: dict = res.json()

    assert res.status_code == 409
    assert res_json == {'detail': "User already exists"}


async def test_admin_delete_user(client: AsyncClient, admin_headers: dict):
    res = await client.delete('/api/users/test_user_routes', headers=admin_headers)
    assert res.status_code == 200

    assert res.json() == {'success': True}
    assert not (data_directories.user_data / 'test_user_routes').is_dir()


async def test_admin_delete_admin_account(client: AsyncClient, admin_headers: dict):
    res = await client.delete('/api/users/admin', headers=admin_headers)
    assert res.status_code == 400

    assert res.json() == {"detail": "Cannot delete own user"}


async def test_interact_as_not_admin(client: AsyncClient, admin_headers: dict):
    post_data = {'username': 'test_user_insufficient', 'password': 'test_password'}

    res = await client.post('/api/users/', headers=admin_headers, json=post_data)
    res_json: dict = res.json()

    assert res.status_code == 200
    assert res_json.get('username') == 'test_user_insufficient'

    auth_data: dict = {
        'grant_type': 'password',
        'username': 'test_user_insufficient',
        'password': 'test_password'
    }
    res2 = await client.post('/api/auth/token', data=auth_data)
    assert res2.status_code == 200

    resp_json = res2.json()
    assert isinstance(resp_json, dict)

    access_token: str | None = resp_json.get('access_token')
    assert access_token is not None

    user_headers = {'Authorization': f"Bearer {access_token}"}

    res3 = await client.get('/api/users/', headers=user_headers)
    res3_json: list[dict] = res3.json()

    assert res3.status_code == 403
    assert res3_json == {'detail': 'Insufficient permissions to access admin-only endpoint'}
