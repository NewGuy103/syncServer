import shutil
import secrets
import pytest

from pathlib import Path
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport
from sqlmodel import text
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine


from app.main import app, app_lifespan
from app.deps import get_session
from app.models.common import UserInfo
from app.internal.config import settings
from app.internal.database import database


@pytest.fixture(scope='session')
def anyio_backend():
    return 'asyncio'


@pytest.fixture(scope='session', name='testing_engine')
async def override_database():
    async_engine = create_async_engine(
        "sqlite+aiosqlite:///testing.db",
        echo=False
    )
    database.override_engine(async_engine)

    async with AsyncSession(async_engine) as session:
        statement = text("PRAGMA foreign_keys=ON;")
        await session.exec(statement)
    
    return async_engine


@pytest.fixture(scope='session', autouse=True)
async def cleanup_datadirs():
    yield

    test_datadir = Path('test_syncserver').resolve()
    shutil.rmtree(test_datadir, ignore_errors=True)

    test_database = Path('testing.db').resolve()
    test_database.unlink(missing_ok=True)


@pytest.fixture(scope='session')
async def session(testing_engine):
    async with AsyncSession(testing_engine) as session:
        yield session


@pytest.fixture(scope='session')
async def client(session: AsyncSession):
    async def session_override():
        return session

    app.dependency_overrides[get_session] = session_override
    async with app_lifespan(app):
        async with AsyncClient(transport=ASGITransport(app), base_url='http://test') as client:
            yield client

    app.dependency_overrides.clear()


@pytest.fixture(scope='session', name='admin_headers')
async def get_admin_headers(client: AsyncClient):
    auth_data: dict = {
        'grant_type': 'password',
        'username': settings.FIRST_USER_NAME,
        'password': settings.FIRST_USER_PASSWORD
    }
    res = await client.post('/api/auth/token', data=auth_data)
    resp_json = res.json()

    headers = {'Authorization': f'Bearer {resp_json['access_token']}'}
    return headers


@pytest.fixture(scope='session', name='admin_userinfo')
async def get_admin_userinfo(client: AsyncClient, admin_headers: dict) -> UserInfo:
    res = await client.get('/api/auth/test_auth', headers=admin_headers)
    res_json: dict = res.json()

    return UserInfo(**res_json)


@pytest.fixture(scope='session', name='admin_apikey_headers')
async def get_admin_api_key(client: AsyncClient, admin_headers: dict):
    expiry_date = datetime.now(timezone.utc) + timedelta(days=1)
    post_data = {
        'key_name': secrets.token_hex(16),
        'key_permissions': ['create', 'read', 'update', 'delete'],
        'expiry_date': expiry_date.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    }
    res = await client.post(
        '/api/auth/api_keys',
        headers=admin_headers,
        json=post_data
    )
    res_json: str = res.json()
    headers: dict = {'X-Api-Key': res_json}

    return headers
