import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app, app_lifespan
from app.internal.config import settings
from app.internal.database import database


@pytest.fixture(scope='module')
def anyio_backend():
    return 'asyncio'


@pytest.fixture(scope='module')
async def client():
    async with app_lifespan(app):
        async with AsyncClient(transport=ASGITransport(app), base_url='http://test') as client:
            yield client
