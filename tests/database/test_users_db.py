from pathlib import Path
import pytest

from sqlmodel.ext.asyncio.session import AsyncSession
from app.server.internal.database import database
from app.server.internal.constants import DBReturnValues
from app.server.internal.config import settings, data_directories

pytestmark = pytest.mark.anyio


async def test_create_user(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_user', 'test_password')
    assert isinstance(user_created, bool) and user_created  # user_created is True and not USER_EXISTS

    user_model = await database.get_user(session, 'test_user')
    assert user_model

    user_data_dir = Path(data_directories.user_data) / user_model.username
    assert user_data_dir.is_dir()


async def test_create_user_exists(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_user', 'test_password')
    assert user_created == DBReturnValues.USER_EXISTS


async def test_verify_user(session: AsyncSession):
    user_verified = await database.users.verify_user(session, 'test_user', 'test_password')
    assert user_verified and user_verified != DBReturnValues.NO_USER


async def test_verify_user_invalid_credentials(session: AsyncSession):
    user_verified = await database.users.verify_user(session, 'test_user', 'invalid_password')
    assert not user_verified and user_verified != DBReturnValues.NO_USER


async def test_retrieve_user_public(session: AsyncSession):
    user_public = await database.users.retrieve_user(session, 'test_user')
    assert user_public.username == 'test_user'


async def test_retrieve_user_public_invalid(session: AsyncSession):
    user_public = await database.users.retrieve_user(session, 'invalid_user')
    assert user_public == DBReturnValues.NO_USER


async def test_retrieve_all_users(session: AsyncSession):
    user_public_list = await database.users.retrieve_all_users(session)
    assert isinstance(user_public_list, list)

    assert user_public_list[0].username == settings.FIRST_USER_NAME


async def test_delete_user(session: AsyncSession):
    user_deleted = await database.users.delete_user(session, 'test_user')
    assert user_deleted and user_deleted != DBReturnValues.NO_USER


async def test_retrieve_user_public_after_delete(session: AsyncSession):
    user_public = await database.users.retrieve_user(session, 'test_user')
    assert user_public == DBReturnValues.NO_USER
