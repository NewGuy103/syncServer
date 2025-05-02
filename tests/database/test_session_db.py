import pytest

from datetime import datetime, timedelta, timezone

from sqlmodel.ext.asyncio.session import AsyncSession
from app.server.internal.database import database

pytestmark = pytest.mark.anyio


# User sessions, not the SQLAlchemy database session
async def test_create_session_token(session: AsyncSession):
    user_created = await database.users.add_user(session, 'test_session_user', 'test_password')
    assert isinstance(user_created, bool) and user_created  # user_created is True and not USER_EXISTS

    user_model = await database.get_user(session, 'test_session_user')
    assert user_model

    expire_offset: timedelta = timedelta(days=15)
    expiry_date: datetime = datetime.now(timezone.utc) + expire_offset

    session_token = await database.sessions.create_session_token(
        session, 'test_session_user', expiry_date
    )
    assert isinstance(session_token, str)


async def test_session_token_valid(session: AsyncSession):
    expire_offset: timedelta = timedelta(days=15)
    expiry_date: datetime = datetime.now(timezone.utc) + expire_offset

    session_token = await database.sessions.create_session_token(
        session, 'test_session_user', expiry_date
    )
    session_valid = await database.sessions.check_session_validity(session, session_token)

    assert session_valid


async def test_invalid_session_token(session: AsyncSession):
    session_valid = await database.sessions.check_session_validity(session, 'invalid_token')
    assert not session_valid


async def test_get_token_info(session: AsyncSession):
    expire_offset: timedelta = timedelta(days=15)
    expiry_date: datetime = datetime.now(timezone.utc) + expire_offset

    session_token = await database.sessions.create_session_token(
        session, 'test_session_user', expiry_date
    )
    user_info = await database.sessions.get_token_info(session, session_token)

    assert user_info.username == 'test_session_user'


async def test_revoke_session(session: AsyncSession):
    expire_offset: timedelta = timedelta(days=15)
    expiry_date: datetime = datetime.now(timezone.utc) + expire_offset

    session_token = await database.sessions.create_session_token(
        session, 'test_session_user', expiry_date
    )

    token_revoked = await database.sessions.revoke_session(session, session_token)
    assert token_revoked

    token_valid = await database.sessions.check_session_validity(session, session_token)
    assert not token_valid
