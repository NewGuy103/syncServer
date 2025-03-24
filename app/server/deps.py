import logging

from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlmodel.ext.asyncio.session import AsyncSession

from .models.common import UserInfo
from .models.auth import ValidPermissions
from .internal.database import async_engine, database
from .internal.config import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/token', auto_error=False)
api_key_header = APIKeyHeader(
    name='X-API-Key', 
    auto_error=False,
    description=(
        "An API key that starts with `syncserver-`.\n\n"
        "Using an API key on `/token` or `/token/revoke` will throw a 403 Forbidden, "
        "as an API key is not required or is not intended to be used in those routes."
    )
)


InvalidCredentialsExc = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid authentication credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_session():
    async with AsyncSession(async_engine) as session:
        yield session


@lru_cache
def get_logger():
    return logging.getLogger('syncserver')


async def get_current_user(
        session: 'SessionDep',
        token: str = Depends(oauth2_scheme),
        x_api_key: str = Security(api_key_header),
) -> UserInfo:
    if not token and not x_api_key:
        raise InvalidCredentialsExc

    if token:
        session_valid: bool = await database.sessions.check_session_validity(session, token)
        if not session_valid:
            raise InvalidCredentialsExc
    else:
        key_valid: bool = await database.api_keys.verify_key(session, x_api_key)
        if not key_valid:
            raise InvalidCredentialsExc
    
    if x_api_key:
        user_info: UserInfo = await database.api_keys.get_user_info(session, x_api_key)
    else:
        user_info: UserInfo = await database.sessions.get_token_info(session, token)
    
    return user_info


def check_is_admin(user: 'UserAuthDep'):
    # TODO: Implement roles in database to prevent relying on direct comparison
    if user.username != settings.FIRST_USER_NAME:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to access admin-only endpoint"
        )


class KeyPermDependencies:
    async def create(self, session: 'SessionDep', x_api_key: Annotated[str | None, Security(api_key_header)]):
        if x_api_key is None:
            return
        
        key_valid: bool = await database.api_keys.verify_key(
            session, x_api_key, permission=ValidPermissions.create
        )
        if not key_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks permission '{ValidPermissions.create}'"
            )
        
        return x_api_key
    
    async def read(self, session: 'SessionDep', x_api_key: Annotated[str | None, Security(api_key_header)]):
        if x_api_key is None:
            return
        
        key_valid: bool = await database.api_keys.verify_key(
            session, x_api_key, permission=ValidPermissions.read
        )
        if not key_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks permission '{ValidPermissions.read}'"
            )
        
        return x_api_key

    async def update(self, session: 'SessionDep', x_api_key: Annotated[str | None, Security(api_key_header)]):
        if x_api_key is None:
            return
        
        key_valid: bool = await database.api_keys.verify_key(
            session, x_api_key, permission=ValidPermissions.update
        )
        if not key_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks permission '{ValidPermissions.update}'"
            )
        
        return x_api_key

    async def delete(self, session: 'SessionDep', x_api_key: Annotated[str | None, Security(api_key_header)]):
        if x_api_key is None:
            return
        
        key_valid: bool = await database.api_keys.verify_key(
            session, x_api_key, permission=ValidPermissions.delete
        )
        if not key_valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks permission '{ValidPermissions.delete}'"
            )
        
        return x_api_key

    async def notallowed(self, x_api_key: Annotated[str | None, Security(api_key_header)]):
        if x_api_key is None:
            return
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key not allowed in this endpoint"
        )


key_perm_deps = KeyPermDependencies()
UserAuthDep = Annotated[UserInfo, Depends(get_current_user)]

KeyPermCreate = Annotated[str | None, Security(key_perm_deps.create)]
KeyPermRead = Annotated[str | None, Security(key_perm_deps.read)]

KeyPermUpdate = Annotated[str | None, Security(key_perm_deps.update)]
KeyPermDelete = Annotated[str | None, Security(key_perm_deps.delete)]

KeyNotAllowed = Security(key_perm_deps.notallowed)

IsAdminDep = Security(check_is_admin)

LoggerDep = Annotated[logging.Logger, Depends(get_logger)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
