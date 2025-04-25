from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Form
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestFormStrict

from ..deps import (
    UserAuthDep, KeyPermCreate, KeyPermRead, KeyPermDelete, 
    LoggerDep, SessionDep, KeyNotAllowed
)
from ..models.auth import APIKeyCreate, APIKeyInfo, AccessTokenError, AccessTokenResponse, AccessTokenErrorCodes
from ..models.common import UserInfo, GenericSuccess
from ..internal.constants import DBReturnValues
from ..internal.database import database

router = APIRouter(prefix='/auth', tags=['Authorization'])


@router.post(
    '/token', 
    dependencies=[KeyNotAllowed],
    responses={
        400: {
            'model': AccessTokenError,
            'description': 'Provided username exceeded 30 characters'
        },
        401: {
            'model': AccessTokenError,
            'description': 'Invalid login crendentials were passed in'
        }
    },
    response_model=AccessTokenResponse
)
async def token_login(
    form_data: Annotated[OAuth2PasswordRequestFormStrict, Depends()],
    logger: LoggerDep, session: SessionDep
):
    """OAuth2 token login.
    
    Passing an `X-API-Key` header, valid or not, will throw an HTTP 403 Forbidden.
    """
    if len(form_data.username) > 30:
        access_token_error = AccessTokenError(
            error=AccessTokenErrorCodes.invalid_request,
            error_description='Provided username is over 30 characters'
        )
        return JSONResponse(
            access_token_error.model_dump(),
            status_code=400
        )

    verified: bool | str = await database.users.verify_user(session, form_data.username, form_data.password)
    match verified:
        case True:
            pass
        case False | DBReturnValues.NO_USER:
            access_token_error = AccessTokenError(
                error=AccessTokenErrorCodes.invalid_client,
                error_description='Invalid login credentials'
            )
            return JSONResponse(
                access_token_error.model_dump(),
                status_code=401
            )
        case _:
            logger.error("Invalid data: %s", verified)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    expire_offset: timedelta = timedelta(days=15)
    expiry_date: datetime = datetime.now(timezone.utc) + expire_offset

    token: str = await database.sessions.create_session_token(session, form_data.username, expiry_date)
    logger.info("User '%s' logged in", form_data.username)

    return AccessTokenResponse(
        access_token=token,
        token_type='bearer',
        expires_in=int(expire_offset.total_seconds())
    )


@router.post('/revoke', dependencies=[KeyNotAllowed])
async def revoke_login_token(user: UserAuthDep, token: Annotated[str, Form()], session: SessionDep) -> None:
    """OAuth2 token revocation.
    
    Passing an `X-API-Key` header, valid or not, will throw an HTTP 403 Forbidden.
    """
    token_valid = await database.sessions.check_session_validity(session, token)
    if not token_valid:
        return
    
    token_info = await database.sessions.get_token_info(session, token)
    if token_info.username != user.username:
        return
    
    await database.sessions.revoke_session(session, token)
    return


@router.get('/test_auth')
async def auth_test(user: UserAuthDep, api_key: KeyPermRead) -> UserInfo:
    return {'username': user.username, 'auth_type': user.auth_type}


@router.post('/api_keys')
async def create_api_key(
    data: APIKeyCreate, user: UserAuthDep, api_key: KeyPermCreate,
    logger: LoggerDep, session: SessionDep
) -> str:
    api_key: str = await database.api_keys.create_key(
        session, user.username, data.key_permissions,
        data.key_name, data.expiry_date
    )
    match api_key:
        case str() if api_key.startswith('syncserver-'):
            pass
        case DBReturnValues.API_KEY_EXISTS:
            raise HTTPException(status_code=409, detail="API key with the same name exists")
        case _:
            logger.error("Invalid data: %s", api_key)
            raise HTTPException(status_code=500, detail="Internal Server Error")

    return api_key


@router.delete('/api_keys/{key_name:path}')
async def delete_api_key(
    key_name: str, logger: LoggerDep, session: SessionDep,
    user: UserAuthDep, api_key: KeyPermDelete
) -> GenericSuccess:
    key_deleted: bool | str = await database.api_keys.delete_key(session, user.username, key_name)
    match key_deleted:
        case True:
            pass
        case DBReturnValues.INVALID_API_KEY:
            raise HTTPException(status_code=404, detail="API key does not exist")
        case _:
            logger.info("Invalid data:", key_deleted)
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    return {'success': True}


@router.get('/api_keys')
async def list_api_keys(
    user: UserAuthDep, api_key: KeyPermRead,
    logger: LoggerDep, session: SessionDep
) -> list[APIKeyInfo]:
    keys: list[APIKeyInfo] = await database.api_keys.list_keys(session, user.username)
    return keys


@router.get('/api_keys/{key_name:path}')
async def get_key_information(
    key_name: str,
    user: UserAuthDep, api_key: KeyPermRead,
    logger: LoggerDep, session: SessionDep
) -> APIKeyInfo:
    key_data: APIKeyInfo | None = await database.api_keys.get_key_info(session, user.username, key_name)

    if not key_data:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return key_data
