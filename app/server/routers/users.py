from typing import Annotated
from fastapi import APIRouter, HTTPException, Path


from ..deps import (
    UserAuthDep, LoggerDep, SessionDep, KeyPermCreate,
    KeyPermRead, KeyPermDelete, IsAdminDep
)
from ..internal.constants import DBReturnValues
from ..internal.database import database
from ..models.common import GenericSuccess, HTTPStatusError
from ..models.users import UserPublicGet, UserCreate


router = APIRouter(
    prefix='/users', 
    tags=['User Management'], 
    dependencies=[IsAdminDep],
    responses={
        403: {
            'model': HTTPStatusError,
            'description': 'Raised if the current user is not the first user provided.'
        }
    }
)


@router.get('/', response_model=list[UserPublicGet])
async def get_users(user: UserAuthDep, session: SessionDep, api_key: KeyPermRead) -> list[UserPublicGet]:
    """Returns all available users."""
    users = await database.users.retrieve_all_users(session)
    return users


@router.post(
    '/', 
    responses={
        409: {
            'model': HTTPStatusError,
            'description': 'User provided already exists.'
        }
    },
    response_model=UserPublicGet
)
async def create_user(
    data: UserCreate, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep,
    api_key: KeyPermCreate
) -> UserPublicGet:
    user_created: bool | str = await database.users.add_user(
        session, data.username, data.password
    )
    match user_created:
        case True:
            pass
        case DBReturnValues.USER_EXISTS:
            raise HTTPException(status_code=409, detail="User already exists")
        case _:
            logger.error("Invalid data:", user_created)
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    user_public: UserPublicGet = await database.users.retrieve_user(session, data.username)
    return user_public


@router.delete(
    '/{username}',
    responses={
        400: {
            'model': HTTPStatusError,
            'description': "Raised when attempting to delete own user."
        },
        404: {
            'model': HTTPStatusError,
            'description': "User provided does not exist."
        }
    },
    response_model=GenericSuccess
)
async def delete_user(
    username: Annotated[str, Path(max_length=30)], 
    user: UserAuthDep, api_key: KeyPermDelete,
    session: SessionDep, logger: LoggerDep
) -> GenericSuccess:
    if username == user.username:
        raise HTTPException(status_code=400, detail="Cannot delete own user")
    
    user_deleted: bool | str = await database.users.delete_user(session, username)
    match user_deleted:
        case True:
            pass
        case DBReturnValues.NO_USER:
            raise HTTPException(status_code=404, detail="User does not exist")
        case _:
            logger.error("Invalid data:", user_deleted)
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    return {'success': True}
