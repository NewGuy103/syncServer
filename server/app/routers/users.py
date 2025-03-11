from typing import Annotated
from fastapi import APIRouter, HTTPException, Path

from ..deps import IsAdminDep, LoggerDep, UserAuthDep, SessionDep
from ..internal.constants import DBReturnValues
from ..internal.database import database
from ..models.users import UserPublicGet, UserCreate


router = APIRouter(prefix='/users', tags=['User Management'], dependencies=[IsAdminDep])


@router.get('/')
async def get_users(user: UserAuthDep, session: SessionDep) -> list[UserPublicGet]:
    users = await database.users.retrieve_all_users(session)
    return users


@router.post('/')
async def create_user(
    data: UserCreate, user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep
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
    
    user_public: UserPublicGet = await database.users.retrieve_user(data.username)
    return user_public


@router.delete('/{username}')
async def delete_user(
    username: Annotated[str, Path(max_length=30)], user: UserAuthDep, 
    session: SessionDep, logger: LoggerDep
) -> dict:
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
