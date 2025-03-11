import asyncio
import secrets
import typing

import logging
import uuid
import aiofiles
import aiofiles.os

from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import SQLModel, null, select
from sqlalchemy.pool import AsyncAdaptedQueuePool
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine

from cryptography.hazmat.primitives import hashes

from .config import settings, data_directories
from .constants import DBReturnValues, FileReturnValues
from .cache import v

from ..models.common import UserInfo
from ..models.auth import APIKeyInfo
from ..models.users import UserPublicGet
from ..models.folders import FolderContents
from ..models.pwdcontext import pwd_context
from ..models.dbtables import DeletedFiles, Files, Folders, UserAPIKeys, UserSessions, Users


if typing.TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine
    from fastapi import UploadFile


logger: logging.Logger = logging.getLogger("syncserver")
async_engine: 'AsyncEngine' = create_async_engine(
    str(settings.SQLALCHEMY_DATABASE_URI),
    poolclass=AsyncAdaptedQueuePool,
    echo=False
)


DEFAULT_CHUNK_SIZE: int = 10 * 1024 * 1024  # 10 MB


class MainDatabase:
    def __init__(self, async_engine: 'AsyncEngine'):
        self.async_engine: 'AsyncEngine' = async_engine
    
    def override_engine(self, async_engine: 'AsyncEngine'):
        self.async_engine: 'AsyncEngine' = async_engine
    
    async def setup(self):
        async with self.async_engine.begin() as conn:
            # await conn.run_sync(SQLModel.metadata.drop_all)
            await conn.run_sync(SQLModel.metadata.create_all)
    
        self.users = UserMethods(self)
        
        self.sessions = SessionMethods(self)
        self.files = FileMethods(self)

        self.folders = FolderMethods(self)
        self.api_keys = APIKeyMethods(self)
        
        async with AsyncSession(self.async_engine) as session:
            if not await self.get_user(session, settings.FIRST_USER_NAME):
                await self.users.add_user(session, settings.FIRST_USER_NAME, settings.FIRST_USER_PASSWORD)

            result = await session.exec(select(Users))
            all_users = result.all()

            for user in all_users:
                datadir_path: Path = data_directories.user_data / user.username
                datadir_path.mkdir(mode=0o755, exist_ok=True)

    async def get_user(self, session: AsyncSession, username: str) -> Users | None:
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        statement = select(Users).where(Users.username == username)
        result = await session.exec(statement)
        user: Users | None = result.one_or_none()

        if not user:
            return None

        return user
    
    async def close(self):
        await self.async_engine.dispose()


class UserMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine
    
    async def add_user(self, session: AsyncSession, username: str, password: str):
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        if not isinstance(password, str):
            raise TypeError("password is not a string")
        
        stored_user: Users | None = await self.parent.get_user(session, username)
        if stored_user:
            return DBReturnValues.USER_EXISTS

        hashed_pw: str = await asyncio.to_thread(pwd_context.hash, password)
        user = Users(username=username, hashed_password=hashed_pw)

        session.add(user)
        await session.commit()

        folder_path: Path = (data_directories.user_data / username).resolve()
        await self.parent.folders.create_folder(session, username, folder_path, root=True)

        return True
    
    async def verify_user(self, session: AsyncSession, username: str, password: str) -> str | bool:
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        if not isinstance(password, str):
            raise TypeError("password is not a string")
        
        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            return DBReturnValues.NO_USER

        hash_valid, new_hash = await asyncio.to_thread(
            pwd_context.verify_and_update,
            password, user.hashed_password
        )

        if not hash_valid:
            return False
        
        if new_hash:
            user.hashed_password = new_hash

        session.add(user)
        await session.commit()

        return True
    
    async def delete_user(self, session: AsyncSession, username: str):
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        existing_user: Users | None = await self.parent.get_user(session, username)
        if not existing_user:
            return DBReturnValues.NO_USER
        
        result = await session.exec(select(Users).where(Users.user_id == existing_user.user_id))
        user: Users = result.one()

        await session.delete(user)
        await session.commit()
        
        return True

    async def retrieve_user(self, session: AsyncSession, username: str) -> UserPublicGet:
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            return DBReturnValues.NO_USER
    
        user_public = UserPublicGet.model_validate(user, from_attributes=True)
    
        return user_public
    
    async def retrieve_all_users(self, session: AsyncSession) -> list[UserPublicGet]:
        result = await session.exec(select(Users))
        users = result.all()
    
        userlist: list = []
        for user in users:
            user_public = UserPublicGet.model_validate(user, from_attributes=True)
            userlist.append(user_public)
        
        return userlist


class SessionMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine

    async def create_session_token(self, session: AsyncSession, username: str, expiry_date: datetime) -> str:
        if not isinstance(username, str):
            raise TypeError("username is not a string")

        date_today: datetime = datetime.now(timezone.utc)
        if date_today > expiry_date:
            raise ValueError("datetime provided has already expired")

        session_token: str = secrets.token_urlsafe(32)
        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")

        new_session: UserSessions = UserSessions(
            session_token=session_token,
            user_id=user.user_id,
            expiry_date=expiry_date
        )
        session.add(new_session)
        await session.commit()

        return session_token
    
    async def get_token_info(self, session: AsyncSession, token: str) -> UserInfo | str:
        if not isinstance(token, str):
            raise TypeError("token is not a string")
        
        result = await session.exec(
            select(UserSessions).where(UserSessions.session_token == token)
        )
        user_session: UserSessions | None = result.one_or_none()

        if not user_session:
            return DBReturnValues.INVALID_SESSION

        userinfo = UserInfo(
            username=user_session.user.username,
            auth_type='token'
        )

        return userinfo

    async def check_session_validity(self, session: AsyncSession, token: str) -> bool:
        if not isinstance(token, str):
            raise TypeError("token is not a string")

        statement = select(UserSessions).where(UserSessions.session_token == token)
        result = await session.exec(statement)

        user_session: UserSessions | None = result.one_or_none()
        if not user_session:
            return False

        expiry_date: datetime = user_session.expiry_date
        current_date: datetime = datetime.now(timezone.utc)

        is_not_expired: bool = expiry_date > current_date
        return is_not_expired
    
    async def revoke_session(self, session: AsyncSession, token: str):
        if not isinstance(token, str):
            raise TypeError("token is not a string")

        statement = select(UserSessions).where(UserSessions.session_token == token)
        result = await session.exec(statement)
        user_session: UserSessions | None = result.one_or_none()

        if not user_session:
            raise ValueError(f'invalid session token: {token}')
        
        await session.delete(user_session)
        await session.commit()
        
        return True


class FileMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine

        self.deleted_files = DeletedFileMethods(parent)

    async def save_file(
        self, session: AsyncSession, username: str, 
        file_path: Path, 
        file_stream: 'UploadFile',
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> bool | str:
        if file_path.exists():
            raise ValueError(f"file at path '{file_path}' exists")

        random_hex = secrets.token_hex(16)
        tmp_filename = f"create-{username}-{random_hex}.part"

        temp_path: Path = (data_directories.temp_files / tmp_filename).resolve()
        lock = v.lock(str(file_path), blocking=True)

        try:
            async with aiofiles.open(temp_path, 'xb') as os_file:
                chunk: bytes = await file_stream.read(chunk_size)
                await os_file.write(chunk)

                chunk: bytes = await file_stream.read(chunk_size)
                while chunk:
                    await os_file.write(chunk)
                    chunk: bytes = await file_stream.read(chunk_size)
                    await os_file.flush()
            
                logger.debug("Finished writing temp path %s to disk", temp_path)
        except Exception:
            temp_path.unlink()

            logger.exception(
                "Writing file '%s' from user '%s' to disk failed:",
                file_path, username
            )
            raise  # logging...

        written_size: int = await aiofiles.os.path.getsize(temp_path)
        logger.debug("Wrote %d bytes to file %s", written_size, temp_path)

        if written_size != file_stream.size:
            logger.warning("Expected to write %d bytes, only wrote %d bytes")
            temp_path.unlink()

            raise ValueError("Unexpected incomplete write")

        async with lock:
            user: Users | None = await self.parent.get_user(session, username)
            if not user:
                raise ValueError(f"username {username} is invalid")
            
            folder: Folders = await self.parent.folders.get_folder(session, username, file_path.parent)
            if not folder:
                raise ValueError(f"folder {file_path.parent} does not exist")
            
            file_instance: Files = Files(
                user_id=user.user_id, 
                file_path=str(file_path),
                folder_id=folder.folder_id
            )
            result = await session.exec(
                select(Files).where(
                    Files.file_path == str(file_path),
                    Files.user_id == user.user_id,
                    Files.delete_entry == null()
                )
            )
            saved_file: Files | None = result.one_or_none()

            if saved_file:
                raise ValueError("file exists in database")
            
            session.add(file_instance)
            await session.commit()

        logger.debug("Committed file path %s to database", file_path)
        temp_path.rename(file_path)

        logger.debug("Renamed tempfile '%s' to '%s'", temp_path, file_path)

        return True
    
    async def update_file(
        self, session: AsyncSession, username: str, 
        file_path: Path, 
        file_stream: 'UploadFile',
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ):
        if not file_path.exists() or file_path.is_dir():
            raise ValueError(f"no file at path '{file_path}' exists")

        random_hex = secrets.token_hex(16)
        tmp_filename = f"update-{username}-{random_hex}.part"

        temp_path: Path = (data_directories.temp_files / tmp_filename).resolve()
        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"username '{username}' is invalid")
        
        folder: Folders = await self.parent.folders.get_folder(session, username, file_path.parent)
        if not folder:
            raise ValueError(f"folder {file_path.parent} does not exist")
        
        result = await session.exec(
            select(Files).where(
                Files.file_path == str(file_path),
                Files.user_id == user.user_id,
                Files.delete_entry == null()
            )
        )

        # Double check if file exists without a database entry
        result.one()

        lock = v.lock(str(file_path), blocking=True)
        try:
            async with aiofiles.open(temp_path, 'xb') as os_file:
                chunk: bytes = await file_stream.read(chunk_size)
                await os_file.write(chunk)

                chunk: bytes = await file_stream.read(chunk_size)
                while chunk:
                    await os_file.write(chunk)
                    chunk: bytes = await file_stream.read(chunk_size)
                    await os_file.flush()
            
            logger.debug("Finished writing temp path %s to disk", temp_path)
        except Exception:
            temp_path.unlink()
            
            logger.exception(
                "Writing file '%s' from user '%s' to disk failed:",
                file_path, username
            )
            raise  # logging...

        async with lock:
            temp_path.rename(file_path)
        
        return True
    
    async def delete_file(self, session: AsyncSession, username: str, file_path: Path):
        if not file_path.exists() or file_path.is_dir():
            raise ValueError(f"no file at path '{file_path}' exists")

        lock = v.lock(str(file_path), blocking=True)
        delete_id: uuid.UUID = uuid.uuid4()

        tmp_filename = f"{delete_id}"
        deleted_path: Path = (data_directories.trash_bin / tmp_filename).resolve()

        try:
            async with lock:
                user: Users = await self.parent.get_user(session, username)
                if not user:
                    raise ValueError(f"username {username} is invalid")
                
                folder: Folders = await self.parent.folders.get_folder(session, username, file_path.parent)
                if not folder:
                    raise ValueError(f"folder {file_path.parent} does not exist")
            
                result = await session.exec(
                    select(Files).where(
                        Files.file_path == str(file_path),
                        Files.user_id == user.user_id,
                        Files.delete_entry == null()
                    )
                )
                file_model: Files = result.one()

                marked_deleted_model: DeletedFiles = DeletedFiles(
                    delete_id=delete_id,
                    file_id=file_model.file_id,
                )
                session.add(marked_deleted_model)
                await session.commit()
            
            file_path.rename(deleted_path)
        except Exception:
            logger.exception(
                "Deleting file '%s' from user '%s' failed:",
                file_path, username
            )
            raise

        return True
        
    async def check_file_exists(self, session: AsyncSession, username: str, file_path: Path) -> bool:
        if not file_path.exists() or file_path.is_dir():
            return False

        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"username {username} is invalid")
        
        folder: Folders = await self.parent.folders.get_folder(session, username, file_path.parent)
        if not folder:
            raise ValueError(f"folder {file_path.parent} does not exist")
        
        result = await session.exec(
            select(Files).where(
                Files.file_path == str(file_path),
                Files.user_id == user.user_id,
                Files.delete_entry == null()
            )
        )

        saved_file: Files | None = result.one_or_none()
        return bool(saved_file)
  
    async def rename_file(self, session: AsyncSession, username: str, file_path: Path, new_path: Path):
        if not file_path.exists() or file_path.is_dir():
            raise ValueError(f"no file at path '{file_path}' exists")
        
        if new_path.exists() or new_path.is_dir():
            raise ValueError(f"existing file at path '{new_path}' exists")

        lock_old = v.lock(str(file_path), blocking=True)
        lock_new = v.lock(str(new_path), blocking=True)

        try:
            async with lock_old, lock_new:
                user: Users = await self.parent.get_user(session, username)
                if not user:
                    raise ValueError(f"username {username} is invalid")
                
                old_folder: Folders = await self.parent.folders.get_folder(session, username, file_path.parent)
                if not old_folder:
                    raise ValueError(f"folder {file_path.parent} does not exist")
                
                new_folder: Folders = await self.parent.folders.get_folder(session, username, new_path.parent)
                if not new_folder:
                    raise ValueError(f"folder {new_path.parent} does not exist")
                
                result = await session.exec(
                    select(Files).where(
                        Files.file_path == str(file_path),
                        Files.user_id == user.user_id,
                        Files.delete_entry == null()
                    )
                )
                saved_file: Files = result.one()

                saved_file.file_path = str(new_path)
                session.add(saved_file)

                await session.commit()
                file_path.rename(new_path)
        except Exception:
            logger.exception(
                "Writing file '%s' from user '%s' to disk failed:",
                str(file_path), username
            )
            raise  # logging...

        return True

    async def read_file(self, session: AsyncSession, username: str, file_path: Path, chunk_size: int = 1):
        if not file_path.exists() or file_path.is_dir():
            raise ValueError(f"no file at path '{file_path}' exists")

        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"username {username} is invalid")
        
        result = await session.exec(
            select(Files).where(
                Files.file_path == str(file_path),
                Files.user_id == user.user_id,
                Files.delete_entry == null()
            )
        )
        result.one()
        return True


class DeletedFileMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine

    async def check_file_deleted(self, session: AsyncSession, username: str, file_path: Path):
        if not file_path.exists() or file_path.is_dir():
            raise ValueError(f"no file at path '{file_path}' exists")

        user: Users | None = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"username {username} is invalid")
        
        result = await session.exec(
            select(Files).where(
                Files.file_path == str(file_path),
                Files.user_id == user.user_id
            )
        )
        file_models = result.all()
        if not file_models:
            return FileReturnValues.NO_FILE_EXISTS
        
        for model in file_models:
            if model.delete_entry:
                continue

            return False
            
        return True
            

class APIKeyMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine

        self.allowed_permissions: list[str] = ['create', 'read', 'update', 'delete']

    def hash_key(self, api_key: str) -> str:
        match api_key:
            case bytes():
                pass
            case str():
                api_key: bytes = api_key.encode('utf-8')
            case _:
                raise TypeError("data is not bytes or string")
        
        digest: hashes.Hash = hashes.Hash(hashes.SHA3_512())
        digest.update(api_key)

        hashed_data: bytes = digest.finalize()
        return hashed_data.hex()
    
    async def create_key(
        self, session: AsyncSession, username: str,
        key_perms: set[str],
        key_name: str,
        expiry_date: datetime
    ) -> str:
        if not isinstance(username, str):
            raise TypeError("'username' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")

        for perms in key_perms:
            if perms not in self.allowed_permissions:
                raise ValueError("invalid key permissions")
        
        date_today: datetime = datetime.now(timezone.utc)
        if date_today > expiry_date:
            raise ValueError("datetime provided has already expired")

        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")

        token: str = secrets.token_hex(32)
        api_key: str = f"syncserver-{token}"

        hashed_key: str = await asyncio.to_thread(self.hash_key, api_key)
        result = await session.exec(select(UserAPIKeys).where(UserAPIKeys.key_name == key_name))
        if result.one_or_none():
            return DBReturnValues.API_KEY_EXISTS

        key_instance: UserAPIKeys = UserAPIKeys(
            user_id=user.user_id, key_permissions=list(key_perms),
            expiry_date=expiry_date, key_data=hashed_key,
            key_name=key_name
        )
        session.add(key_instance)
        await session.commit()
        
        return api_key
    
    async def verify_key(self, session: AsyncSession, api_key: str, permission: str = '') -> bool:
        if permission not in self.allowed_permissions and permission:
            raise ValueError("permission provided is invalid")  # fail quick, pydantic should validate it
        
        hashed_key: str = await asyncio.to_thread(self.hash_key, api_key)
        result = await session.exec(select(UserAPIKeys).where(UserAPIKeys.key_data == hashed_key))

        key_data: UserAPIKeys | None = result.one_or_none()
        if not key_data:
            return False
        
        if permission not in key_data.key_permissions and permission:
            return False

        return True

    async def delete_key(self, session: AsyncSession, username: str, key_name: str) -> str:
        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        result = await session.exec(
            select(UserAPIKeys).where(
                UserAPIKeys.key_name == key_name,
                UserAPIKeys.user_id == user.user_id
            )
        )
        key_data: UserAPIKeys | None = result.one_or_none()

        if not key_data:
            return DBReturnValues.INVALID_API_KEY
        
        await session.delete(key_data)
        await session.commit()
        
        return True

    async def list_keys(self, session: AsyncSession, username: str) -> list[APIKeyInfo]:
        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        result = await session.exec(select(UserAPIKeys).where(UserAPIKeys.user_id == user.user_id))
        key_data = result.all()

        if not key_data:
            return []
    
        key_list: list = []
        for key in key_data:
            key_info: APIKeyInfo = APIKeyInfo(
                key_name=key.key_name, expiry_date=key.expiry_date,
                key_permissions=key.key_permissions
            )
            key_list.append(key_info)
            
        return key_list

    async def get_user_info(self, session: AsyncSession, api_key: str):
        hashed_key: str = await asyncio.to_thread(self.hash_key, api_key)
        result = await session.exec(select(UserAPIKeys).where(UserAPIKeys.key_data == hashed_key))
        key_data: UserAPIKeys = result.one()

        return UserInfo(username=key_data.user.username, auth_type='api_key')


class FolderMethods:
    def __init__(self, parent: MainDatabase):
        self.parent = parent
        self.async_engine = parent.async_engine

    async def get_folder(self, session: AsyncSession, username: str, folder_path: Path):
        user: Users = await self.parent.get_user(session, username)    
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        result = await session.exec(select(Folders).where(
            Folders.folder_path == str(folder_path),
            Folders.user_id == user.user_id
        ))

        folder: Folders | None = result.one_or_none()
        return folder

    async def create_folder(self, session: AsyncSession, username: str, folder_path: Path, root: bool = False):
        if folder_path.exists() and not root:
            raise ValueError(f"folder at path '{folder_path}' exists")

        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        parent: Folders = await self.get_folder(session, username, folder_path.parent)
        if not parent and not root:
            raise ValueError(f"parent folder '{folder_path.parent} does not exist in database")
        
        result = await session.exec(select(Folders).where(
            Folders.user_id == user.user_id,
            Folders.folder_path == str(folder_path)
        ))
        folder = result.one_or_none()
        if folder:
            raise ValueError("folder path exists")
        
        if root:
            folder_instance = Folders(
                folder_path=str(folder_path),
                user_id=user.user_id,
                parent_id=None
            )
        else:
            folder_instance = Folders(
                folder_path=str(folder_path),
                user_id=user.user_id,
                parent_id=parent.folder_id
            )

        session.add(folder_instance)
        await session.commit()

        if not root:
            folder_path.mkdir(mode=0o755, parents=False, exist_ok=False)
    
        return True
    
    async def check_folder_exists(self, session: AsyncSession, username: str, folder_path: Path):
        if not folder_path.exists():
            return False
        
        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        result = await session.exec(select(Folders).where(
            Folders.user_id == user.user_id,
            Folders.folder_path == str(folder_path)
        ))
        folder = result.one_or_none()

        return bool(folder)
    
    async def list_folder_data(self, session: AsyncSession, username: str, folder_path: Path, root: bool = False):
        if not folder_path.exists():
            raise ValueError(f"no folder at path '{folder_path}' exists")

        user: Users = await self.parent.get_user(session, username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        result = await session.exec(select(Folders).where(
            Folders.user_id == user.user_id,
            Folders.folder_path == str(folder_path)
        ))
        folder = result.one()

        files: list[str] = []
        folders: list[str] = []
        
        for file in folder.files:
            pathlike = Path(file.file_path)
            files.append(pathlike.name)
        
        for child_folder in folder.child_folders:
            pathlike = Path(child_folder.folder_path)
            folders.append(pathlike.name)
        
        folder_contents = FolderContents(
            folder_path=folder_path.name,
            files=files,
            folders=folders
        )
        return folder_contents


database: MainDatabase = MainDatabase(async_engine)
