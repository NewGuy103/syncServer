from typing import Optional
import uuid
import secrets

from datetime import datetime, timedelta, timezone
from sqlmodel import JSON, Column, SQLModel, Field, DateTime, Relationship, TypeDecorator
from .auth import ValidPermissions


class TZDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if not value.tzinfo or value.tzinfo.utcoffset(value) is None:
                raise TypeError("tzinfo is required")
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class UserBase(SQLModel):
    user_id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(max_length=30, nullable=False, unique=True, index=True, min_length=1)
    hashed_password: str = Field(max_length=100, nullable=False)


class Users(UserBase, table=True):
    sessions: list['UserSessions'] = Relationship(
        back_populates='user', 
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )
    api_keys: list['UserAPIKeys'] = Relationship(
        back_populates='user', 
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )

    files: list['Files'] = Relationship(
        back_populates='user', 
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )
    folders: list['Folders'] = Relationship(
        back_populates='user', 
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )


class UserSessions(SQLModel, table=True):
    session_token: str = Field(
        primary_key=True, max_length=45, 
        default_factory=lambda: secrets.token_urlsafe(32)
    )
    expiry_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(15),
        sa_column=Column(TZDateTime, index=True)
    )

    user_id: uuid.UUID = Field(foreign_key='users.user_id', ondelete='CASCADE')
    user: Users = Relationship(
        back_populates='sessions', 
        sa_relationship_kwargs={'lazy': 'selectin'}
    )


class UserAPIKeys(SQLModel, table=True):
    key_id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    key_permissions: list[ValidPermissions] = Field(default_factory=list, sa_column=Column(JSON))
    expiry_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(30),
        sa_column=Column(TZDateTime, index=True)
    )
    key_data: str = Field(nullable=False, index=True, min_length=1)
    key_name: str = Field(nullable=False, min_length=1)

    user_id: uuid.UUID = Field(foreign_key='users.user_id', ondelete='CASCADE')
    user: Users = Relationship(
        back_populates='api_keys', 
        sa_relationship_kwargs={'lazy': 'selectin'}
    )


# Self referential model (https://docs.sqlalchemy.org/en/latest/orm/self_referential.html)
class Folders(SQLModel, table=True):
    folder_id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    folder_path: str = Field(min_length=1, nullable=False, index=True)

    # Foreign keys    
    user_id: uuid.UUID = Field(foreign_key='users.user_id', ondelete='CASCADE')
    parent_id: uuid.UUID | None = Field(foreign_key='folders.folder_id', ondelete='CASCADE')

    # Relationships
    parent_folder: Optional['Folders'] = Relationship(
        back_populates='child_folders',
        sa_relationship_kwargs={'lazy': 'selectin', 'remote_side': 'Folders.folder_id'}
    )
    child_folders: list['Folders'] = Relationship(
        back_populates='parent_folder',
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )

    user: Users = Relationship(back_populates='folders', sa_relationship_kwargs={'lazy': 'selectin'})
    files: list['Files'] = Relationship(
        back_populates='folder', 
        sa_relationship_kwargs={'lazy': 'selectin'},
        cascade_delete=True
    )


class Files(SQLModel, table=True):
    file_id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_path: str = Field(min_length=2, nullable=False, index=True)

    folder_id: uuid.UUID = Field(foreign_key='folders.folder_id', ondelete='CASCADE')
    user_id: uuid.UUID = Field(foreign_key='users.user_id', ondelete='CASCADE')

    user: Users = Relationship(
        back_populates='files', 
        sa_relationship_kwargs={'lazy': 'selectin'}
    )
    folder: Folders = Relationship(
        back_populates='files', 
        sa_relationship_kwargs={'lazy': 'selectin'},
    )

    delete_entry: Optional['DeletedFiles'] = Relationship(
        back_populates='file', 
        sa_relationship_kwargs={'lazy': 'selectin', 'uselist': False}
    )


class DeletedFiles(SQLModel, table=True):
    delete_id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    deleted_on: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), index=True)
    )

    file_id: uuid.UUID = Field(foreign_key='files.file_id', ondelete='CASCADE')
    file: Files = Relationship(
        back_populates='delete_entry', 
        sa_relationship_kwargs={'lazy': 'selectin'}
    )
