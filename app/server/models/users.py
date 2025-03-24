import uuid
from pydantic import BaseModel, Field


class UserBase(BaseModel):
    username: str


class UserCreate(UserBase):
    username: str = Field(max_length=30, min_length=1)
    password: str = Field(min_length=1, max_length=100)


class UserPublicGet(UserBase):
    user_id: uuid.UUID
