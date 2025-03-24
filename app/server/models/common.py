from typing import Literal
from pydantic import BaseModel


class UserInfo(BaseModel):
    username: str
    auth_type: str


class GenericSuccess(BaseModel):
    success: Literal[True]
