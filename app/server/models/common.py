from typing import Literal
from pydantic import BaseModel, ConfigDict


class UserInfo(BaseModel):
    username: str
    auth_type: str


class GenericSuccess(BaseModel):
    success: Literal[True]


class HTTPStatusError(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": "Short client error message here."
            }
        }
    )
    detail: str
