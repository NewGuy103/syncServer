from enum import StrEnum, auto
from typing import Annotated
from pydantic import BaseModel, AwareDatetime, FutureDatetime


class ValidPermissions(StrEnum):
    create = auto()
    read = auto()
    update = auto()
    delete = auto()


class AccessTokenErrorCodes(StrEnum):
    invalid_request = auto()
    invalid_client = auto()
    invalid_grant = auto()
    invalid_scope = auto()

    unauthorized_client = auto()
    unsupported_grant_type = auto()


class APIKeyBase(BaseModel):
    key_name: str
    expiry_date: AwareDatetime
    key_permissions: set[ValidPermissions]


class APIKeyCreate(APIKeyBase):
    expiry_date: Annotated[AwareDatetime, FutureDatetime]


class APIKeyInfo(APIKeyBase):
    pass


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class AccessTokenError(BaseModel):
    error: AccessTokenErrorCodes
    error_description: str
