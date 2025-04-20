from enum import StrEnum, auto
from pydantic import BaseModel

# Authentication Models
class AccessTokenErrorCodes(StrEnum):
    invalid_request = auto()
    invalid_client = auto()
    invalid_grant = auto()
    invalid_scope = auto()

    unauthorized_client = auto()
    unsupported_grant_type = auto()


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class AccessTokenError(BaseModel):
    error: AccessTokenErrorCodes
    error_description: str

