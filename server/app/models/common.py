from pydantic import BaseModel

class UserInfo(BaseModel):
    username: str
    auth_type: str
