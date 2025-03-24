from pydantic import BaseModel, AwareDatetime


class DeletedFilesGet(BaseModel):
    deleted_on: AwareDatetime

