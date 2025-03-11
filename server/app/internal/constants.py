from enum import StrEnum


class DBReturnValues(StrEnum):
    USER_EXISTS = 'USER_EXISTS'
    NO_USER = 'NO_USER'
    INVALID_SESSION = 'INVALID_SESSION'
    API_KEY_EXISTS = 'API_KEY_EXISTS'
    INVALID_API_KEY = 'INVALID_API_KEY'


class FileReturnValues(StrEnum):
    FILE_EXISTS = 'FILE_EXISTS'
    NO_FILE_EXISTS = 'NO_FILE_EXISTS'
    UNEXPECTED_PARTIAL_WRITE = 'UNEXPECTED_PARTIAL_WRITE'
    FILE_LOCKED = 'FILE_LOCKED'
