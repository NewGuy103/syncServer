from fastapi import APIRouter
from . import auth, files, folders, users, deletedfiles

router = APIRouter(prefix='/api')
file_router = APIRouter(prefix='/files', tags=['File Management'])

router.include_router(auth.router)
router.include_router(folders.router)

file_router.include_router(files.router)
file_router.include_router(deletedfiles.router)

router.include_router(file_router)
router.include_router(users.router)
