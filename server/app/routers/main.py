from fastapi import APIRouter
from . import auth, files, folders, users

router = APIRouter(prefix='/api')
router.include_router(auth.router)

router.include_router(folders.router)
files.main_router.include_router(files.file_router)

router.include_router(files.main_router)
router.include_router(users.router)
