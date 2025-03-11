import logging

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI 

from .version import __version__
from .internal.database import database
from .internal.config import log_conf, settings
from .internal.ospaths import make_data_dirs
from .internal.cache import v
from .routers import main


@asynccontextmanager
async def app_lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        make_data_dirs()
    except OSError:
        print("Data directory cannot be accessed:", exc_info=True)
        raise

    await log_conf.setup_logging()
    logger: logging.Logger = logging.getLogger("syncserver")

    logger.critical(settings.DATA_DIRECTORY)
    try:
        await database.setup()
    except Exception:
        logger.critical("Database startup failed:", exc_info=True)
        raise

    try:
        await v.ping()
    except Exception:
        logger.critical("Could not ping Valkey server:", exc_info=True)
        raise

    logger.info("Application started, running version '%s'", __version__)
    yield

    try:
        await database.close()
    except Exception:
        logger.critical("Could not close database:", exc_info=True)
        raise

    try:
        await v.aclose()
    except Exception:
        logger.critical("Could not close Valkey client connection:", exc_info=True)
        raise

    logger.info("Application stopped")


app = FastAPI(
    title='NewGuy103 - syncServer',
    version=__version__,
    lifespan=app_lifespan, 
    debug=True
)
app.include_router(main.router)
