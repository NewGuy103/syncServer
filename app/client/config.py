import logging

from typing import Type
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, HttpUrl
from pydantic_settings import (
    BaseSettings, PydanticBaseSettingsSource, 
    SettingsConfigDict, JsonConfigSettingsSource
)

from platformdirs import PlatformDirs
from ..version import __version__


dirs = PlatformDirs("syncserver-client", "newguy103", version=__version__)
config_file_src = Path(dirs.user_config_dir) / 'config.json'

logger: logging.Logger = logging.getLogger('syncserver-client')


def setup_logger(level: int):
    global logger
    logger.setLevel(level)

    formatter: logging.Formatter = logging.Formatter(
        '[%(name)s]: [%(module)s | %(funcName)s] - [%(asctime)s] - [%(levelname)s] - %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    stream_handler: logging.StreamHandler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    file_handler: logging.FileHandler = logging.FileHandler(Path(dirs.user_config_dir) / 'client.log')
    file_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)


class LogLevels(int, Enum):
    debug = logging.DEBUG
    info = logging.INFO
    warning = logging.WARNING
    error = logging.ERROR
    critical = logging.CRITICAL


class AvailableLogins(BaseModel):
    username: str = ''
    server_url: HttpUrl = HttpUrl(url='http://localhost:8000')
    is_default: bool = False


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(json_file=config_file_src, validate_assignment=True)

    logins: list[AvailableLogins] = []
    log_level: LogLevels = LogLevels.debug.value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (JsonConfigSettingsSource(settings_cls),)

    def save_settings(self):
        with open(config_file_src, 'w') as file:
            file.write(self.model_dump_json(indent=4))
