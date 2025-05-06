import warnings
import logging.config
import json

import aiofiles

from typing import Literal, Self
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field, computed_field, PostgresDsn, DirectoryPath, model_validator
from pydantic_core import MultiHostUrl


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env', 
        env_file_encoding='utf-8'
    )

    DATA_DIRECTORY: DirectoryPath = Field(
        default=Path('.', 'syncserver').resolve(),
        validate_default=True
    )
    ENVIRONMENT: Literal['local', 'dev', 'prod'] = 'local'

    POSTGRES_HOST: str = "127.0.0.1"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "syncserver"
    POSTGRES_DB: str = "syncserver"
    POSTGRES_PASSWORD: str = "helloworld"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn:
        return MultiHostUrl.build(
            scheme="postgresql+asyncpg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )
    
    FIRST_USER_NAME: str = 'admin'
    FIRST_USER_PASSWORD: str = 'helloworld'

    USE_VALKEY_CACHE: bool = True
    VALKEY_URI: MultiHostUrl = MultiHostUrl.build(
        scheme="valkey",
        username='',
        password='',
        host='127.0.0.1',
        port=6379,
        path='0',
    )

    def _check_value_default(self, key_name: str, value: str):
        if value == 'helloworld':
            msg = (f"The value of '{key_name}' is the default 'helloworld', "
                    "changing it to a different value is recommended.")

            if self.ENVIRONMENT == 'local':
                warnings.warn(msg, stacklevel=1)
            else:
                raise ValueError(msg)

    @model_validator(mode="after")
    def _check_values_okay(self) -> Self:
        self._check_value_default('POSTGRES_PASSWORD', self.POSTGRES_PASSWORD)
        self._check_value_default('FIRST_USER_PASSWORD', self.FIRST_USER_PASSWORD)

        if not self.USE_VALKEY_CACHE:
            msg = ("Disabling Valkey cache is not recommended for running in production")
            if self.ENVIRONMENT == 'local':
                warnings.warn(msg, stacklevel=1)
            else:
                raise ValueError(msg)
        
        return self


class DataDirectories(BaseModel):
    user_data: Path
    temp_files: Path
    config_dir: Path
    trash_bin: Path


class LogConfigManager:
    def __init__(self):
        self.log_config: Path = (data_directories.config_dir / 'log.json').resolve()
        self.log_file: Path = (data_directories.config_dir / 'app.log').resolve()
    
    def make_logging_config(self):
        return {
            'version': 1,
            'formatters': {
                'default': {
                    'format': '[%(name)s]: [%(module)s | %(funcName)s] - [%(asctime)s] - [%(levelname)s] - %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'precise': {
                    'format': (
                        '[process %(process)d] - [%(name)s]: [%(module)s | %(funcName)s] - [%(levelname)s] '
                        '- "%(pathname)s:%(lineno)d" - [%(asctime)s]: %(message)s'
                    ),
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'stream': 'ext://sys.stdout',
                    'formatter': 'default'
                },
                "syncserver": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "formatter": "default",
                    "maxBytes": 5 * 1024 * 1024,  # 5 MB
                    "backupCount": 3,
                    "filename": str(self.log_file)
                }
            },
            'loggers': {
                "syncserver": {
                    "handlers": [
                        "syncserver",
                        "console"
                    ],
                    "level": "INFO",
                    "propagate": True
                }
            },
            'disable_existing_loggers': False
        }

    async def setup_logging(self) -> None:
        if not self.log_config.exists():
            log_config = self.make_logging_config()
            async with aiofiles.open(self.log_config, 'w') as file:
                await file.write(json.dumps(log_config, indent=4))
        else:
            async with aiofiles.open(self.log_config, 'r') as file:
                log_config = json.loads(await file.read())

        logging.config.dictConfig(log_config)


settings = AppSettings()
data_directories = DataDirectories(
    user_data=(settings.DATA_DIRECTORY / 'userfiles').resolve(),
    trash_bin=(settings.DATA_DIRECTORY / 'trashbin').resolve(),
    temp_files=(settings.DATA_DIRECTORY / 'temp').resolve(),
    config_dir=(settings.DATA_DIRECTORY / 'config').resolve(),
)

log_conf = LogConfigManager()
