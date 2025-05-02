from typing import Type
from pathlib import Path

from pydantic import HttpUrl
from pydantic_settings import (
    BaseSettings, PydanticBaseSettingsSource, 
    SettingsConfigDict, JsonConfigSettingsSource
)

from platformdirs import PlatformDirs
from ..version import __version__


dirs = PlatformDirs("syncserver-client", "newguy103", version=__version__)
config_file_src = Path(dirs.user_config_dir) / 'config.json'


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(json_file=config_file_src, validate_assignment=True)

    username: str = ''
    server_url: HttpUrl = HttpUrl(url='http://localhost:8000')

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
