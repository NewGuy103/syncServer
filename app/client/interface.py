import os
import json
import logging
import httpx

from pathlib import PurePosixPath
from platformdirs import PlatformDirs
from pydantic import TypeAdapter, ValidationError

from .models import (
    APIKeyCreate, AccessTokenResponse, AccessTokenError, 
    APIKeyInfo, FolderContents, GenericSuccess, ConfigData
)
from ..version import __version__


dirs = PlatformDirs("syncserver-client", "newguy103", version=__version__)

# TODO: Implement a better/simpler log setup
logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter: logging.Formatter = logging.Formatter(
    '[%(name)s]: [%(module)s | %(funcName)s] - [%(asctime)s] - [%(levelname)s] - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

stream_handler: logging.StreamHandler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

logger.addHandler(stream_handler)


# TODO: temp fix for a simple config manager using pydantic
class ConfigManager:
    def __init__(self):
        self.default_data: ConfigData = ConfigData(
            server_url='http://localhost:8000',
            username='admin'
        )
        
        if not os.path.isdir(dirs.user_config_dir):
            os.makedirs(dirs.user_config_dir)

    def load_from_save(self):
        config_path = os.path.join(dirs.user_config_dir, 'config.json')
        if not os.path.isfile(config_path):
            with open(config_path, 'w') as file:
                file.write(self.default_data.model_dump_json(indent=4))
        
        with open(config_path, 'r') as file:
            stored_config = file.read()
        
        # throw an error on fail, pyside6 app should catch this in the WorkerThread
        self.config_data = ConfigData.model_validate_json(stored_config)    
        return
    
    def get_data(self):
        return self.config_data.model_copy(deep=True)
    
    def save_data(self, config_model: ConfigData):
        config_path = os.path.join(dirs.user_config_dir, 'config.json')
        with open(config_path, 'w') as file:
            file.write(config_model.model_dump_json(indent=4))
        

# TODO: Use async httpx when PySide6 supports the asyncio event loop features
# or learn trio to make this asyncio
class MainClient:
    def __init__(self, authorization: str, server_url: str):
        self.auth_header: str = authorization
        self.server_url: str = server_url

    @classmethod
    def fetch_authorization_header(
        cls, username: str, 
        password: str, server_url: str
    ) -> AccessTokenResponse | AccessTokenError:
        with httpx.Client(timeout=30, follow_redirects=False, base_url=server_url) as client:
            # OAuth2 Specification (https://www.oauth.com/oauth2-servers/access-tokens/password-grant/)
            data = {
                'grant_type': 'password',
                'username': username,
                'password': password
            }

            # Controller should handle it with an error Signal
            try:
                res = client.post(
                    '/api/auth/token',
                    headers={
                        'accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    data=data
                )
                res_data: dict = res.json()

                if res.is_server_error:
                    res.raise_for_status()
            except httpx.HTTPStatusError:
                logger.exception("Internal server error:")
                raise
            except httpx.HTTPError:
                logger.exception("HTTP error:")
                raise
            except json.JSONDecodeError:
                logger.exception(
                    "Data received from server is invalid JSON, response body: %s",
                    res.text
                )
                raise
            except Exception:
                logger.critical(
                    "Unexpected Exception while fetching authorization header, "
                    "response body: %s", res.text,
                    exc_info=True
                )
                raise

        if res.is_client_error:    
            err_model = AccessTokenError(**res_data)
            return err_model
        
        res_model = AccessTokenResponse(**res_data)
        return res_model
    
    def setup(self) -> bool:
        self.client: httpx.Client = httpx.Client(
            headers={
                'accept': 'application/json',
                'Authorization': f'Bearer {self.auth_header}'
            },
            timeout=30,
            follow_redirects=False,
            base_url=self.server_url
        )

        try:
            auth_resp = self.client.get('/api/auth/test_auth')
            auth_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except Exception:
            logger.critical("Unexpected error:", exc_info=True)
            raise

        self.files = FilesInterface(self)
        self.folders = FolderInterface(self)

        self.api_keys = APIKeyInterface(self)
        return True

    def close(self):
        self.client.close()


class FilesInterface:
    def __init__(self, parent: MainClient):
        self.parent = parent
        self.client = parent.client

    def upload_file(self, folder: str, filename: str, file_path: str) -> GenericSuccess:
        if folder == '/':
            url: str = f'/api/files/file/{filename}'
        else:
            url: str = f'/api/files/file/{folder}/{filename}'
        
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (filename, file)}
                res = self.client.post(url, files=files)
                
                res.raise_for_status()
                res_json: dict = res.json()
                    
                res_model = GenericSuccess(**res_json)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:\n%s", exc.response.status_code, exc.response.text)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_model
    
    def update_file(self, folder: str, filename: str, file_path: str) -> GenericSuccess:
        if folder == '/':
            url: str = f'/api/files/file/{filename}'
        else:
            url: str = f'/api/files/file/{folder}/{filename}'
        
        try:
            with open(file_path, 'rb') as file:
                files = {'file': (filename, file)}
                res = self.client.put(url, files=files)
                
                res.raise_for_status()
                res_json: dict = res.json()
                    
                res_model = GenericSuccess(**res_json)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:\n%s", exc.response.status_code, exc.response.text)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_model
    
    def delete_file(self, folder: str, filename: str) -> GenericSuccess:
        if folder == '/':
            url: str = f'/api/files/file/{filename}'
        else:
            url: str = f'/api/files/file/{folder}/{filename}'
        
        try:
            res = self.client.delete(url)
            
            res.raise_for_status()
            res_json: dict = res.json()
                
            res_model = GenericSuccess(**res_json)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_model
    
    def rename_file(self, folder: str, old_name: str, new_name: str):
        if folder == '/':
            url: str = f'/api/files/file/{old_name}'
        else:
            url: str = f'/api/files/file/{folder}/{old_name}'
        
        try:
            data = {'new_name': new_name}
            res = self.client.patch(url, json=data)
            
            res.raise_for_status()
            res_json: dict = res.json()
                
            res_model = GenericSuccess(**res_json)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_model


class FolderInterface:
    def __init__(self, parent: MainClient):
        self.parent = parent
        self.client = parent.client
    
    def list_root_folder(self) -> FolderContents:
        try:
            res = self.client.get('/api/folders/')
            res.raise_for_status()

            res_json: dict = res.json()
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise
        
        model = FolderContents(**res_json)
        return model
    
    def list_folder_contents(self, path: PurePosixPath):
        if path.parts[0] == '/':
            file_path = '/'.join(path.parts[1:])  # remove root '/'
        else:
            file_path = str(path)
        
        try:
            res = self.client.get(f'/api/folders/{file_path}')
            res.raise_for_status()

            res_json: dict = res.json()
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise
        
        model = FolderContents(**res_json)
        return model


class APIKeyInterface:
    def __init__(self, parent: MainClient):
        self.parent = parent
        self.client = parent.client
    
    def list_all_keys(self) -> list[APIKeyInfo]:
        try:
            res = self.client.get('/api/auth/api_keys')
            res.raise_for_status()

            res_json: list[dict] = res.json()
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise
        
        ta = TypeAdapter(list[APIKeyInfo])
        models = ta.validate_python(res_json)

        return models

    def delete_key(self, key_name: str) -> GenericSuccess:
        try:
            res = self.client.delete(f'/api/auth/api_keys/{key_name}')
            res.raise_for_status()

            res_json: dict = res.json()
            res_model = GenericSuccess(**res_json)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_model
    
    def create_key(self, data: APIKeyCreate) -> str:
        json_model = data.model_dump(mode='json')
        try:
            res = self.client.post('/api/auth/api_keys', json=json_model)
            res.raise_for_status()

            res_json: str = res.json()
            if not res_json.startswith('syncserver-'):
                raise ValueError(f"expected api key with prefix 'syncserver-', got {res_json}")
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:", exc.response.status_code)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return res_json


if __name__ == '__main__':
    raise RuntimeError("cannot run this interface module directly")
