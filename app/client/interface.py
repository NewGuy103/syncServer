import json
import tempfile
import httpx

from pathlib import Path, PurePosixPath
from pydantic import TypeAdapter

from .models import (
    APIKeyCreate, AccessTokenResponse, AccessTokenError, 
    APIKeyInfo, FolderContents, GenericSuccess,
    DeletedFilesGet
)
from .config import logger

CHUNK_SIZE = 10 * 1024 * 1024  # 10MiB

# TODO: Use async httpx when PySide6 supports the asyncio event loop features
# or learn trio to make this asyncio
class MainClient:
    def __init__(self, authorization: str, server_url: str):
        self.auth_header: str = authorization
        self.server_url: str = server_url

    def log_request(self, req: httpx.Request):
        headers = dict(req.headers)
        if headers.get('authorization'):
            headers['authorization'] = '...'

        logger.debug("HTTP request sent: [%s %s] - Headers: %s", req.method, req.url, headers)

    def log_response(self, res: httpx.Response):
        req = res.request
        logger.debug(
            "HTTP response received from request [%s %s] - Status Code %d - Headers: %s",
            req.method, req.url, res.status_code, dict(res.headers)
        )

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
                logger.debug("Sent request to get Authorization token")

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
            logger.debug("Client error: %s", str(err_model))
            
            return err_model
        
        res_model = AccessTokenResponse(**res_data)
        return res_model
    
    def setup(self) -> bool:
        event_hooks = {'request': [self.log_request], 'response': [self.log_response]}
        self.client: httpx.Client = httpx.Client(
            headers={
                'accept': 'application/json',
                'Authorization': f'Bearer {self.auth_header}'
            },
            timeout=30,
            follow_redirects=False,
            base_url=self.server_url,
            event_hooks=event_hooks
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

        self.deleted = DeletedFilesInterface(self, parent)

    def make_url(self, folder: str, filename: str) -> str:
        """Make the URL where the file (and optionally folder) points to.
        
        `folder` is a PurePosixPath turned into a string, 
        so the URL is set like `/api/files/file{folder}/{filename}`.

        Which equates to: `/api/files/file/myfolder/filename`
        """
        if folder == '/':
            url: str = f'/api/files/file/{filename}'
        else:
            url: str = f'/api/files/file{folder}/{filename}'
        
        return url
    
    def upload_file(self, folder: str, filename: str, file_path: str) -> GenericSuccess:
        url: str = self.make_url(folder, filename)

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
        url: str = self.make_url(folder, filename)

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
        url: str = self.make_url(folder, filename)

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
        url: str = self.make_url(folder, old_name)

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
    
    def download_file(self, folder: str, filename: str, local_path: Path) -> None:
        url: str = self.make_url(folder, filename)

        try:
            with self.client.stream('GET', url) as res, tempfile.NamedTemporaryFile(
                mode='w+b', delete=False, suffix='.part',
                prefix='syncserver_download-'
            ) as file:
                for data in res.iter_bytes(CHUNK_SIZE):
                    file.write(data)
            
                tmp_path = Path(file.name)
            
            tmp_path.rename(local_path)
        except httpx.HTTPStatusError as exc:
            logger.exception("HTTP Status Error, HTTP %d:\n%s", exc.response.status_code, exc.response.text)
            raise
        except httpx.HTTPError:
            logger.exception("Generic HTTP Error:")
            raise
        except json.JSONDecodeError:
            logger.exception("Expected JSON data, but received this: [%s]", res.text)
            raise
        except OSError:
            logger.exception("Could not open temp file:")
            raise
        except Exception:
            logger.critical("Unexpected error during request:", exc_info=True)
            raise

        return None


class FolderInterface:
    def __init__(self, parent: MainClient):
        self.parent = parent
        self.client = parent.client
    
    def make_url(self, path: PurePosixPath):
        if path.parts[0] == '/':
            folder_path = '/'.join(path.parts[1:])  # remove root '/'
        else:
            folder_path = str(path)
        
        url: str = f'/api/folders/{folder_path}'
        return url
    
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
        url: str = self.make_url(path)
        
        try:
            res = self.client.get(url)
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

    def create_folder(self, path: PurePosixPath):
        url: str = self.make_url(path)
        try:
            res = self.client.post(url)
            res.raise_for_status()

            res_json: dict = res.json()
            res_model: GenericSuccess = GenericSuccess(**res_json)
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
    
    def delete_folder(self, path: PurePosixPath):
        url: str = self.make_url(path)

        try:
            res = self.client.delete(url)
            res.raise_for_status()

            res_json: dict = res.json()
            res_model: GenericSuccess = GenericSuccess(**res_json)
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
    
    def rename_folder(self, old_path: PurePosixPath, new_name: str):
        url: str = self.make_url(old_path)

        try:
            data = {"new_name": new_name}

            res = self.client.put(url, json=data)
            res.raise_for_status()

            res_json: dict = res.json()
            res_model: GenericSuccess = GenericSuccess(**res_json)
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


class DeletedFilesInterface:
    def __init__(self, parent: FilesInterface, main_parent: MainClient):
        self.parent = parent
        self.main_parent = main_parent

        self.client = main_parent.client
    
    def list_files_with_deletes(self) -> list[PurePosixPath]:
        try:
            res = self.client.get('/api/files/deleted/')
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

        ta = TypeAdapter(list[PurePosixPath])
        paths = ta.validate_python(res_json)
        
        return paths
    
    def empty_trashbin(self):
        try:
            res = self.client.delete('/api/files/deleted/')
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

    def show_deleted_versions(self, path: PurePosixPath, limit: int = 100, offset: int = 0) -> list[DeletedFilesGet]:
        params = {'limit': limit, 'offset': offset}
        try:
            res = self.client.get(f'/api/files/deleted{path}', params=params)
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

        ta = TypeAdapter(list[DeletedFilesGet])
        models = ta.validate_python(res_json)

        return models
    
    def delete_file_version(
        self, path: PurePosixPath, 
        offset: int = 0, delete_all: bool = False
    ) -> GenericSuccess:
        try:
            params = {'offset': offset, 'delete_all': delete_all}

            res = self.client.delete(f'/api/files/deleted{path}', params=params)
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
    
    def restore_file_version(
        self, path: PurePosixPath, 
        offset: int = 0
    ) -> GenericSuccess:
        try:
            data = {'offset': offset}

            res = self.client.put(f'/api/files/deleted{path}', json=data)
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
