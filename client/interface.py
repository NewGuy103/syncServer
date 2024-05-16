import os
import logging
import requests

from typing import Literal
from datetime import datetime

__version__: str = "1.2.0"

logger: logging.Logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter: logging.Formatter = logging.Formatter(
    '[syncServer-interface]: [%(asctime)s] - [%(levelname)s] - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S'
)

stream_handler: logging.StreamHandler = logging.StreamHandler()
stream_handler.setFormatter(formatter)

file_handler: logging.FileHandler = logging.FileHandler('syncServer-clientInterface.log')
file_handler.setFormatter(formatter)

logger.addHandler(stream_handler)
logger.addHandler(file_handler)


class ServerInterface:
    def __init__(
            self, server_url: str, 
            username: str = None, 
            password: str = None,
             
            api_key: str = None,
            auth_endpoint: str = '/auth/check'
    ) -> None:
        if not username and not password and not api_key:
            raise ValueError("Authentication credentials are missing")
        
        # runtime type checking
        if username and password:
            if not isinstance(username, str):
                raise TypeError("username is not a string")
            
            if not isinstance(password, str):
                raise TypeError("password is not a string")
        elif api_key:
            if not isinstance(api_key, str):
                raise TypeError("api_key is not a string")
        
        if not username and not password and not api_key:
            raise ValueError("Credentials for authentication is missing")
        
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers['Authorization'] = api_key
        else:
            self.headers['syncServer-Username'] = username
            self.headers['syncServer-Password'] = password

        try:
            res: requests.Response = requests.get(
                url=f"{server_url}{auth_endpoint}", 
                headers=self.headers,
                timeout=10
            )
        except Exception:
            logger.exception("(ServerInterface.__init__): Failed to make authentication request:")
            raise
        
        json_res: dict = res.json()

        auth_verified: str = json_res.get('success')
        ecode: str = json_res.get('ecode')

        if ecode and ecode not in {'INVALID_CREDENTIALS', 'INVALID_APIKEY', 'EXPIRED_APIKEY'}:
            emsg: str = json_res.get('error')
            raise RuntimeError(f"Authorization failed with error code [{ecode}]: {emsg}")
        
        if not auth_verified:
            raise ValueError(f"Authorization failed, error code [{ecode}]")
        
        self.server_url: str = server_url
        self.files: _FileInterface = _FileInterface(self)

        self.dirs: _DirInterface = _DirInterface(self)
        self.api_keys: _APIKeyInterface = _APIKeyInterface(self)

        return


class _FileInterface:
    def __init__(self, parent: ServerInterface) -> None:
        self.headers: dict[str, str] = parent.headers
        self.server_url: str = parent.server_url
        return

    def upload(
        self, paths: list[str] | tuple[str], 
        modify_remote: bool = False, 
        endpoint: str = ""
    ) -> int | dict | tuple[list, dict]:
        """
        Upload files to the SyncServer or modify existing files.

        Parameters:
          - paths (list or tuple): List of file paths to be uploaded or modified.
           Format: [['localpath1', 'remotepath1'], ['localpath2', 'remotepath2'], ...]
          - modify_remote (bool, optional): If endpoint is not specified, this can be used
            to indicate if uploading or modifying a file by switching to either `/upload`
            or `/modify` default endpoints.

        Returns:
        - If a single file is uploaded successfully, returns 0.
        - If multiple files are uploaded, returns a tuple containing lists of successfully uploaded
            files and failed uploads.
            Example: (['file1', 'file2'], {'file3': {'error': '...'}})
        - If there's an issue with the request, returns the JSON response.

        Raises:
        - ValueError: If the paths format is incorrect or if a remote path is missing.

        If endpoint is specified, then `modify_remote` is not used, due to `/upload` and
        `/modify` generally being the same, where `/upload` only creates new files,
        and `/modify` only updates existing files.
        """

        files: dict = {}
        route: str = endpoint or (
            "/api/files/upload" if not modify_remote 
            else "/api/files/modify"
        )

        for i, file_paths in enumerate(paths):
            if len(file_paths) != 2:
                raise ValueError(
                    f"one list of file paths can only have two items, found on list {i}"
                )

            filename: str = file_paths[0]
            if not isinstance(filename, (bytes, str)):
                raise TypeError(f"local filename on list {i} is not bytes or str")
            
            if not os.path.isfile(filename):
                logger.warning("Path '%s' is not a file", filename)
                continue
            
            remote_filepath: str = file_paths[1]
            if not remote_filepath:
                raise ValueError(f"remote path is missing on list {i}")
            
            if not isinstance(remote_filepath, str):
                raise TypeError(f"remote file path on list {i} is not a string")
            
            files[remote_filepath] = (remote_filepath, open(filename, "rb"))

        response: requests.Response = requests.post(
            url=self.server_url + route, 
            headers=self.headers, files=files, 
            timeout=5
        )
        
        for file_tuple in files.values():
            try:
                file_tuple[1].close()
            except Exception:
                logger.exception("(_FileInterface.upload): Closing file '%s' failed:", file_tuple[1].name)

        json_response: dict = response.json()
        if len(list(files.keys())) == 1:
            if json_response.get("success"):
                return 0

            return json_response

        ok_uploads: list = json_response.get("ok", [])
        failed_uploads: dict = json_response.get("fail", {})

        return ok_uploads, failed_uploads

    def remove(
        self, 
        remote_paths: list[str] | tuple[str],
        true_delete: bool = False,
        endpoint: str = "/api/files/delete",
    ) -> int | tuple[list, dict]:
        """
        Remove files or directories from the SyncServer.

        Parameters:
        - remote_paths (list or tuple): List of remote paths to be removed.
        Format: ['/remote-path1', '/remote-path2', ...]
        - endpoint (str, optional): API endpoint for removal. Default is "/delete".

        Returns:
        - If a single file/directory is removed successfully, returns 0.
        - If multiple files/directories are removed, returns a tuple containing lists
            of successfully removed items and failed removals.
            Example: (['item1', 'item2'], {'item3': {'error': '...'}})
        - If there's an issue with the request, returns the JSON response.

        Raises:
        - TypeError: If remote paths are not in a list or tuple or if a remote path is not bytes or str.
        """

        if not isinstance(remote_paths, (list, tuple)):
            raise TypeError("remote paths must be in a list/tuple")

        if not isinstance(true_delete, bool):
            raise TypeError("true_delete must be a bool value")

        for remote_path in remote_paths:
            if not isinstance(remote_path, str):
                raise TypeError(f"remote path '{remote_path}' is not a string")

        data: dict = {"file-paths": remote_paths, "true-delete": true_delete}
        response: requests.Response = requests.post(
            url=self.server_url + endpoint, 
            headers=self.headers, json=data, 
            timeout=5
        )

        json_response: dict = response.json()
        if len(remote_paths) == 1:
            if json_response.get("success"):
                return 0

            return json_response

        ok_uploads: list = json_response.get("ok", [])
        failed_uploads: dict = json_response.get("fail", {})

        return ok_uploads, failed_uploads

    def restore(
        self, remote_path: str,
        restore_which: int = 0,
        endpoint: str = "/api/files/restore",
    ) -> int | dict:
        if not isinstance(remote_path, str):
            raise TypeError("remote path must be a string")

        if not isinstance(restore_which, int):
            raise TypeError("restore_which can only be an int value")

        data: dict[str, str] = {"file-path": remote_path, "restore-which": restore_which}
        response: requests.Response = requests.post(
            url=self.server_url + endpoint, 
            headers=self.headers, 
            json=data, timeout=5
        )

        json_data: dict = response.json()
        if json_data.get("success"):
            return 0

        return json_data

    def list_deleted(
        self, remote_path: str, endpoint: str = "/api/files/list-deleted"
    ) -> list | dict:
        if not isinstance(remote_path, str):
            raise TypeError("remote path must be a string")

        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={"file-path": remote_path},
            timeout=5,
        )

        json_data: dict = response.json()
        is_batch: bool = json_data.get("batch", -1)

        if is_batch == -1:  # assume error response
            return json_data

        if is_batch:
            del json_data["batch"]
            return json_data
        elif not is_batch:
            return json_data.get("delete-order")

    def remove_deleted(
        self,
        remote_path: str,
        delete_which: int | Literal[":all:"],
        endpoint: str = "/api/files/remove-deleted",
    ) -> int | dict:
        if not isinstance(remote_path, str):
            raise TypeError("remote path must be a string")

        if not (delete_which == ":all:" or isinstance(delete_which, int)):
            raise TypeError("delete_which can only be ':all:' or int")

        if isinstance(delete_which, int) and delete_which < 0:
            raise ValueError('delete_which can only be a positive number')
        
        data: dict = {"file-path": remote_path, "delete-which": delete_which}
        response: requests.Response = requests.post(
            url=self.server_url + endpoint, headers=self.headers, json=data, timeout=5
        )
        
        json_data: dict = response.json()
        if json_data.get("success"):
            return 0

        return json_data

    def read(
            self, remote_path: str, output_path: str,
            chunk_size: int = 10 * 1024 * 1024, endpoint: str = "/api/files/read"
    ) -> dict | int:
        if not isinstance(remote_path, str):
            raise TypeError("remote path must be a string")

        if not isinstance(output_path, str):
            raise TypeError("output path must be a string")
        
        if os.path.isfile(output_path):
            raise FileExistsError(f"File exists, cannot proceed: {output_path}")
        
        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={"file-path": remote_path},
            timeout=5, stream=True
        )
        
        content_type: str = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            json_response = response.json()
            return json_response

        with open(output_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    file.write(chunk)
                    continue

                break

        return 0


class _DirInterface:
    def __init__(self, parent: ServerInterface) -> None:
        self.headers: dict[str, str] = parent.headers
        self.server_url: str = parent.server_url
        return
    
    def create(
        self, dir_path: str, endpoint: str = "/api/dirs/create"
    ) -> int | dict:
        if not isinstance(dir_path, str):
            raise TypeError("directory path must be a string")

        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={"dir-path": dir_path},
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return 0

        return json_response

    def delete(self, dir_path: str, endpoint: str = "/api/dirs/remove") -> int | dict:
        if not isinstance(dir_path, str):
            raise TypeError("directory path must be a string")

        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={"dir-path": dir_path},
            timeout=5
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return 0

        return json_response

    def list_dir(
            self, dir_path: str, 
            list_deleted_only: bool = False,
            endpoint: str = "/api/dirs/list"
    ) -> list | dict:
        if not isinstance(dir_path, str):
            raise TypeError("directory path must be a string")

        if not isinstance(list_deleted_only, bool):
            raise TypeError("'list_deleted_only' can only be bool")
        
        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={"dir-path": dir_path, 'list-deleted-only': list_deleted_only},
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return json_response.get("dir-listing")

        return json_response
    
    def get_dir_paths(self, endpoint: str = "/api/dirs/get-paths") -> list[str]:
        response: requests.Response = requests.get(
            url=self.server_url + endpoint,
            headers=self.headers,
            timeout=5
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return json_response.get("dir-paths")

        return json_response


class _APIKeyInterface:
    def __init__(self, parent: ServerInterface) -> None:
        self.headers: dict[str, str] = parent.headers
        self.server_url: str = parent.server_url
        return

    def create_key(
            self, key_name: str, 
            key_permisions: list[str], 

            key_expiry_date: str,
            endpoint: str = "/api/keys/create"
    ) -> str | dict:
        if not isinstance(key_name, str):
            raise TypeError("key name must be a string")
        
        if not isinstance(key_permisions, list):
            raise TypeError("key permisions must a list")
        
        if not isinstance(key_expiry_date, str):
            raise TypeError("key expiry date must be a string")
        
        # Check datetime format if valid
        datetime.strptime(key_expiry_date, "%Y-%m-%d %H:%M:%S")

        data: dict[str, str] = {
            "key-name": key_name,
            "key-permissions": key_permisions,
            "key-expiry-date": key_expiry_date
        }

        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json=data,
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return json_response.get("api-key")

        return json_response
    
    def delete_key(
            self, key_name: str, 
            endpoint: str = "/api/keys/delete"
    ) -> int | dict:
        if not isinstance(key_name, str):
            raise TypeError("key name must be a string")

        data: dict[str, str] = {"key-name": key_name}
        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json=data,
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return 0

        return json_response
    
    def list_keys(self, endpoint: str = "/api/keys/list-all") -> list | dict:
        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json={},
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return json_response.get('key-names')

        return json_response
    
    def get_key_data(
            self, *, api_key: str = '', 
            key_name: str = '',
            endpoint: str = "/api/keys/get-data"
    ) -> list | dict:
        if api_key and key_name:
            raise ValueError("only a raw API key or key name is allowed")
        
        if not api_key and not key_name:
            raise ValueError("a raw API key or key name must be specified")
        
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")
        
        if api_key:
            data: dict = {'api-key': api_key}
        else:
            data: dict = {'key-name': key_name}
        
        response: requests.Response = requests.post(
            url=self.server_url + endpoint,
            headers=self.headers,
            json=data,
            timeout=5,
        )
        
        json_response: dict = response.json()
        if json_response.get("success"):
            return json_response.get('key-data')

        return json_response


# Backwards compatibility
class FileInterface(_FileInterface):
    def __init__(
            self, server_url: str, 
            username: str = None, 
            password: str = None,
             
            api_key: str = None
    ) -> None:
        self.__server_interface: ServerInterface = ServerInterface(
            server_url, username=username, password=password,
            api_key=api_key
        )
        super().__init__(self.__server_interface)


class DirInterface(_DirInterface):
    def __init__(
            self, server_url: str, 
            username: str = None, 
            password: str = None,
             
            api_key: str = None
    ) -> None:
        self.__server_interface: ServerInterface = ServerInterface(
            server_url, username=username, password=password,
            api_key=api_key
        )
        super().__init__(self.__server_interface)
    

class APIKeyInterface(_APIKeyInterface):
    def __init__(
            self, server_url: str, 
            username: str = None, 
            password: str = None,
             
            api_key: str = None
    ) -> None:
        self.__server_interface: ServerInterface = ServerInterface(
            server_url, username=username, password=password,
            api_key=api_key
        )
        super().__init__(self.__server_interface)


if __name__ == "__main__":
    raise NotImplementedError("cannot run this module as a script")
