import json
import os
from typing import Any, Union
import requests

__version__ = "1.0.0"

class FileInterface:
    """
    Provides an interface for interacting with the SyncServer file management system.

    Args:
        server_url (str): The URL of the SyncServer.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Attributes:
        server_url (str): The URL of the SyncServer.
        username (str): The username for authentication.
        _password (str): The password for authentication (private attribute).
    """

    def __init__(
            self, server_url: str,
            username: str,
            password: str
    ) -> None:
        self.server_url = server_url
        self.username = username
        self._password = password

    def upload(
            self, paths: list | tuple,
            modify_remote: bool = False
        ) -> Union[int, tuple[list, dict]]:
        """
        Upload files to the SyncServer or modify existing files.

        Parameters:
          - paths (list or tuple): List of file paths to be uploaded or modified.
           Format: [['localpath1', 'remotepath1'], ['localpath2', 'remotepath2'], ...]
          - modify_remote (bool, optional): If True, the files will be modified on the server if they already exist.
            If False (default), the files will be uploaded as new.

        Returns:
        - Union[int, Tuple[list, dict]]: 
          - If a single file is uploaded successfully, returns 0.
          - If multiple files are uploaded, returns a tuple containing lists of successfully uploaded 
            files and failed uploads.
            Example: (['file1', 'file2'], {'file3': {'error': '...'}})
          - If there's an issue with the request, returns the JSON response.

        Raises:
        - ValueError: If the paths format is incorrect or if a remote path is missing.
        """

        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        files = {}
 
        route = "/upload" if not modify_remote else "/modify"
        for i, file_paths in enumerate(paths):
            if len(file_paths) != 2:
                raise ValueError(
                    f'one list of file paths can only have two items, found on list {i}'
                )
            
            filename = file_paths[0]
            if not os.path.isfile(filename):
                continue
            
            if not file_paths[1]:
                raise ValueError(f"remote path is missing on list {i}")
            
            files[file_paths[1]] = (file_paths[1], open(filename, 'rb'))
        
        response = requests.post(
            url=self.server_url+route, headers=headers,
            files=files, timeout=5
        )

        for file_tuple in files.values():
            file_tuple[1].close()

        json_response = response.json()
        if len(list(files.keys())) == 1:
            if json_response.get('success'):
                return 0
            
            return json_response
        
        ok_uploads = json_response.get('ok', [])
        failed_uploads = json_response.get('fail', {})

        return ok_uploads, failed_uploads
    
    def remove(self, remote_paths: list | tuple, endpoint="/delete") -> Union[int, tuple[list, dict]]:
        """
        Remove files or directories from the SyncServer.

        Parameters:
        - remote_paths (list or tuple): List of remote paths to be removed.
        Format: ['/remote-path1', '/remote-path2', ...]
        - endpoint (str, optional): API endpoint for removal. Default is "/delete".

        Returns:
        - Union[int, Tuple[list, dict]]: 
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
        
        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        json_list = json.dumps(remote_paths)

        for remote_path in remote_paths:
            if not isinstance(remote_path, (bytes, str)):
                raise TypeError(f"remote path '{remote_path}' is not bytes or str")

        response = requests.post(
            url=self.server_url+endpoint, headers=headers,
            data={'file-paths': json_list}, timeout=5
        )

        json_response = response.json()
        if len(remote_paths) == 1:
            if json_response.get('success'):
                return 0
            
            return json_response
        
        ok_uploads = json_response.get('ok', [])
        failed_uploads = json_response.get('fail', {})

        return ok_uploads, failed_uploads
    
    def read(self, remote_path: bytes | str, endpoint="/read") -> Union[dict[str, Any], bytes]:
        """
        Read the contents of a file from the SyncServer.

        Parameters:
        - remote_path (bytes or str): Remote path of the file to be read.
        - endpoint (str, optional): API endpoint for reading. Default is "/read".

        Returns:
        - Union[Dict[str, Any], bytes]: 
          - If the content is in JSON format, returns the parsed JSON response.
          - If the content is binary, returns the binary content.

        Raises:
        - TypeError: If remote path is not bytes or str.
        """

        if not isinstance(remote_path, (bytes, str)):
            raise TypeError("remote path must be bytes/str")
        
        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        response = requests.post(
            url=self.server_url+endpoint, headers=headers,
            data={'file-path': remote_path}, timeout=5
        )

        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            json_response = response.json()
            return json_response
        
        return response.content


class DirInterface:
    """
    The DirInterface class provides methods for interacting with directories on the SyncServer.

    Methods:
        - create(dir_path: bytes | str, endpoint="/create-dir") -> Union[int, dict]: 
          Create a directory on the SyncServer.

        - delete(dir_path: str, endpoint="/remove-dir") -> Union[int, dict]: 
          Remove a directory from the SyncServer.

        - list_dir(dir_path: str, endpoint="/list-dir") -> Union[list, dict]: 
          List files in a directory on the SyncServer.

    Parameters:
        - server_url (str): The URL of the SyncServer.
        - username (str): The username for authentication.
        - password (str): The password for authentication.
    """

    def __init__(
            self, server_url: str,
            username: str,
            password: str
    ) -> None:
        self.server_url = server_url
        self.username = username
        self._password = password
    
    def create(
        self, dir_path: bytes | str, endpoint="/create-dir"
    ) -> Union[int, dict]:
        """
        Create a directory on the SyncServer.

        Parameters:
        - dir_path (bytes or str): The directory path to be created.

        Returns:
        - Union[int, dict]: 
          - If the directory is created successfully, returns 0.
          - If there's an issue with the request, returns the JSON response.

        Raises:
          - TypeError: If dir_path is not bytes or str.
        """

        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("directory path must be bytes/str")

        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        response = requests.post(
            url=self.server_url+endpoint, headers=headers,
            data={'dir-path': dir_path}, timeout=5
        )
        
        json_response = response.json()
        if json_response.get("success"):
            return 0
        
        return json_response

    def delete(self, dir_path: str, endpoint="/remove-dir") -> Union[int, dict]:
        """
        Remove a directory from the SyncServer.

        Parameters:
          - dir_path (str): The directory path to be removed.

        Returns:
        - Union[int, dict]: 
          - If the directory is removed successfully, returns 0.
          - If there's an issue with the request, returns the JSON response.

        Raises:
          - TypeError: If dir_path is not bytes or str.
        """

        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("directory path must be bytes/str")

        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        response = requests.post(
            url=self.server_url+endpoint, headers=headers,
            data={'dir-path': dir_path}, timeout=5
        )
        
        json_response = response.json()
        if json_response.get("success"):
            return 0
        
        return json_response


    def list_dir(
        self, dir_path: str, endpoint="/list-dir"
    ) -> Union[list, dict]:
        """
        List files in a directory on the SyncServer.

        Parameters:
        - dir_path (str): The directory path to list files from.

        Returns:
        - Union[list, dict]: 
          - If the directory exists, returns a list of filenames.
          - If there's an issue with the request, returns the JSON response.

        Raises:
          - TypeError: If dir_path is not bytes or str.
        """
        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("directory path must be bytes/str")

        headers = {
            'syncServer-Username': self.username,
            'syncServer-Token': self._password
        }
        response = requests.post(
            url=self.server_url+endpoint, headers=headers,
            data={'dir-path': dir_path}, timeout=5
        )
        
        json_response = response.json()
        if json_response.get("success"):
            return json_response.get('dir-listing')
        
        return json_response
    
if __name__ == "__main__":
    raise NotImplementedError("cannot run this module as a script")
