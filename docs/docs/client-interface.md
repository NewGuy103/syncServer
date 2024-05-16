# Client Module Documentation

## Overview

---

This module allows you to interact with the `syncserver.server` API with HTTP.
This uses `requests` to send HTTP requests.

The module has a logger named `logger`, it writes to `./syncServer-clientInterface.log`.

## ServerInterface

---

This is the main interface that you should use when interacting with the server. This
puts all the methods into a main class.

```python
from syncserver.client import ServerInterface
interface = ServerInterface(
    "http://localhost:8561", username="user", password="pass"
)
```

**Attributes:**

- **server_url**: The provided server URL.
- **files**: The interface for file-related operations. Instance of `_FileInterface`.
- **dirs**: The interface for directory-related operations. Instance of `_DirInterface`.
- **api_keys**: The interface for API key-related operations. Instance of `_APIKeyInterface`.

**Parameters:**

- **server_url** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The URL to the server.
- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **password** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The password of the user.
- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - API Key if you don't
    like using username/password authentication.

**Raises:**

- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) - If one of the following happens:
    * No authentication credentials were provided.
    * One list in `paths` has an empty remote path.
    * If authentication failed with an expected error. (Invalid/expired API key, wrong credentials)
- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `username`, `password`, or `api_key` is
    not a string.
- [**RuntimeError**](https://docs.python.org/3/library/exceptions.html#RuntimeError) - If authentication fails with an
    unexpected error.

- **requests.RequestException** - If any exception happens during the authentication request.

## File Interface

---

This is the interface for file-based operations. It is found as `ServerInterface.files`.

**This class is designed to be initialized by ServerInterface only.** 
If you want to use `FileInterface` directly, look at the [**Old Interfaces**](#old-interfaces) section.

### `upload`

---

**Parameters:**

- **paths** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The local and remote paths
    of files to upload to.
- **modify_remote** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - A switch indicating
    if you want to upload it as a new file or modify an existing remote file.
    (This is not used if the `endpoint` parameter is specified.)
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the upload path.
    `/api/files/upload` if `modify_remote` is `False`, `/api/files/modify` if `True`.

**Returns:**

- `0` - If one upload is successful.
- `dict` - If one upload fails.
- `tuple[list, dict]` - If more than one file was specified, which means it's a batch action.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * The local path is not `bytes` or `str`.
    * The remote path is not a string.

- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) - If one of the following happens:
    * One list in `paths` has more or less than two items.
    * One list in `paths` has an empty remote path.

This function takes in a list in this format:
```json
[
    ["local_path.txt", "/remote-file-path"],
    ["local_path_2.txt", "/remote-file-path-2"]
]
```

Where the first item is the path to the local file, and the second item is the remote path for the server.

If one file is uploaded, then it will either return `0` if it uploads successfully, or a `dict`
with the error response.

But if more than one file is uploaded, it will return a `tuple`:
```python
(
    ["/remote-1", "/remote-2"], 
    {
        "/remote-3": {} # JSON error response here
    }
)
```

Where the list is the files that uploaded successfully, and the dictionary includes all the files that did not
upload successfully.

The upload and modify routes in the server script are functionally identical, only difference is that upload creates
the file if it doesn't exist, while modify updates an existing file.

### `remove`

---

**Parameters:**

- **remote_paths** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The local and remote paths
    of files to upload to.
- **true_delete** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - A switch indicating
    if the server should mark it as deleted or fully delete it.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the delete path.
    Defaults to `/api/files/delete`.

**Returns:**

- `0` - If one delete is successful.
- `dict` - If one delete fails, or if there is more than one delete.
- `tuple[list, dict]` - If more than one file is deleted, which means it's a batch action.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_paths` is not a list or tuple.
    * If `true_delete` is not a boolean.
    * If a remote path in `remote_paths` is not a string.

This function takes in a list in this format:
```json
["/remote-path-1", "/remote-path-2"],
```

Where each item is treated as a remote path.

If one file is deleted, then it will either return `0` if it's deleted successfully, or a `dict`
with the error response.

But if more than one file is deleted, it will return a `tuple`:
```python
(
    ["/remote-1", "/remote-2"], 
    {
        "/remote-3": {} # JSON error response here
    }
)
```

Where the list is the files that deleted successfully, and the dict includes all the files that did not
delete successfully.

### `restore`

---

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to restore.
- **restore_which** ([_int_](https://docs.python.org/3/library/functions.html#int)) - An integer representing
    which deleted file version to restore.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the restore path.
    Defaults to `/api/files/restore`.

**Returns:**

- `0` - If the restore is successful.
- `dict` - If the restore fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not a string.
    * If `restore_which` is not an integer.

This function takes in ing as the sole remote path.

It will return `0` if the restore is successful, or `dict` if it fails.

### `list_deleted`

---


**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to list the deleted versions. This can also be `:all:` to list all deleted file versions.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the list deleted path.
    Defaults to `/api/files/list-deleted`.

**Returns:**

- `list[str]` - If the listing is successful.
- `dict` - If the listing fails, or if you listed all the deleted file versions.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `remote_path` is not a string.

This function takes in a string as the sole remote path.

It will return a `list[str]` with the deleted file versions if it's a remote path, or a `dict` if
the upload fails.

But if you listed all deleted file versions, then it will return a `dict` like this:
```json
{
    "/remote-1": ["2024-01-01 5:00:00", "2024-01-01 7:34:44"],
    "/remote-2": ["2024-01-01 15:00:00", "2024-01-01 23:42:02"],
}
```

This will always be in the order of latest -> oldest.

### `remove_deleted`

---

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to restore.
- **delete_which** ([_int_](https://docs.python.org/3/library/functions.html#int)) - An integer representing
    which deleted file version to delete. This can also be `:all:` to remove all versions.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the true delete path.
    Defaults to `/api/files/remove-deleted`.

**Returns:**

- `0` - If the true delete is successful.
- `dict` - If the true delete fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not a string.
    * If `delete_which` is not an integer or `:all:`.

This function takes in a string as the sole remote path.

It will return `0` if the true delete is successful, or `dict` if it fails.

### `read`

---

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the file.
- **output_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - Where to save the file.
- **chunk_size** ([_int_](https://docs.python.org/3/library/functions.html#int)) - How much data to stream per chunk.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the read path.
    Defaults to `/api/files/read`.

**Returns:**

- `0` - If the file read is successful.
- `dict` - If the file reading fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not a string.
    * If `output_path` is not a string.

This function will write the file to the output filename by streaming it.

## Directory Interface

---

Provides an interface for interacting with the directories in the server.

Directories are not made using the file system, but instead an emulated one.
This will cause all directories to be isolated, so directory `/ab/cd` is not
a sub-directory of `/ab`.

API keys will be preferred over username/password.

**This class is designed to be initialized by ServerInterface only.** 
If you want to use `DirInterface` directly, look at the [**Old Interfaces**](#old-interfaces) section.

### `create`

---

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to create.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the create
    directory path. Defaults to `/api/dirs/create`.

**Returns:**

- `0` - If the directory creation is successful.
- `dict` - If the directory creation fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `dir_path` is not a string.

This function takes in a string as the sole directory path. 

This will create a directory, allowing files to be put in this directory.

### `delete`

---

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to delete.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the delete
    directory path. Defaults to `/api/dirs/remove`.

**Returns:**

- `0` - If the directory deletion is successful.
- `dict` - If the directory deletion fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `dir_path` is not a string.

This function takes in a string as the sole directory path.

This will remove a directory and all the files within it.

**Since version 1.1.0, the server will not mark the directory or files as deleted, but directly delete it.**

### `list_dir`

---

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to list.
- **list_deleted_only** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - Switch indicating
    if listing only deleted files, lists non-deleted files otherwise.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the list
    directory path. Defaults to `/api/dirs/list`.

**Returns:**

- `list[str]` - The list of file names within the directory.
- `dict` - If the directory listing fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `dir_path` is not a string.
    * If `list_deleted_only` is not bool.

This function takes in a string as the sole directory path.

This will list the filenames inside the specified directory.

### `get_dir_paths`

---

**Parameters:**

- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the get
    directory paths. Defaults to `/api/dirs/get-paths`.

**Returns:**

- `list[str]` - The list with directory paths.
- `dict` - If listing fails.

This will get all directory paths that your user has created.

## APIKeyInterface

---

Provides an interface for managing API keys in the server with the REST API.

These API keys are not stored in plaintext on the server, so when you create an API key,
you won't be able to retrieve it again.

**This class is designed to be initialized by ServerInterface only.** 
If you want to use `FileInterface` directly, look at the [**Old Interfaces**](#old-interfaces) section.

### `create_key`

---

**Parameters:**

- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the API key.
- **key_permissions** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The permissions
    of this API key. Allowed values are: `[create, read, update, delete]`.
- **key_expiry_date** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The date when the key expires.
    Allowed datetime format is: `%Y-%m-%d %H:%M:%S`.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key creation. Defaults to `/api/keys/create`.

**Returns:**

- *API Key* - The returned API key. The key starts with `syncServer-`.
- `dict` - If the API key creation fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `key_name` or `key_expiry_date` is not a string.
    * If `key_permissions` is not a list.

This will create an API key on the server, and return the API key.
The server will not store this API key in plain text, so it will only be viewable once.

### `delete_key`

---

**Parameters:**

- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the API key.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key deletion. Defaults to `/api/keys/delete`.

**Returns:**

- `0` - If the API key was deleted successfully.
- `dict` - If the API key deletion fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `key_name` is not a string.

This will remove the API key from the server and make it invalid.

### `list_keys`

---

**Parameters:**

- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key listing. Defaults to `/api/keys/list`.

**Returns:**

- `list[str]` - A list of the API key names.
- `dict` - If the API key listing fails.

This will list the available API key names, but will not return the raw API keys.

### `get_key_data`

---

**Parameters:**

- **api_Key**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The raw API key. Cannot
    be used with `key_name`.
- **key_name**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The API key name. Cannot
    be used with `api_key`.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key listing. Defaults to `/api/keys/list`.

**Returns:**

- `list[list, str, bool]` - API key data for the provided key:
    - 0: List containing the key permissions.
    - 1: The expiry date.
    - 2: If the key has expired yet.
- `dict` - If the API key listing fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `key_name` or `api_key`
    is not a string.
- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) - If one of the following happens:
    - `api_key` and `key_name` was provided together.
    - `api_key` or `key_name` was not provided.

This will show the data for that API key.

---

## Old Interfaces

---

These interfaces are for backwards compatibility. Under the hood, it simply subclasses the corresponding method,
initializes a `ServerInterface` instance, and calls `super().__init__()`, passing that instance.

### `FileInterface`, `DirInterface`, `APIKeyInterface`

**Parameters:**

- **server_url** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The URL to the server.
- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **password** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The password of the user.
- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - API Key if you don't
    like using username/password authentication.
