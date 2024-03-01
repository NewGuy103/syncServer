# Client Module Documentation

## Overview

---

This module allows you to interact with the `syncserver.server` API with HTTP.
This uses `requests` to send HTTP POST requests.

## FileInterface

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L23)

Provides an interface for interacting with the files in the server with the REST API.
You can authenticate with either username/password, or an API token.

API keys will be preferred over username/password.

```python
from syncserver.client import FileInterface
username_pw_client = FileInterface(
    server_url="http://localhost:5000", username="user", password="pass"
)
api_key_client = FileInterface(server_url="http://localhost:5000", api_key="syncServer-...")
```

**Parameters:**

- **server_url** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The URL to the server.
- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **password** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The password of the user.
- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - API Key if you don't
    like using username/password authentication.

### `upload`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L47)

**Parameters:**

- **paths** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The local and remote paths
    of files to upload to.
- **modify_remote** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - A switch indicating
    if you want to upload it as a new file or modify an existing remote file.
    (This is not used if the `endpoint` parameter is specified.)
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the upload path.
    `/upload` if `modify_remote` is `False`, `/modify` if `True`.

**Returns:**

- `0` - If one upload is successful.
- `dict` - If one upload fails, or if there are more than one uploads.

**Raises:**

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

Where the list is the files that uploaded successfully, and the dict includes all the files that did not
upload successfully.

### `remove`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L111)

**Parameters:**

- **remote_paths** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The local and remote paths
    of files to upload to.
- **true_delete** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - A switch indicating
    if the server should mark it as deleted or fully delete it.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the delete path.
    Defaults to `/delete`.

**Returns:**

- `0` - If one delete is successful.
- `dict` - If one delete fails, or if there is more than one delete.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_paths` is not a list or tuple.
    * If `true_delete` is not a boolean.
    * If a remote path in `remote_paths` is not bytes or str.


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

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L166)

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to restore.
- **restore_which** ([_int_](https://docs.python.org/3/library/functions.html#int)) - An integer representing
    which deleted file version to restore.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the restore path.
    Defaults to `/restore`.

**Returns:**

- `0` - If the restore is successful.
- `dict` - If the restore fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not bytes or str.
    * If `restore_which` is not an integer.

This function takes in a string as the sole remote path.

It will return `0` if the restore is successful, or `dict` if it fails.

### `list_deleted`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L190)

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to list the deleted versions. This can also be `:all:` to list all deleted file versions.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the list deleted path.
    Defaults to `/list-deleted`.

**Returns:**

- `list[str]` - If the listing is successfu;.
- `dict` - If the listing fails, or if you listed all the deleted file versions.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not bytes or str.

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

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L216)

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the
    deleted file to restore.
- **delete_which** ([_int_](https://docs.python.org/3/library/functions.html#int)) - An integer representing
    which deleted file version to delete.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the true delete path.
    Defaults to `/remove-deleted`.

**Returns:**

- `0` - If the true delete is successful.
- `dict` - If the true delete fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not bytes or str.
    * If `delete_which` is not an integer or `:all:`.

This function takes in a string as the sole remote path.

It will return `0` if the true delete is successful, or `dict` if it fails.

### `read`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L240)

**Parameters:**

- **remote_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The remote path of the file.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the read path.
    Defaults to `/read`.

**Returns:**

- `bytes` - If the file read is successful.
- `dict` - If the file reading fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `remote_path` is not bytes or str.

This function takes in a string as the sole remote path.

It will return the response object's content directly.

## DirInterface

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L276)

Provides an interface for interacting with the directories in the server with the REST API.
You can authenticate with either username/password, or an API token.

Directories are not made using the file system, but instead an emulated one.
This will cause all directories to be isolated, so directory `/ab/cd` is not
a sub-directory of `/ab`.

API keys will be preferred over username/password.

```python
from syncserver.client import DirInterface
username_pw_client = DirInterface(
    server_url="http://localhost:5000", username="user", password="pass"
)
api_key_client = DirInterface(server_url="http://localhost:5000", api_key="syncServer-...")
```

### `create`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L300)

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to create.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the create
    directory path. Defaults to `/create-dir`.

**Returns:**

- `0` - If the directory creation is successful.
- `dict` - If the directory creation fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `dir_path` is not bytes or str.

This function takes in a string as the sole directory path. 

This will create a directory, allowing files to be put in this directory.

### `delete`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L334)

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to delete.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the delete
    directory path. Defaults to `/remove-dir`.

**Returns:**

- `0` - If the directory creation is successful.
- `dict` - If the directory creation fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `dir_path` is not bytes or str.

This function takes in a string as the sole directory path.

This will remove a directory and all the files within it.

**Currently in version 1.1.0, the server will not mark the directory or files as deleted.**

### `list_dir`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L366)

**Parameters:**

- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The directory path to list.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the list
    directory path. Defaults to `/list-dir`.

**Returns:**

- `list[str]` - The list of file names within the directory.
- `dict` - If the directory listing fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `dir_path` is not bytes or str.

This function takes in a string as the sole directory path.

This will list the filenames inside the specified directory.

## APIKeyInterface

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L398)

Provides an interface for managing API keys in the server with the REST API.
You can authenticate with either username/password, or an API token.

These API keys are not stored in plaintext on the server, so when you create an API key,
you won't be able to retrieve it again.

API keys will be preferred over username/password.

```python
from syncserver.client import DirInterface
username_pw_client = DirInterface(
    server_url="http://localhost:5000", username="user", password="pass"
)
api_key_client = DirInterface(server_url="http://localhost:5000", api_key="syncServer-...")
```

### `create_key`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L422)

**Parameters:**

- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the API key.
- **key_permissions** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The permissions
    of this API key. Allowed values are: `[create, read, update, delete]`.
- **key_expiry_date** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The date when the key expires.
    Allowed datetime format is: `%Y-%m-%d %H:%M:%S`.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key creation. Defaults to `/api/create-key`.

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

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#L458)

**Parameters:**

- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the API key.
- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key deletion. Defaults to `/api/delete-key`.

**Returns:**

- `0` - If the API key was deleted successfully.
- `dict` - If the API key deletion fails.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If one of the following happens:
    * If `key_name` is not a string.

This will remove the API key from the server and make it invalid.

### `list_keys`

---

[[source]](https://github.com/NewGuy103/syncServer/blob/accc19e29af8e712ebcf52405c9ea4545dcb355d/client/interface.py#483)

**Parameters:**

- **endpoint**: ([_str_](https://docs.python.org/3/library/functions.html#str)) - The endpoint of the API
    key listing. Defaults to `/api/list-keys`.

**Returns:**

- `list[str]` - A list of the API key names.
- `dict` - If the API key listing fails.

This will list the available API key names, but will not return the raw API keys.

---
