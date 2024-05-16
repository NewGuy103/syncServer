# Server Database Documentation

## Overview

---

The `syncserver.server` database uses `sqlite3` by default.

There is also a command line interface to interact with the configurations of the database.

## Command line interface

---

```bash
usage: syncserver.server-db [-h] [--database-path [db-path]] [--database-protected] [--recover-key] [--edit-vars] [--edit-config]
                            [--set-protection] [--add-user] [--remove-user]

Command line tool to manage the syncServer database locally. Current application version: 1.2.0

options:
  -h, --help            show this help message and exit
  --database-path [db-path], -db [db-path]
                        Path to syncServer database.
  --database-protected, -dp
                        Prompt to enter the database password.
  --recover-key, -rk    Recover the original encryption key with the key password.
  --edit-vars, -ev      Edit configuration variables without fully initializing the database.
  --edit-config, -ec    Open the configuration and edit it with nano.
  --set-protection, -sp
                        Set the encryption key that the database will use.
  --add-user, -aU       Create a new user using provided credentials
  --remove-user, -rU    Remove an existing user.
```

*Since version 1.1.0, `--set-protection` will not re-encrypt all the previously encrypted data*
*if the database had an encryption key before.*

## FileDatabase

---

A class representing a file database with user authentication, file storage, and encryption capabilities.

```python
from syncserver.server import FileDatabase
file_db = FileDatabase(db_password=None)
```

**Attributes:**

- **db** - The `sqlite3` connection to the database.
- **api_keys** - An instance of `APIKeyInterface` that allows the database to access API keys.
- **deleted_files** - An instance of `DeletedFiles` that allows the database to access deleted files.
- **dirs** - An instance of `DirectoryInterface` that allows the database to access directories.

**Parameters:**

- **db_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The path to the `sqlite3` database. 
    Defaults to `$XDG_DATA_HOME/syncServer-server/<version>/syncServer.db`.
- **db_password** ([_bytes_](https://docs.python.org/3/library/functions.html#bytes) | [_str_](https://docs.python.org/3/library/functions.html#str)) - The encryption password used to protect the database.
- **recovery_mode**  ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - Flag to only partially initialize
    the database to access the configuration variables.

**Raises:** 

- [**RuntimeError**](https://docs.python.org/3/library/exceptions.html#RuntimeError) - This exception is raised if one of the following
    happens:
    - `syncServer-db-version` is not in the `config_vars` dictionary.
    - `syncServer-db-version` does not match to the current database version in the application.
    - `syncServer-protected` is not in the `config_vars` dictionary.
    - Provided a database password but the database was not protected.
    - Decrypting the database fails due to the wrong key.

### `set_protection` 

---

**Parameters:**

- **set_protection** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - Whether to enable/disable database protection.
- **cipher_key** ([_bytes_](https://docs.python.org/3/library/functions.html#bytes) | [_str_](https://docs.python.org/3/library/functions.html#str)) - The password to use for data encryption/decryption.

This writes to the database's config table, and modifies `config_vars` to reflect the state of the database. When database protection is set to `True`, then `config_secrets` is encrypted and the application will encrypt all data being stored at rest, and decrypt data when required.

If database protection is set to `False`, then the database will not encrypt any more data at rest. This will not decrypt existing data,
and will cause the database to fail decryption on some data if it was encrypted.

### `save_conf`

**Parameters:**

- **secrets** ([_dict_](https://docs.python.org/3/library/stdtypes.html#dict)) - The dictionary with the updated
    config secrets.
- **_vars** ([_dict_](https://docs.python.org/3/library/stdtypes.html#dict)) - The dictionary with the updated
    config vars.

This function simply saves the updated configuration secrets/variables, and is mainly used by the command line interface.

### `verify_user`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **token** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The password to verify.

**Returns:**

- ([**bool**](https://docs.python.org/3/library/functions.html#bool)) - If the password is verified or not.
- `NO_USER` - If the user does not exist in the database.
- ([**Exception**](https://docs.python.org/3/library/exceptions.html#Exception)) - If any error happens during hash verification.

This verifies the hash of the user with their password.

### `add_user` 

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **token** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The password to verify.

**Returns:**

- `0` - If user creation is successful.
- `USER_EXISTS` - If the user exists in the database.

**Raises:**

- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) - If `username` is a blacklisted
    username.

This function will create a new user account with the provided username and token, and create the root directory for the user.

### `remove_user` 

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.

**Returns:**

- `0` - If user deletion is successful.
- `NO_USER` - If no user with that name exists in the database.

This will permanently delete the user and all their existing data (files, API keys, etc).

### `dir_checker` 

---

**Parameters:**

- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full file path.
- **user_id** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The user ID of the user.

**Returns:**

- `tuple[str]` - If the directory exists, returns a tuple containing the directory ID.
- `None` - If the directory does not exist.
- `NO_USER` - If the specified user ID is not found in the database.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If 'file_path' is not a string.
- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) - If 'file_path' is empty.

This checks the provided file path and sees if the underlying directory exists. (A Unix path-like)

### `add_file`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the file to save to.
- **file_stream** (file stream) - The file stream containing file data.
- **chunk_size** ([_int_](https://docs.python.org/3/library/functions.html#int)) - How much memory to allocate for each chunk.

**Returns:**

- `0` - If the file is successfully added to the database.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the directory for the file does not exist for the user.
- `FILE_EXISTS` - If a file with the same path exists for the user.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string, or
    if  `chunk_size` is not an integer.
- [**IOError**](https://docs.python.org/3/library/exceptions.html#IOError) - If the file stream is empty.

This adds a file into the database by reading the file stream in chunks. If encryption is enabled, then the data will be encrypted first before being stored in the database. This uses `sqlite3`'s concat (`||`) operator for chunk writing.

### `modify_file`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the file to update.
- **file_stream** (file stream) - The file stream containing file data.
- **chunk_size** ([_int_](https://docs.python.org/3/library/functions.html#int)) - How much memory to allocate for each chunk.

**Returns:**

- `0` - If the file is successfully modified and written to the database.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the directory for the file does not exist for the user.
- `NO_FILE_EXISTS` - If a file with the same path does not exist for the user.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string, or
    if  `chunk_size` is not an integer.
- [**IOError**](https://docs.python.org/3/library/exceptions.html#IOError) - If the file stream is empty.

This modifies an existing file in the database by reading the file stream in chunks. If encryption is enabled, then the data will be encrypted first before being stored in the database. This uses `sqlite3`'s concat (`||`) operator for chunk writing.

### `remove_file`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the file to delete.
- **permanent_delete** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - A switch to indicate
    if the file should be marked as deleted or permanently removed from the database.

**Returns:**

- `0` - If the file is successfully removed from the database.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the directory for the file does not exist for the user.
- `NO_FILE_EXISTS` - If a file with the same path does not exist for the user.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If 'file_path' is not a string.

This will remove a file temporarily marking it as deleted, making it hidden from the main database while retaining the original
file, and can be restored.

Or this will remove a file permanently by removing it from the database entirely.

### `read_file`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the file to read.
- **chunk_size** ([_int_](https://docs.python.org/3/library/functions.html#int)) - How much memory to allocate for each chunk.
    If the chunk size stored in the database does not match the provided chunk size, the one inside the database will be used.

**Returns:**

- `Generator` - A generator containing the file content.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the directory for the file does not exist for the user.
- `NO_FILE_EXISTS` - If a file with the same path does not exist for the user.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string, or
    if  `chunk_size` is not an integer.

This will read a file from the database with the provided chunk size. Due to the database encrypting files in chunks,
there is a chunk size stored inside the database when the file was last uploaded/modified.

This ensures that the database can read the file and decrypt it properly.

## DirectoryInterface

---

Interface class allowing `FileDatabase` to access directory methods.

**This class is designed to be initialized by `FileDatabase` only.**

```python
dirs = file_db.dirs
dirs.make_dir("username", "/dir-path")
```

### `make_dir`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the directory to create.

**Returns:**

- `0` - If the directory is created successfully.
- `NO_USER` - If the user does not exist in the database.
- `DIR_EXISTS`: If the specified directory already exists for the specified user.
- `MISSING_PATH`: If 'dir_path' is empty.
- `INVALID_DIR_PATH`: If the 'dir_path' is not a valid directory path.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If 'dir_path' is not a strnig.

This creates a directory with the specified name and path for the user. The directories are not stored within the
underlying file system, but instead within the `sqlite3` database.

The paths are similar to a Unix path: (`/dir/file.txt`)

**Since version 1.1.0, creating sub-directories within another directory will isolate that directory**
**from the top level directory.**

### `remove_dir`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the directory to remove.

**Returns:**

- `0` - If the directory is successfully removed from the database.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS`: If the specified directory does not exist for the specified user.
- `ROOT_DIR`: If attempting to remove the root directory.
- `INVALID_DIR_PATH`: If the 'dir_path' is not a valid directory path.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If 'dir_path' is not a string.

This will remove a directory and all the files within it. Attempting to remove the root directory will be stopped.

**Since version 1.1.0, this does not remove the sub-directories, as those ones are isolated.**
**This will also permanently delete the directory and not mark it as deleted.**

### `list_dir`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **dir_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the directory to list.
- **list_deleted_only** ([_bool_](https://docs.python.org/3/library/functions.html#bool)) - Option to list only deleted files,
    if False, only lists non-deleted files.

**Returns:**

- `list[str]` - A list containing the files inside the directory.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` -  If the specified directory does not exist for the specified user.
- `INVALID_DIR_PATH` - If the 'dir_path' is not a valid directory path.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If 'dir_path' is not a string.

This will list a directory and show all the files within it. 

**Since version 1.1.0, this does not list the sub-directories, as these are isolated.**

### `get_dir_paths`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.

**Returns:**

- `list[str]` - All directory paths that the user has created.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIRS` - If no directories were found. (This means that the `/` directory normally present, is absent)

This will show all the directory paths that the user has created.

## DeletedFiles

---

Interface class allowing `FileDatabase` to access deleted files.

**This class is designed to be initialized by `FileDatabase` only.**

```python
deleted_files = file_db.deleted_files
deleted_files.restore_file("username", "/file-path", restore_which=0)
```

### `list_deleted`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the deleted file.
    (This can also be set to `:all:` to list all deleted files and their versions, then return a dictionary.)

**Returns:**

- `list[str] | dict` - A list or dictionary containing the deleted file timestamps. This is ordered as latest -> oldest.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the specified directory does not exist for the specified user.
- `NO_MATCHING_FILES` - If no files were found that were deleted.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string.

List all the timestamps of a deleted file. This is useful to see the order of when files were deleted, as index 
`0` shows the latest deleted file, and it counts up from there.

If the `file_path` is `:all:`, then it will return a dictionary containing all the deleted file paths, and a list of
the deleted timestamps as the value for that deleted file path.

### `restore_file`

---

*Implicit restore removed in 1.2.0*

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the file to restore.
- **restore_which** ([_int_](https://docs.python.org/3/library/functions.html#str)) - The deleted file version to restore.

**Returns:**

- `0` - If the file was successfully restored.
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the specified directory does not exist for the specified user.
- `NO_FILE_EXISTS` - If there are no matching files within the database. (Marked as deleted or not)
- `FILE_CONFLICT` - If a file already exists with the same path and is not deleted.
- `FILE_NOT_DELETED` - If no files were found that were deleted.
- `OUT_OF_BOUNDS` - If trying to access a non-existent deleted file.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string,
    or if `restore_which` is not an integer.

Restore a deleted file from the database. If the database finds only matching file, it will implicitly
restore that file. But if it finds more than one file, then it is required to set the `restore_which` parameter.

The order of deleted files is latest -> oldest, and can be retrieved with `DeletedFiles.list_deleted`.

### `true_delete`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **file_path** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The full path of the deleted file paths.
- **delete_which** ([_int_](https://docs.python.org/3/library/functions.html#int) **|** `:all:`) - The deleted version to delete.
    (This can also be set to `:all:` to list all deleted files and return a dictionary.)

**Returns:**

- `0` - If the deleted file version was successfully removed from the database
- `NO_USER` - If the user does not exist in the database.
- `NO_DIR_EXISTS` - If the specified directory does not exist for the specified user.
- `NO_MATCHING_FILES` - If no files were found that were deleted.
- `OUT_OF_BOUNDS` - If trying to access a non-existent deleted file.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `file_path` is not a string.
    This can also be set to `:all:` to delete all deleted file versions.

Fully delete a file from the database. This will make the file unrecoverable, as the data will be purged. 
If the database finds only matching file, it will implicitly
delete that file. But if it finds more than one file, then it is required to set the `delete_which` parameter.

The order of deleted files is latest -> oldest, and can be retrieved with `DeletedFiles.list_deleted`.

## APIKeyInterface

---

Interface class allowing `FileDatabase` to access API keys. The API keys are hashed before
being stored in the database. 

The only allowed key permissions are: `[create, read, update, delete, all]`.

**This class is designed to be initialized by `FileDatabase` only.**

```python
api_keys = file_db.api_keys
api_keys.create_key("username", ['create'], 'key-name', '2024-01-01 0:00:00')
```

### `get_key_owner`

---

**Parameters:**

- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The API key to use.

**Returns:**

- *username* - The username of the API key owner.
- `INVALID_APIKEY` - If the API key does not exist.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `api_key` is not a string.

This will get the username of the owner of the API key. If the database is externally modified, the key will 
exist but will not have a matching user ID. A warning will be logged and `INVALID_APIKEY` will be returned.

### `verify_key`

---

**Parameters:**

- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The API key to use.
- **permission_type** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The permission type
    to verify. 

**Returns:**

- `0` - If the API key is valid and has the matching permission.
- `INVALID_PERMISSION` - If the permission is invalid.
- `INVALID_APIKEY` - If the API key does not exist.
- `APIKEY_NOT_AUTHORIZED` - If the API key does not have the provided permission.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `api_key` or `permission_type`
     is not a string.

This will check the API key and check if it has the provided permission.

### `create_key`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **key_perms** ([_list_](https://docs.python.org/3/library/stdtypes.html#list)) - The list containing the key's
    permissions.
- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name to set for this key.
- **expires_on** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The date when the key expires.
    This must be in the format of `%Y-%m-%d %H:%M:%S`.

**Returns:**

- *API Key* - The API key created by the server. The prefix is: `syncServer-`.
- `INVALID_KEYPERMS` - If the key permissions include an unknown permission.
- `INVALID_DATETIME` - If the date time is in an invalid format.
- `DATE_EXPIRED` - If the provided expiry date has already passed.
- `NO_USER` - If the user does not exist in the database.
- `APIKEY_EXISTS` - If an API key with the same name exists.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `username`, `key_name`, 
    `expires_on` is not a string, or `key_perms` is not a list.

This creates a unique API key for the user with the permissions set. When the server returns this API key, it hashes the API
key before storing. This will ensure that the API key is viewable only once.

The function will explicitly disallow creating an API key with the permission `all`, this is used internally by the server script.

### `delete_key`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the key to delete.
**Returns:**

- `0` - If the API key was deleted successfully.
- `INVALID_APIKEY` - If the API key does not exist.
- `NO_USER` - If the user does not exist in the database.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `username` or `key_name` is not a string.

This will delete the API key with the name provided.

### `list_keys`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.

**Returns:**

- `list[str]` - The names of API keys that belong to the user.
- `[]` - An empty list if no API keys were found.
- `NO_USER` - If the user does not exist in the database.

**Raises:**

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If `username` is not a string.

This will **not** list the raw API keys, but only the key names. The server does not have access to the raw
API key after it is created, only the hashed version of it.

### `apikey_get_data`

---

**Parameters:**

- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The raw API key.

**Returns:**

- `list` - A list containing two items: the API key permissions (list) and the expiry date (str).
- `INVALID_APIKEY` - If the API key does not exist.

**Raises:** 

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `api_key` is not a string.

This function retrives the data from a raw API key. It retrieves the key permissions and expiry date.

### `keyname_get_data`

---

**Parameters:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The API key name.

**Returns:**

- `list` - A list containing two items: the API key permissions (list) and the expiry date (str).
- `NO_USER` - If the user does not exist in the database.
- `INVALID_APIKEY` - If the API key does not exist.

**Raises:** 

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) - If `username` or `key_name` is not a string.

This function retrives the data from an API key that belongs to a user. It retrieves the key permissions and expiry date.

### `check_expired`

---

**Parameters:**

**If using a key name:**

- **username** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The name of the user.
- **key_name** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The API key name.

**If using an API key:**

- **api_key** ([_str_](https://docs.python.org/3/library/functions.html#str)) - The raw API key.


**Returns:**

- `bool` - If the API key is expired or not.
- `NO_USER` - If the user does not exist in the database. Only returned if using an API key name.
- `INVALID_APIKEY` - If the API key does not exist.

**Raises:** 

- [**TypeError**](https://docs.python.org/3/library/exceptions.html#TypeError) -  If one of the following happens:
    - `api_key` is not a string.
    - `username` and `key_name` is not a string.
- [**ValueError**](https://docs.python.org/3/library/exceptions.html#ValueError) -  If one of the following happens:
    - An API key and key name was specified together.
    - No API key or key name was specified.
    - No username was provided when using a key name.

This function checks an API key or key name's expiry date, and compares it with the current date. If today is greater than
the stored date, then we return true.

---
