# Server API Overview

---

This page will define how to call the REST APIs provided in `syncserver.server`.

The base URL for all API endpoints is:

```
http://localhost:$SYNCSERVER_PORT
```

All the endpoints only accept JSON (except for `/upload` and `/modify`).

## Authentication

---

All API requests require authentication. You can use these headers for username-password authentication:

- **syncServer-Username**: YOUR-USERNAME
- **syncServer-Token**: YOUR-PASSWORD

Or an `Authorization` header for API key authentication:

- **Authorization**: YOUR-API-KEY

Failing to authenticate or providing invalid credentials will result in these responses:

- **INVALID_APIKEY:**
  You passed an invalid API key to the server.

- **APIKEY_NOT_AUTHORIZED:**
  The API key you passed doesn't have the permission required to access this endpoint.

- **INVALID_CREDENTIALS:**
  Your username or password is incorrect.

## File Endpoints

### `/upload`

---

Send a file to the server.

API key permission required: `create`

**Parameters:**

- Form data including a file, and the field name. (`/remote_name=@local_filename`)

**Error Codes and Meaning:**

- **MISSING_FILES:** No files were provided in the request for upload.
    - The server did not receive any files, please check if the file data is being properly passed.

- **NO_REMOTE_PATH:** A remote path was not specified for the file.
    - The remote path was not passed when uploading. The server gets the parameter name as the remote path of the file: `/remote-path=@local-file.txt`.

- **INVALID_CONTENT:** The parameter name is not a proper data type.
    -  The server does not accept any parameter name type other than binary or string.

- **EMPTY_STREAM:** An empty file stream was passed to the server.
    - The server attempted to read from an empty file stream, so it rejects the file.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **FILE_EXISTS:** The file already exists on the server.
    - The server has detected a file with the same name exists on the server, so it will not write to prevent data being overwritten. The `/modify` endpoint writes to existing files on the server.

### `/modify`

---

Modify an existing file on the server.

API key permission required: `update`

**Parameters:**

- Form data including a file, and the field name. (`remote_name=@local_filename`)

**Error Codes and Meaning:**

- **NO_REMOTE_PATH:** A remote path was not specified for the file.
    - The remote path was not passed when uploading. The server gets the parameter name as the remote path of the file: `/remote-path=@local-file.txt`.

- **INVALID_CONTENT:** The parameter name is not a proper data type.
    - The server does not accept any parameter name type other than binary or string.

- **EMPTY_STREAM:** An empty file stream was passed to the server.
    - The server attempted to read from an empty file stream, so it rejects the file.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **NO_FILE_EXISTS:** The file does not exist on the server.
    - The server could not find a file with the same name exists on the server, so it will not write. The `/upload` endpoint writes to new files to the server.

### `/delete`

---

Mark a file removed in the server, or delete it permanently. Marking it as deleted makes it so that referencing the deleted file
on any other endpoint using the file path will only reference the non-deleted file.

API key permission required: `delete`

**Parameters:**

- `file-paths`: A list of the remote paths to delete.
- `true-delete`: True/False depending if you want to directly delete the file or mark it deleted.

**Error Codes and Meaning:**

- **MISSING_FILEPATHS:** No file paths were provided in the request for upload.
    - The server did not receive the JSON list, please check if the parameter is `file-paths`.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **NO_FILE_EXISTS:** The file does not exist on the server.
    - The server could not find a file with the same name exists on the server, so it will not write. The `/upload` endpoint writes to new files to the server.

- **EMPTY_PATHLIST:** The file path list is empty.
    - This means that the provided list has no items. This can happen when passing the wrong data type into the list, and the server ends up filtering it, making the list have zero items.

- **MISSING_PARAMETER:** The `true-delete` parameter is missing.
    - Check if the JSON key is spelled `true-delete` and not `true_delete`.

- **INVALID_PARAMETER:** The `true-delete` parameter is not True or False.
    - Check if the JSON value is true/false.

- **INVALID_CONTENT:** The `file-paths` parameter is not a list.
    - Check if the JSON value is a list/array.

### `/restore`

---

Restore a file that was marked deleted.

API key permission required: `update`

**Parameters:**

- `file-path`: The file path to restore.
- `restore-which`: An integer indicating the version of the file to restore. This uses `latest -> oldest` setup
    where `0` is the latest deleted file, and it counts up from that. See `/list-deleted` for information.
  
**Error Codes and Meaning:**

- **MISSING_FILEPATH:** No file path was provided in the request for upload.
    - The server did not receive the file path please check if the parameter is `file-path`.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the 
    directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **FILE_CONFLICT:** A file exists that isn't deleted.
    - Check if a file exists within the server with the same path, and remove that file.

- **FILE_NOT_DELETED:** No files have been deleted with that path.
    - This means that no matching files were found that were deleted.

- **OUT_OF_BOUNDS:** Attempted to access a file out of bounds.
    - This means you tried to restore a file version that wasn't listed. (e.g. deleting one file
    but trying to restore the second deleted version, which does not exist)

- **MISSING_PARAMETER:** The `restore-which` parameter is missing.
    - Check if the JSON key is spelled `restore-which` and not `restore_which`.

- **INVALID_PARAMETER:** The `restore-which` parameter is not an integer.
    - Check if the JSON value is an integer.

- **INVALID_CONTENT:** The `file-path` parameter is not a string.
    - Check if the JSON value is a string.

### `/list-deleted`

---

List the deleted file versions, or list all deleted file versions.

Returns a JSON object containing either a list or dictionary on success.

API key permission required: `read`

**Parameters:**

- `file-path`: The file path of the deleted files. Or `:all:` to list all.

**Error Codes and Meaning:**

- **MISSING_FILEPATH:** No file path was provided in the request for upload.
    - The server did not receive the file path, please check if the parameter is `file-path`.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the 
    directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **NO_MATCHING_FILES:** No files have been deleted with that path.
    - This means that no matching files were found that were deleted.

- **INVALID_CONTENT:** The `file-path` parameter is not a string.
    - Check if the JSON value is a string.

### `/remove-deleted`

---

Irreversibly delete a file marked as deleted from the database.

API key permission required: `delete`

**Parameters:**

- `file-path`: The file path of the deleted files.
- `delete-which`: An integer indicating the version of the file to restore. This uses `latest -> oldest` setup
    where `0` is the latest deleted file, and it counts up from that. 
    
    Optionally, you can also set this to `:all:` to delete all matching files that were 
    marked as deleted. See `/list-deleted` for information.

**Error Codes and Meaning:**

- **MISSING_FILEPATH:** No file path was provided in the request for upload.
    - The server did not receive the file path, please check if the parameter is `file-path`.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the 
    directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **NO_MATCHING_FILES:** No files have been deleted with that path.
    - This means that no matching files were found that were deleted.

- **MISSING_PARAMETER:** The `delete-which` parameter is missing.
    - Check if the JSON key is spelled `delete-which` and not `delete_which`.

- **INVALID_PARAMETER:** The `delete-which` parameter is not an integer.
    - Check if the JSON value is an integer.

- **INVALID_CONTENT:** The `file-path` parameter is not a string.
    - Check if the JSON value is a string.

- **OUT_OF_BOUNDS:** Attempted to access a file out of bounds.
    - This means you tried to delete a file version that wasn't listed. (e.g. deleting one file
    but trying to delete the second deleted version, which does not exist)
  
### `/read`

---

Read a file from the server.

Returns the file content in binary when successful.

API key permission required: `read`

**Parameters:**

- `file-path`: The file path of the file to read from

**Error Codes and Meaning:**

- **MISSING_FILEPATH:** No file path provided to read from.
    - The server did not get the file path parameter. Please check if the parameter is `file-path`.

- **INVALID_CONTENT:** The parameter name is not a proper data type.
    - The server does not accept any parameter name type other than binary or string.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - Within the parameter name, you can put the directory name in the syntax of a Unix path. If the directory path does not exist, then it will not continue writing: `/no-such-dir/remote-path`.

- **NO_FILE_EXISTS:** The file does not exist on the server.
    - The server could not find a file with the same name exists on the server, so it will not write. The `/upload` endpoint writes to new files to the server.


## Directory Endpoints

---

### `/create-dir`

---

Create a directory to put files into. This allows you to set the remote path like this: `/dir/somefile`

*This directory does not interact with the underlying file system, but an emulated one within the database.*

API key permission required: `create`

**Parameters:**

- `dir-path`: Directory path to create. This is similar to a file path.

**Error Codes and Meaning:**

- **MISSING_DIRPATH:** No directory path provided to create.
    - The server did not get the dir path parameter. Please check if the parameter is `dir-path`.

- **INVALID_CONTENT:** The directory name is not a proper data type.
    - The server does not accept any directory name type other than binary or string.

- **DIR_EXISTS:** The directory path already exists.
    - The directory was found and already exists, so the server does not continue writing. 
    `/remove-dir` can be used to remove directories and all the files within it.

- **MISSING_PATH:** The target path is missing.
    - This means that no directory path was actually provided. (i.e an empty string.)

- **INVALID_DIR_PATH:** The directory path is malformed or invalid.
    - The directory path could have characters before the first forward slash (like `chars/dir1`) and is treated as malformed.

### `/remove-dir`

---

Delete a directory and all it's files. 

*Currently in version 1.1.0, this permanently deletes the directory, and does not mark them as deleted.* 
*Also applies to deleted files within the directory.*

API key permission required: `delete`

**Parameters:**

- `dir-path`: Directory path to delete.

**Error Codes and Meaning:**

- **MISSING_DIRPATH:** No directory path provided to create.
    - The server did not get the dir path parameter. Please check if the parameter is `dir-path`.

- **INVALID_CONTENT:** The directory name is not a proper data type.
    - The server does not accept any directory name type other than binary or string.

- **NO_DIR_EXISTS:** The directory path does not exist.
    - The directory wasn't found, so the server does not continue writing. `/create-dir` can be used to create directories.

- **ROOT_DIR:** Attempted to delete the root directory.
    - This means that you attempted to set `dir-path` to `/`, which is a safeguard to prevent recursively deleting 
    everything that your user account owns. 

- **INVALID_DIR_PATH:** The directory path is malformed or invalid.
    - The directory path could have characters before the first forward slash (like `chars/dir1`) and is treated as malformed.

### `/list-dir`

---

List all the files inside a directory.

*Currently in version 1.1.0, this does not list subfolders.*

API key permission required: `read`

**Parameters:**

- `dir-path`: Directory path to list.

**Error Codes and Meaning:**

- **MISSING_DIRPATH:** No directory path provided to create.
    - The server did not get the dir path parameter. Please check if the parameter is `dir-path`.

- **INVALID_CONTENT:** The directory name is not a proper data type.
    - The server does not accept any directory name type other than binary or string.

- **DIR_EXISTS:** The directory path already exists.
    - The directory was found and already exists, so the server does not continue writing. `/remove-dir` can be used to remove directories and all the files within it.

- **INVALID_DIR_PATH:** The directory path is malformed or invalid.
    - The directory path could have characters before the first forward slash (like `chars/dir1`) and is treated as malformed.

## API Key Endpoints

---

### `/api/create-key`

---

Create an API key with the specified permissions.

API key permission required: `create`

**Parameters:**

- `key-name`: The name of the API key.
- `key-permissions`: The permissions of the API key. This can be: `['create', 'read, 'update', 'delete']`.
- `key-expiry-date`: The date of when the key will expire. The format is: `%Y-%m-%d %H:%M:%S`

**Error Codes and Meaning:**

- **INVALID_TYPE:** Invalid type for a parameter.

      This is returned when the one following happens:

      - `key-name` is not a string.
      - `key-permissions` is not a list.
      - `key-expiry-date` is not a string.
    
- **MISSING_KEYNAME**, **MISSING_KEYPERMS**, **MISSING_EXPIRYDATE**: Missing parameter.
    - This is returned if one of the parameters is missing.

- **INVALID_KEYPERMS:** Invalid key permission.
    - One of the permissions is not in the allowed permissions: `['create', 'read, 'update', 'delete']`.

- **INVALID_DATETIME:** Invalid datetime format.
    - The key expiry date is not in the format `%Y-%m-%d %H:%M:%S`.

- **APIKEY_EXISTS:** Another API key exists with the same name.
    - Another API key was created before. You can rename the key or delete the original key.

### `/api/delete-key`

---

Delete an API key and render it unusable.

API key permission required: `delete`

**Parameters:**

- `key-name`: The name of the API key.

**Error Codes and Meaning:**

- **INVALID_TYPE:** Invalid type for `key-name`.
      - This is returned when `key-name` is not a string.

- **MISSING_KEYNAME**: Missing parameter.
    - This is returned if the parameter `key-name` is missing.

- **INVALID_APIKEY:** The API key is invalid or does not exist.
    - This means that the API key with the name provided does not exist, or is invalid.

### `/api/list-keys`

---

List API key names. **This will not list the raw API keys.**

API key permission required: `read`

**Error Codes and Meaning:**

- **NO_AVAILABLE_APIKEYS:** No API keys exist.
    - This means that you have not created any API keys yet or deleted all your keys.

---
