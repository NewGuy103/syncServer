# newguy103-syncserver

## Overview

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

Note from me: This is just a hobby project, and not supposed to be a production application. It's just a way to improve my skills and have something to work on.

Documentation can be found here: [https://syncserver.readthedocs.io/en/latest/](https://syncserver.readthedocs.io/en/latest/)

## Installation

```bash
pip install newguy103-syncserver
```

## Client Module

### Usage:

The client module offers `ServerInterface` as the preferred way to access the server, but also includes the old
`FileInterface`, `DirInterface` and `APIKeyInterface` classes for backwards compatibility.

### Example:
```python
from syncserver.client import ServerInterface

server_url = "http://localhost:8561"
interface = ServerInterface(
    server_url, username="alice", 
    password="yourPassword"
)

# API keys can be used and will be preferred over username/password
interface = ServerInterface(
    server_url, apikey="YOUR_APIKEY_HERE"
)

interface.files.upload([["./local-file.txt", "/remote-file.txt"]])
interface.dirs.create("/remote-dir")

interface.api_keys.create(
    "My API key", ["create", "read", "update", "delete"],
    "2025-03-14 8:00:00"
)
```

## Server (CLI)

### `syncserver-server` CLI:

The server runs as a Flask application and handles server routes. The name of the flask object in the script is `APP`.
```
$ python -m syncserver.server
$ syncserver-server
Enter database password [or empty if not protected]: 
```

The script listens on port `8561` by default.
You can change the port that the flask server listens on with the `SYNCSERVER_PORT` environment variable.
```bash
export SYNCSERVER_PORT=7009
```

### Routes:

- `/api/files/upload`: Upload files
- `/api/files/modify`: Modify files
- `/api/files/delete`: Delete files
- `/api/files/restore`: Restore deleted files
- `/api/files/list-deleted`: List deleted file versions
- `/api/files/remove-deleted`: Remove a deleted file permanently
- `/api/files/read`: Download files
- `/api/dirs/create`: Create directories
- `/api/dirs/remove`: Remove directories
- `/api/dirs/list`: List directory contents
- `/api/dirs/get-paths`: Show all directory paths
- `/api/keys/create`: Create an API key
- `/api/keys/delete`: Delete an API key
- `/api/keys/list-all`: List API key names
- `/api/keys/get-data`: Get API key data

**Note:** Ensure the server is running and accessible from the specified URL.

### `syncserver-server.db` CLI:

This is a way to manage the database configuration and users from the terminal.

```
$ syncserver-server.db --help
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
## Server (Module)

### Usage:

The module allows you to interact with `syncserver.server` databases without using the frontend.

### Example:
```python
from syncserver.server import FileDatabase
file_stream = open('./file.txt', 'rb')

# Initialize database connection to local database file
# Database path defaults to $XDG_DATA_HOME/syncServer-server/<version>/syncServer.db
file_database = FileDatabase(db_path='')

file_database.add_file("user", "/remote-file-path", file_stream)
file_database.dirs.make_dir("user", "/remote-dir-path")

file_database.api_keys.create_key("user", ['create'], "Main-API-Key", "2025-01-01 0:00:00")
```

Refer to the documentation for more information.


## Version

1.2.0
