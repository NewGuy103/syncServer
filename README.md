# newguy103-syncserver

## Overview

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

Documentation can be found here: https://github.com/NewGuy103/syncServer/wiki

## Installation

```bash
pip install newguy103-syncserver
```

## Client Module

### Usage:

The SyncServer Client module offers three main classes:

- **FileInterface**: Handles file-related operations.
- **DirInterface**: Manages directory-related operations.
- **APIKeyInterface**: Manages API key-related operations.

### Example:

```python
from syncserver.client import FileInterface, DirInterface
file_client = FileInterface(username="user", password="pass", server_url="http://localhost:8561")

# Use provided methods
file_client.upload([['~/Documents/my-file', '/my-file']])

dir_client = DirInterface(username="user", password="pass", server_url="http://localhost:8561")
dir_client.create("/Docs")

apikey_client = APIKeyInterface(username="user", password="pass", server_url="http://localhost:8561")
apikey_client.create_key(key_name="Main-API-Key", key_permissions=['create'], key_expiry_date="2025-01-01 0:00:00")
```

## Server (Script)

### Usage:

The server runs as a Flask application and handles file synchronization routes.
```
$ python -m syncserver.server
$ syncserver-server
Enter database password [or empty if not protected]: 
```

You can change the port that the flask server listens on with the `SYNCSERVER_PORT` environment variable.
```bash
export SYNCSERVER_PORT=7009
```

### Routes:

- `/upload`: Upload files
- `/modify`: Modify files
- `/delete`: Delete files
- `/restore`: Restore deleted files
- `/list-deleted`: List deleted file versions
- `/remove-deleted`: Fully remove a deleted file
- `/read`: Read files
- `/create-dir`: Create directories
- `/remove-dir`: Remove directories
- `/list-dir`: List directory contents
- `/api/create-key`: Create an API key
- `/api/delete-key`: Delete an API key
- `/api/list-keys`: List API key names

**Note:** Ensure the server is running and accessible from the specified URL.

## Server (Module)

### Usage:

The module allows you to interact with `syncserver.server` databases without using the frontend.

### Example:
```python
from syncserver.server import FileDatabase
file_stream = open('./file.txt', 'rb')

# Initialize database connection to local database file
file_database = FileDatabase(db_path='./syncServer.db')

file_database.add_file("user", "/remote-file-path", file_stream)
file_database.dirs.make_dir("user", "/remote-dir-path")

file_database.api_keys.create_key("user", ['create'], "Main-API-Key", "2025-01-01 0:00:00")
```

Refer to the documentation for more information.

## Version

1.1.0
