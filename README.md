# newguy103-syncserver

## Overview

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

## Installation

```bash
pip install newguy103-syncserver
```

## Client Module

### Usage:

The SyncServer Client module offers two main classes:

- **FileInterface**: Handles file-related operations.
- **DirInterface**: Manages directory-related operations.

### Example:

```python
from syncserver.client import FileInterface, DirInterface

# Initialize FileInterface or DirInterface
file_client = FileInterface(username="user", password="pass", server_url="http://localhost:5000")

# Use provided methods for file and directory operations
file_client.upload_file("path/to/local/file.txt", "remote/path/file.txt")
dir_client = DirInterface(username="user", password="pass", server_url="http://localhost:5000")
dir_client.create_directory("path/to/new/directory")
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
- `/read`: Read files
- `/create-dir`: Create directories
- `/remove-dir`: Remove directories
- `/list-dir`: List directory contents

**Note:** Ensure the server is running and accessible from the specified URL.

## Server (Module)

### Usage:

The module allows you to interact with `syncserver.server` databases without using the frontend.

### Example:
```python
from syncserver.server import FileDatabase

username = 'username1'
password = 'password1'

file_stream = open('./file.txt', 'r')

# Initialize database connection to local database file
file_database = FileDatabase(db_path='./syncServer.db')

# Set database protection
file_database.set_protection(True, cipher_key=b'pw')

# Verify user credentials
credentials_correct = file_database.verify_user(username, password)

# Add or remove a user from the database
file_database.add_user(username, password)
file_database.remove_user(username, password)

# Interact with files (requires username and password of a user)
file_database.add_file(
    username, password, 
    '/remote-filepath', file_stream
)
file_database.modify_file(
    username, password, 
    '/remote-filepath', file_stream
)

file_database.remove_file(
    username, password, 
    '/remote-filepath'
)
file_content = file_database.read_file(
    username, password, 
    '/remote-filepath'
)

# Interact with directories (requires username and password of a user)
file_database.make_dir(username, password, '/dir-path')
file_database.remove_dir(username, password, '/dir-path')

dir_listing = file_database.list_dir(username, password, '/dir-path')
```

Refer to the docstrings in the module for more documentation.
## Version

1.0.0