## Welcome to the `newguy103-syncserver` documentation

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

Current latest version: 1.1.0

```python
>>> from syncserver.client import FileInterface
>>> file_interface = FileInterface('http://localhost:8561', 'username', 'password')
>>> file_interface.upload(['/path/to/local/file', '/remote/path'])
0
>>> file_interface.read('/remote/path')
b"..."
```

## Installation

```bash
pip install newguy103-syncserver
```

## Modules

- [Client Module](client-interface)
- [Server Database](server-db)
- [Server API](api-overview)
