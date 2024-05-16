## Welcome to the `newguy103-syncserver` documentation

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

Note from me: This is just a hobby project, and not supposed to be a production application. It's just a way to improve my skills and have something to work on.

Current latest version: 1.2.0

```python
>>> from syncserver.client import ServerInterface
>>> server_interface = ServerInterface(
    'http://localhost:8561', username='username', password='password')
>>> server_interface.upload(['/path/to/local/file', '/remote/path'])
0
>>> server_interface.read('/remote/path', 'local-path.txt')
0
```

## Installation

```bash
pip install newguy103-syncserver
```

## Modules

- [Client Module](client-interface)
- [Server Database](server-db)
- [Server API](api-overview)
