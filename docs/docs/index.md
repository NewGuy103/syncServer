## Welcome to the `newguy103-syncserver` documentation

### NOTE

This documentation is deprecated. You probably want the [FastAPI](https://github.com/NewGuy103/syncServer) version of this app.

Updated documentation can be found on [GitHub Pages](https://newguy103.github.io/syncServer/).

This documentation will still be kept, but the flask version of this app will not be updated.

**newguy103-syncserver** is a Python package designed to simplify file synchronization operations through a server-client architecture. The package provides both the server, built on Flask, and a client module for interacting with the server.

Note from me: This is just a hobby project, and not supposed to be a production application. It's just a way to improve my skills and have something to work on.

Current latest version: 1.3.0

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

(Note: This will install the FastAPI version of the app.)

```bash
pip install newguy103-syncserver
```

## Modules

- [Client Module](client-interface.md)
- [Client GUI](gui-interface.md)
- [Server Database](server-db.md)
- [Server API](api-overview.md)