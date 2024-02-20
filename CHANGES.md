```
## First Release and Minor Fixes
**Changes:**
* **`server/__main__.py`**:
    * Added more runtime checking to prevent Exceptions from being raised.
    * Removed `newguy103-pycrypter` import as `ThreadManager` was not required.
    * Added error codes to more responses.
    * Added module docstring.
    * Replaced `if` statements with `match/case` statements for readability.
    * Allowed setting the flask app port on runtime with the `SYNCSERVER_PORT` environment variable.
* **`server/_db.py`**:
    * Added module docstring.
    * Created docstrings for `FileDatabase` class and its methods.
    * `FileDatabase` parameter `db_name` changed to `db_path` and default option is now `./syncServer.db`.

**Additions:**
* **`client`**:
    * Created `__init__.py` and `interface.py` to interact with the `syncserver` flask server.
    * `interface.py` has classes `FileInterface` and `DirInterface` to interact with the flask server.

**Other:**
* Created release `1.0.0` and uploaded to GitHub and PyPI as `newguy103-syncserver`.
```

## New Features and Overhaul
**Changes:**
* **`server/__main__.py`**:
    * Added the `/restore`, `/list-deleted` and `/true-delete` routes.
    * Planning to add support for API tokens.
    * Added some type handling to prevent errors.
* **`server/_db.py`**:
    * Added new parameter to `delete_file` called `permanent_delete`, as the default is now marking files as deleted.
    * Planning to remove the `token` parameter in the methods.
    * Also planning to move directory methods into another class.
* **`client/interface.py`**:
    * Added methods to handle deleted files for the client: `list_deleted`, `restore` and `remove_deleted`.

**Additions:**
* **`server`**:
    * Added support to mark files as deleted.
    * Added `DeletedFiles` class to handle deleted files.

**Other:**
* Planning to release v1.1 when all is ready.