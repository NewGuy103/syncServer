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
