## Changes in codebase and new client GUI

**Changes:**
* **`server/_db.py`**:
    * Changed type annotation and runtime type checking from `bytes | str` to `str` since we use a JSON endpoint.
    * Changed `list_dir` to not list deleted files by default, can now be toggled to only list
    deleted files using the `list_deleted_only` parameter.
    * Removed implicit restore for `restore_file` and changed default parameter to `0`.
    * Fixed wrong `if` statement in `true_delete`.
    * Changed CLI tempfile to have `.py` as the suffix, because we represent a Python dictionary in nano. (No
    python code is being ran, just using `ast.literal_eval` to safely parse the dictionary)
* **`server/__main__.py`**:
    * Grouped each endpoint into `/api`:
        * `/upload`, `/modify`, `/delete`, `/read`, `/restore`, `/remove-deleted` and `/list-deleted` has been moved
        into `/api/files`.
        * `/create-dir`, `/remove-dir` and `/list-dir` has been moved into `/api/dirs`, without the `-dir` suffix.
        * `/api/create-key`, `/api/delete-key` and `/api/list-keys` has been moved into `/api/keys`, without the
        `-key` suffix, however `/api/list-keys` has been moved into `/api/keys/list-all`.
    * `/api/dirs/list` now has parameter `list-deleted-only` to list deleted files only.
    * Kept the original name for all endpoints for backwards compatibility, but expect these to 
    be removed in a future version.
    * Failed username/password authentication attempts now return a 401 instead of a 400.
* **`client/interface.py`**:
    * Changed type annotation and runtime type checking from `bytes | str` to `str`.
    * Removed `ServerErrorResponse` exception due to it being redundant, the server already returns JSON
    stating it hit a server error.
    * Removed `_check_code`, same reason for `ServerErrorResponse`.
    * Centralized the 3 interfaces into a new `ServerInterface` class.
    * Changed the interface classes be private and to have `ServerInterface` as a parent, but also added backwards
    compatibility by using the original class name.

**Additions:**
* **`server/_db.py`**:
    * Added `get_dir_paths` function to get all available directories.
    * Added `all` API key permission.
    * Added `get_key_perms` to get the permissions of an API key.
* **`server/__main__.py`**:
    * Added `/auth/check` endpoint to check authentication headers if valid or not.
    * Added `/api/keys/get-perms` to get API key permissions.
    * Added `/api/dirs/get-paths` to get all directory paths.
    * Added type checking to see if the authentication headers are strings.
    * Added implicit conversion of remote path strings to `/<filename>` if the string is only `<filename>` for
    `/api/files/upload` and `/api/files/modify`.
* **`client/interface.py`**:
    * Added new `ServerInterface` class, which puts all the 3 interfaces into one class, and checks if the credentials
    are valid when initializing.
    * Added checking to see if `remove_deleted` parameter `delete_which` is a positive integer or is `:all:`
    * Added `get_dir_paths` to get all directory paths.
    * Added `get_key_perms` to get the permissions of an API key.
    * Added `ClientEncryptionHandler` as a function to create encrypted and decrypted files and store them in 
    `~/.local/share/syncServer-client/<version>` or `$XDG_DATA_DIR/syncServer-client/<version>`. Uses AES-GCM-256 
    and PBKDF2HMAC, and implements salting, hash and password peppers.
    * Added logging handler as `logger`.
* **`client/__init__.py`**:
    * Added `ClientEncryptionHandler` and `ServerInterface` as an importable class.
* **`client/cui.py`**:
    * Added `cui.py` to store all the PyQt5 GUI classes.
* **`client/gui.py`**:
    * Added `gui.py` as the main client GUI.

**Other:**
* Added type annotations for variables and return types.
* GUI is incomplete, currently in the process of completing it.