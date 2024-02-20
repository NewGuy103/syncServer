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