## More updates for 1.1.0

**Changes:**
* **`server/_db.py`**:
    * Separated database version from application version. (`db_version` inside `_load_conf`)
    * Removed optional `hash_pepper` and `password_pepper` parameters from `set_protection` call, 
    setting these can be done with `--edit-config`.
    * Separated directory methods into a class named `DirectoryInterface` in the same style as the other classes.
    * `DeletedFiles.true_delete` now uses `:all:` for deleting all deleted files compared to `all`.
* **`server/__main__.py`**:
    * Fixed `restore-which` parameter in `/restore` not taking an integer.
    * Directory methods now reference the initialized directory interface class. (`self.dirs`)
    * Deleted files listing and deletion now use `:all:` to target all deleted files.
* **`README.md`**:
    * Update README to reflect v1.1.0.

**Additions:**
* **`server/_db.py`**:
    * Added command line options: `--database-protected`, `--edit-vars`, `--set-protection` and `--recover-key`.
        These can be used for managing the database locally.
    * Added `recovery_mode` option to `FileDatabase`, which only reads the config variables and does not 
        initialize the database further.
* **`docs/`**:
    * This will be the directory for the documentation.
    
**Other:**
* Updating documentation for v1.1.0. This will use [Read The Docs](https://readthedocs.io) now.
