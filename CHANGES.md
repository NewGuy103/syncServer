## Patch recursive cursor use and implement transaction manager

**Additions:**

**`server/_db.py`**:

* Add `transaction` context manager function to start a transaction and return a cursor, and close it when done.
* Added experimental `dict_cache` switch to `FileDatabase`, allowing you to cache user information in memory in a dictionary.
* Added `journal_mode=WAL` and `synchronous=FULL` pragma when initializing `FileDatabase`.
* Added `key_recover` to `DatabaseAdmin` as a way to recover the original encryption key.
* Added `update_encryption` to `DatabaseAdmin`, which updates file data for all uploaded files using the key provided.
    If a new key is not provided, it will simply decrypt the files using the old key.

**Changes:**

**`server/_db.py`**:

* Updated database version to 1.2.0. (Schema may still change between commits)
* Moved `set_protection` and `save_conf` to `DatabaseAdmin`, initialized by `FileDatabase`.
* Centralized `_get_userid` and `_get_dirid` to reduce boilerplate code and allow an easy way to change behaviour.
* Update `--set-protection` option to include an entry for the recovery key path.
* Remove `self.cursor` to prevent further recursive cursor use.

**Other:**
* Make sure the server is down before running `update_encryption`, as the server might still be using the old encryption key.
* Planning to make the server script use flask's `g` object for the database.
