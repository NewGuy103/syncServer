# Many changes and additions

**Version**: v0.1.0

**Date:** 15/03/2025

## Additions

**`/app/internal/database.py`**:

* Added `file_lock()` and `folder_lock()` to file and folder to allow returning a different type of lock.
* Added `check_for_parent_rename()` to check the Valkey cache for an renames that happened
  while waiting for a file upload to complete.
* Added `remove_folder()` and `rename_folder()`.

**`/tests/routers/test_folders.py`**:

* Added folder route tests.

**`/app/routers/folders.py`**:

* Added database calls to sync both the filesystem and the database.

## Changes

**`/app/models/dbtables.py`**:

* Now has `cascade_delete=True` for the one-to-many relationships.

**`/tests/conftest.py`**:

* Fix `conftest.py` not having fixtures due to my backup program causing a conflict.

**`/app/internal/database.py`**:

* File operations (excluding read) now acquire a lock on their parent folder during database operations.

## Misc

* Will remove old `_db.py` and `_server.py` once rewrite is complete.
