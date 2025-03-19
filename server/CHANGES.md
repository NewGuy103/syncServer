# Implement deleted files and bug fixes

**Version**: v0.1.0

**Date:** 19/03/2025

## Additions

**`/app/internal/constants.py`**:

* Added `OFFSET_INVALID` return code.

**`/app/internal/database.py`**:

* Implemented deleted files as `DeletedFiles`, accessible through `database.files.deleted_files`.
* Added `FileMethods.lookup_database_for_file()` which is used by `DeletedFileMethods`.
* Added logic to rename child folders when renaming a folder.

**`/app/models/common.py`**:

* Created `GenericSuccess` as a simple response model.

**`/app/models/files.py`**:

* Created this file for any models relating to the `/files` router.

**`/tests/conftest.py`**:

* Added hook to order test in a custom order instead of A-Z.

**`/tests/routers/test_deletedfiles.py`**:

* Added folder route tests.

## Changes

**`/app/internal/database.py`**:

* Lock methods now prefix themselves as `filelock/folderlock/deletelock:`.
* Removed `DeletedFileMethods.check_file_deleted()`
* Getting folder contents now properly show the full path starting from `/` instead of just the name.

**`/app/models/dbtables.py`**:

* Now has `cascade_delete=True` for the one-to-many relationships.

**`/routers/files.py`**:

* Main router has been moved to `/routers/main.py`.

**`/tests/routers/folders.py`**:

* Getter tests now check content with a `/` and using `in` instead of direct comparison.

## Misc

* Will remove old `_db.py` and `_server.py` once rewrite is complete.
* Most routers now return `GenericSuccess` (`{"success": true}`).
