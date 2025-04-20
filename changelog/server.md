# Fix some tests regarding database and tests

**Version**: v0.1.0

**Date:** 20/04/2025

## Additions

**`app/server/routers/auth.py`**:

* Added simple docstring explaining passing in `X-Api-Key` to `/token` and `/revoke`
  will throw an HTTP 403 Forbidden.

## Changes

**`app/server/models/folders.py`**:

* Now requires a PurePosixPath instead of a string as the data in the list.

**`app/server/routers/deletedfiles.py`**:

* GET `/api/files/deleted/` now returns a `list[PurePosixPath]` instead of a `list[str]`.

**`app/server/internal/database.py`**:

* `FolderMethods.list_folder_data()` and `rename_folder()` now uses `.options(selectinload)` to fix
  a bug where implicit IO happens.

## Misc

* Tests relating to server now uses the import `app.server` instead of `app`.
