# Create tests for database and create Dockerfile

**Version**: v0.1.0

**Date:** 20/03/2025

## Additions

**`/docker/Dockerfile, /.dockerignore`**:

* Created Dockerfile and .dockerignore to allow containerization.

**`/requirements.in, /requirements.txt`**:

* Updated requirements to include valkey.

**`/tests/database/`**:

* Added tests to check if the database is working properly, and to see if it
  works without FastAPI.

## Changes

**`/app/internal/database.py`**:

* `FolderMethods.remove_folder()` now removes folder in the function call.
* `SessionMethods.get_token_info()` and `revoke_session()` now raises an exception instead
  of returning `INVALID_SESSION` on invalid tokens.
* Made unexpected partial write log warning on `FileMethods.save_file()` properly log the values.
* `FolderMethods.create_folder()` now creates the folder regardless to prevent a problem where
  a user is created without a data directory on the host.
* `FolderMethods.rename_folder()` no longer refreshes the folder object as it canceled changes
  when renaming files inside it.

## Misc

* Will remove old `_db.py` and `_server.py` once rewrite is complete.
