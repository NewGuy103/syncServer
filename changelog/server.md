# Remove renamelog due to it being redundant and add more tests

**Version**: v0.1.0

**Date:** 2/05/2025

## Additions

**`app/server/main.py`**:

* Added check to set `debug=True/False` depending on environment.
* Added description, license info and contact info.

**`app/server/internal/config.py`**:

* Added validation to check if some variables are still the default 'helloworld' and
  raises a warning or error depending on environment.

**`app/server/models/common.py`**:

* Added `HTTPStatusError` model for OpenAPI documentation when raising a client error.

**`tests/database/test_deletedfiles_db.py`**:

* Added test cases for deleted files on the database.

**`tests/database/test_deletedfiles_db.py`**:

* Added test cases for user routes.

## Changes

**`app/server/internal/database.py`**:

* `get_admin_apikey_headers()` now returns a callable async function which takes in a list
  of key permissions.

**`app/server/main.py`**:

* No longers imports the Valkey client from `internal/cache.py`, and instead imports
  the `CacheProvider` instance and sets up Valkey depending on the `USE_VALKEY_CACHE` environment variable.

**`app/server/models/dbtables.py`**:

* Changed `cascade_delete=True` into `passive_deletes='all` due to sqlmodel updating the foreign key to
  null before deleting, causing a foreign key violation.

**`app/server/internal/database.py`**:

* Removed renamelog setup, the function never actually ran when attempting to recreate
  the "race condition" I found. Locks will stay though.
* Increased chunk size from 10 MiB to 25 MiB when saving files.

## Misc

* Added OpenAPI documentation for all of the methods.
