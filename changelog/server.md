# Small rewrite to make Valkey server an optional requirement

**Version**: v0.1.0

**Date:** 29/04/2025

## Additions

**`app/server/internal/config.py`**:

* Added `USE_VALKEY_CACHE` environment variable.

**`app/server/internal/cache.py`**:

* Added `CacheProvider` class as a simple class to create locks either with Valkey or
  asyncio. Will probably refine soon.

**`app/server/routers/deletedfiles.py`**:

* Added `offset` parameter and a simple docstring to `GET /api/files/deleted/{file_path}`.

**`app/server/internal/database.py`**:

* Added `valkey_client` parameter to `async MainDatabase.setup()`.

**`.github/workflows/tests.yml`**:

* Added Pytest actions to run tests on every push.

## Changes

**`app/server/main.py`**:

* No longers imports the Valkey client from `internal/cache.py`, and instead imports
  the `CacheProvider` instance and sets up Valkey depending on the `USE_VALKEY_CACHE` environment variable.

**`app/server/models/dbtables.py`**:

* Changed `cascade_delete=True` into `passive_deletes='all` due to sqlmodel updating the foreign key to
  null before deleting, causing a foreign key violation.

**`app/server/internal/database.py`**:

* File, folder and delete locks now get their locks either from Valkey or a local asyncio Lock.
* Renamelog now uses a very simple get/set function from `CacheProvider` as a fallback
  if Valkey is not present.

## Misc

* Planning to use FastAPI's methods to write the OpenAPI spec of the server (responses, response_models, etc).
