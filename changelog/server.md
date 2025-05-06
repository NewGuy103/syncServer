# Add alembic migrations to project

**Version**: v0.1.0

**Date:** 6/05/2025

## Additions

**`tests/conftest.py`**:

* Now calls `SQLModel.metadata.create_all()` when setting up tests.

## Changes

**`app/server/internal/database.py`**:

* No longer calls `SQLModel.metadata.create_all()` in `setup()`, that is instead handled by alembic now.

## Misc

* Server API is complete, only thing that's left is to finish the client.
