# Add alembic migrations to project

**Version**: v0.1.0

**Date:** 6/05/2025

## Additions

**`/alembic.ini | migrations/`**:

* Added alembic migrations to project.

**`/pyproject.toml | /uv.lock`**:

* Added `alembic` as a dependency.

**`docker/Dockerfile`**:

* Added `alembic.ini`, `migrations/` and `scripts/` to image.

**`docker/docker-compose.yml`**:

* Added example healthchecks to cache and database images.
* Added `prestart` service to automatically call `scripts/migrations.sh`.
* Added `depends_on:` block to the app image.

**`scripts/migrations.sh`**:

* Added script to run any alembic migrations required.

**`docs/docs/database-component.md`**:

* Added migrations section.

**`.github/workflows/tests.yml`**:

* Added `contents: read` permissions to tests action.

## Changes

**`docker/Dockerfile`**:

* Changed how the image gets the `uv` executable to the proper way by using `COPY --from`.

## Misc

* Releasing v0.1.0 is almost ready, only need to complete the client GUI.
