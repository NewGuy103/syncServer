# Relicense under MPL-2.0 and cleanup repository

**Version**: v0.1.0

**Date:** 1/05/2025

## Additions

**`.github/workflows/docker-image.yml`**:

* Added Docker Image CI workflow to build Docker images on `ghcr.io`.

**`.github/workflows/project-docs.yml`**:

* Added Material For Mkdocs CI workflow to build documentation on GitHub Pages.

**`/README.md`**:

* Added more information to project readme.

**`docs/docs/app-overview.md`**:

* Renamed from `api-overview.md` and added up to date documentation.

**`docs/docs/database-component.md`**:

* Renamed from `server-db.md` and added up to date documentation.

## Changes

**`/LICENSE`**:

* Changed license from GNU GPL 3.0 to MPL 2.0.

**`docker/docker-compose.yml`**:

* Now sets `USE_VALKEY_CACHE=true` and `ENVIRONMENT=prod` by default.

**`docker/Dockerfile`**:

* Changed to not copy `./scripts` to the Docker image.

**`docs/docs/client-interface.md | docs/docs/gui-interface.md`**

* Removed PySide6 client documentation, too much of a hassle to document.

**`docs/requirements.in`**:

* Removed unused `requirements.in` file.

## Misc

* Planning to make Pytest run in a GitHub Actions workflow.
