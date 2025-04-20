# Merge changes into a dedicated changelog/ directory

**Version**: v0.1.0

**Date:** 20/04/2025

## Additions

**`changelog/`**:

* Created `changelog/` directory to organize changelog for both client, server and other changes.

**`docker/docker-compose.yml`**:

* Added docker compose example for simpler setup.

## Changes

**`/CHANGES-*.md`**:

* Deleted `CHANGES.md` and `CHANGES-server.md`.

**`/pyproject.toml`**:

* Added optional dependency `client` to put the client UI dependencies.
* Updated dependencies.

## Misc

* Will clean up the repository after most client code is complete.
