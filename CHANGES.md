# Refactor project and merge client and server

**Version**: v0.1.0

**Date:** 24/03/2025

## Additions

**`/.python-version`**:

* Added pin to Python version. Currently pinned to 3.12.

**`/uv.lock`**:

* Switched from `requirements.txt` to `uv.lock` (readthedocs will still use requirements.txt).

## Changes

**`/pyproject.toml`**:

* Updated to add dependencies and metadata.

**`docker/Dockerfile`**:

* Updated to use `uv` instead of `pip`.

## Misc

* Will work on PySide6 application soon.
