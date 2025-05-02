# Update docs and metadata

**Version**: v0.1.0

**Date:** 2/05/2025

## Additions

**`docker/Dockerfile`**:

* Added metadata labels to image.

## Changes

**`docker/docker-compose.yml`**:

* Commented the `build` block to make the compose file reference the ghcr.io image by default.

**`/ruff.toml`**:

* Pinned target version to 3.13.

**`docs/docs/app-overview.md | docs/docs/database-component.md`**:

* Updated links to point to the exact file in the repository.

## Misc

* Old documentation ([readthedocs](https://syncserver.readthedocs.io)) will stay as an archive
  to the old flask app. The `old-flask-app` branch will be archived too.
* Planning to release v0.1.0 once everything is complete.
