# Very simple bug fix

**Version**: v0.1.0

**Date:** 25/04/2025

## Additions

None.

## Changes

**`app/server/routers/auth.py`**:

* GET/DELETE `/api/auth/api_keys/{key_name}` now matches all paths (`{key_name:path}`) to
  prevent unexpected errors when an API key name has a slash (`/`).

## Misc

* None.
