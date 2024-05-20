## Improve server script to work with production WSGI servers

**Additions:**

**`server/_server.py`**:

* Added `create_app` function, initializes the app by creating the `FileDatabase` object and storing it in app config,
then returns the global app for WSGI servers.
* Added `teardown_app` to shut down the server and close database. Runs on exit.
* Added error code 500 handler to return a JSON server error object instead of HTML.
* Added a before request handler to get the app database and store in flask's `g` object.

**`server/_db.py`**:

* Added method `close` to clean up the database and mark it as closed.

**Changes:**

**`server/_server.py`**:

* `_verify` now raises a `RuntimeError` when using this without an app context.
* All `SERVER_ERROR()` calls have been replaced with `flask.abort(500)`.
* Removed old routes, now all routes use the `/api` path.
* Removed global database object in favor of flask's `g` to improve compatibility with WSGI servers.

**`server/__main__.py`**:

* Imports `create_app` from `_server` instead of doing app init.

**Other:**
* Will release version 1.3.0 after testing.
