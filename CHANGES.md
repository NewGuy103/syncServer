## Updates to add support for API Tokens
**Changes:**
* **`server/__main__.py`**:
    * Changed the main script to use individual functions with a global `database` method.
    * Changed the `case _:` blocks to return the `SERVER_ERROR()` constant.
    * Changed `_verify_credentials` to `_verify` to support API tokens.
    * Updated logging messages to include the route.
    * Changed `/remove` route to `/delete` route.
* **`server/_db.py`**:
    * Removed subclassing for `DeletedFiles`.
* **`client/interface.py`**:
    * Changed `__init__` for interface methods to use a `self.headers` variable instead of manually defining it in each method.

**Additions:**
* **`server/__main__.py`**:
    * Added support for API tokens. This can now be used to replace the `syncServer-` credentials headers.
    * Added `SERVER_ERROR()` constant that represents a server error message in JSON.
    * Added `/api`, `/api/create-key`, `/api/delete-key` and `/api/list-keys` methods.
* **`server/_db.py`**:
    * Added `APIKeyInterface` class designed to be initialized by `FileDatabase` to support API keys.
    * Added a simple command line interface that allows you to edit the configuration for the database.
    It can be accessed with `syncserver.server --edit-config`.
    * Added simple username blacklist in `add_user` to prevent unexpected behaviour within the API.
* **`client/__init__.py`**:
    * Added `APIKeyInterface` to import and `__all__`.
* **`client/interface.py`**:
    * Added `APIKeyInterface` to support API key authentication, and `api_key` parameter for all interface methods.

**Other:**
* API Routes and client interface methods will prioritize API tokens compared to the traditional `syncServer-` authentication method.
* Changed version number to 1.1.0 
* Release 1.1.0 will be released once thoroughly tested.
