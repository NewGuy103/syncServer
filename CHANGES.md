## More GUI updates and API changes

**Changes:**
* **`server/_db.py`**:
    * Fixed `api_keys.create_key` only checking the date, and not the datetime.
    * Changed `get_key_perms` into two subfunctions: `apikey_get_data` and `keyname_get_data`.
    * `api_keys.list_keys` now return an empty list instead of `NO_AVAILABLE_APIKEYS` when no keys are found.
* **`server/__main__.py`**:
    *  `/api/files/upload`, `/api/files/modify` and `api/files/delete` now return the 
    error data directly if only one file was passed.
    * Removed some `print` statements in server code.
    * Fixed `SERVER_ERROR` log in `/api/files/read` referencing `remove_file` instead of `read_file`.
    * Removed `NO_AVAILABLE_APIKEYS` response in `/api/keys/list-all`.
    * Changed `/api/keys/get-perms` to `/api/keys/get-data`.
    * `main` now returns the global `APP` object.
    * Moved the database password asking code into the `if __name__ == '__main__'` at the bottom.
* **`client/interface.py`**:
    * `ServerInterface` now logs and re-raises exceptions when connecting to the server. It also raises
    a `ValueError` if authorization fails in an expected way, and `RuntimeError` if unexpected.
    * Fixed `_FileInterface.upload`'s exception message having an additional `[{i}]`.
    * `_APIKeyInterface.get_key_perms` is now `get_key_data`, and can take either an API key or key name.
* **`client/gui.py`**:
    * Changed file manager dialog to reference the result as the error dictionary directory following
    the changes on the API.
    * Removed the check on the login GUI that prevents using client side 
    encryption when using an API key.
    * Removed redundancy in `StartLogin.start_login` by passing the username/password and API key,
    but instead setting one login option to be an empty string, so the `ServerInterface` class uses
    the not-empty option.
    * Client side encryption now uses a separate password, allowing to use API key login
    while also using encryption. (Encryption functionality is not complete yet)
    * Removed the URL passed to `StartLogin` when running the script as an app.

**Additions:**
* **`server/_db.py`**:
    * Added key expiry and checking if key expiry date is already expired. Returns `DATE_EXPIRED` when this happens.
    * Added `check_expired` function to do key expiry checking. Takes in either an API key or key name + username.
    * Added `apikey_get_data` and `keyname_get_data` functions to get the data of an API key.
    * Added checking to prevent the `all` permission from being a valid permission in `api_keys.create_key`.
* **`server/__main__.py`**:
    * Added expiry checking in the `_verify` function.
    * Added permission check bypass by setting `_api_permission_type` to `all`.
    * Added `DATE_EXPIRED` response in `/api/keys/create`.
    * `/api/keys/get-data` can now take in either an API key or key name, but cannot take both at the same time.
* **`client/cui.py`**:
    * Added the directory manager and API key manager dialogs.
* **`client/gui.py`**:
    * Added the directory manager and API key manager dialogs.
    * Added check to purging all deleted files, checking if there are files available.
    * The server URL inputbox can now be controlled by passing `url='<url>'` to `StartLogin`.
    * Setting environment variable `SYNCSERVER_URL` changes the URL in the inputbox if `url` is not
    passed to `StartLogin`.
    * API key logins now require the `read` permission to be provided by the API key.
    * Client side encryption will show a warning if no password is provided and will
    disable encryption.

**Other:**
    * Will start working on client side encryption.
    * GUI is almost completed, might add small fixes.
    * `read` permission requirement is only for the GUI client.
