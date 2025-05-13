# Implement multiple accounts and finish client UI

**Version**: v0.1.0

**Date:** 13/05/2025

## Additions

**`pyside6_ui/add_account_dialog.ui` | `app/client/ui/add_account_dialog.py`**:

* Added dialog to handle adding new accounts.

**`scripts/generate-client-ui.py`**:

* Added a simple script to autogenerate the client UI from the designer files in `pyside6_ui/`.

**`app/client/controllers/tabs/settings.py`**:

* Added settings and multiple user accounts functionality.

**`app/client/interface.py`**:

* Added request and response hooks for logging.
* `DeletedFilesInterface.show_deleted_versions()` now has `limit` and `offset` params.

**`app/client/main.py`**:

* Added `reload_config()` method.

## Changes

**`app/client/controllers/tabs/settings.py`**:

* Added trashbin functionality.

**`app/client/interface.py`**:

* Moved logger setup from interface to `config.py`.

**`app/client/controllers/apps.py`**:

* Now gets an `AvailableLogins` model instead of just a string when login is complete.

**`app/client/controllers/login.py`**:

* Now emits an `AvailableLogins` model instead of just a string.

**`app/client/config.py`**:

* Removed `username` and `server_url` keys and replaced with a `logins` key with a list of `AvailableLogins`.
* Logger setup is now handled in this module.

## Misc

* Made the client UI use layouts instead of just drag and drop.
* Finalized both client and server parts, v0.1.0 will be released soon.
