# Make client module more modular and maintainable

**Version**: v0.1.0

**Date:** 25/04/2025

## Additions

**`pyside6_ui/*_dialog.ui` | `app/client/ui`**:

* Added simple dialogs specific to their function (API keys, files).

**`app/client/interface.py`**:

* Added makeshift config manager that uses pydantic to get/set config data.
* Added some client code to interact with the API, but not complete.
* No longers sets the `Content-Type` header when creating the client.
* Now raises a `RuntimeError` if ran as a script.

**`app/client/models.py`**:

* Copied more API models from the server to the client.
* Copied over `GenericSuccess`.
* Added `FileListWidgetData` as a simple model to differentiate from a file or folder in the list widget.

**`app/client/workers.py`**:

* Moved `WorkerThread` to this module to make it more maintainable.

**`app/client/controllers`**:

* Moved all controller-related code to this module.

**`app/client/controllers/tabs`**:

* Created to store the controllers for the specific tabs for all app-related operations.

## Changes

**`app/client/__main__.py`**:

* Now references `main` instead of `gui`.

**`app/client/main.py`**:

* Made `main.py` more modular by removing a lot of code and putting them into modules.
* Now loads the app config and throws a fatal error if config loading fails.

## Misc

* API client still incomplete, UI is nearing completion so far.
