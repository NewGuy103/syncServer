# Implement more files tab actions

**Version**: v0.1.0

**Date:** 26/04/2025

## Additions

**`pyside6_ui/files_download_manager.ui` | `app/client/ui/files_download_manager.py`**:

* Added download manager UI for files tab.

**`app/client/interface.py`**:

* Added `FilesManager.download_file()` to download a file from the server, default chunk size is 10 MiB.
* Added `FilesManager.make_url()` to create the URL for the file path.

**`app/client/models.py`**:

* Added `DownloadStartedState` and `UploadStartedState` models.

**`app/client/config.py`**:

* Added to replace the makeshift config manager and to store other config-related data.

**`app/client/controllers/tabs/files.py`**:

* Separated a lot of client code into specific classes with their parent being `FilesTabController.
* Created `DownloadController` to allow downloading a file.
* Created `FilesDownloadManagerDialog` to handle showing running and completed downloads/uploads.

## Changes

**`app/client/interface.py`**:

* Removed makeshift config manager in favor of `pydantic-settings`.

**`app/client/models.py`**:

* Removed `ConfigData` in favor of `pydantic-settings`.

**`app/client/__main__.py`**:

* Now checks for required dependencies before proceeding with running the app.

**`app/client/main.py`**:

* No longer uses a `WorkerThead` to load config data.
* Now uses `AppSettings` from the config module.

**`app/client/controllers/login.py`**:

* Now uses `AppSettings` instead of the makeshift config manager.

## Misc

* Will work on implementing folder actions, deleted files and the dashboard soon.
* User management will probably not be implemented yet.
