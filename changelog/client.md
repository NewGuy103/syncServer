# Implement trashbin tab and add icons

**Version**: v0.1.0

**Date:** 28/04/2025

## Additions

**`pyside6_ui/trashbin_manager.ui` | `app/client/ui/trashbin_manager.py`**:

* Added trashbin manager for deleted files.

**`app/client/interface.py`**:

* Added `DeletedFilesInterface` for deleted files.

**`app/client/models.py`**:

* Added `DeletedFileVersionState` and `DeletedFilesGet` models.

**`app/client/controllers/apps.py`**:

* Added `ControllerSignals` class for signals between app tabs.

**`app/client/controllers/tabs/files.py`**:

* Implemented folder creation, deletion and renaming.

**`app/client/controllers/tabs/trashbin.py`**:

* Added trashbin functionality.

## Changes

None.

## Misc

* Added icons to some buttons and most actions.
* Client is almost complete, the final component is the dashboard.
