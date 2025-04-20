# Create working UI and client interface

**Version**: v0.1.0

**Date:** 20/04/2025

## Additions

**`pyside6_ui/`**:

* Added to store the designer UI files without putting them in `app/`.

**`app/client/ui/`**:

* Created `ui` directory as a submodule where PySide6 generated files are stored and used.

**`app/client/main.py`**:

* Added as the controller for the main app.

**`app/client/models.py`**:

* Copied from `app/server/models`.

**`app/client/interface.py`**:

Technically not an addition, but it does replace the old `interface.py`.

* Added as a replacement to the old `requests` interface, now using `httpx`.

## Changes

None so far.

## Misc

* Currently a work in progress, API client is incomplete and so is the UI.
