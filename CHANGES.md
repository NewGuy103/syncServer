## Simple changes and client side encryption removed (extra)

### Note: Merged new changes in `server/__main__.py` into the same CHANGES.md

---

**Changes:**

**`server/__main__.py`**:
* Moved all code into `server/_server.py`.
* Now imports from `_db` and `_server` to run the main script.

**`server/_db.py`**:
* Changed `FileDatabase` to initialize the database file at `$XDG_DATA_HOME/syncServer-server/<version>/syncServer.db`
instead of `./syncServer.db`, `~/.local/share` is used as a substitute if `$XDG_DATA_HOME` is not present.

**`client/interface.py`**:
* Removed client side encryption class, as it might be too hard to implement.
* Changed `_FileInterface.read` to have an output file argument, which allows it to use streaming,
instead of loading the whole file in memory. (Bugfix)

**`client/gui.py`**:
* Changed `remote_file_download` to instead pass the output path instead of handling writing the file.
* Removed any trace of the client side encryption handler.

**`client/cui.py`**:
* Removed client side encryption options in login UI.

**Additions:**

**`server/_server.py`**:
* Added this as the server script file.

**Other:**
* Will not be considering client side encryption for a while.
* Versions have been updated to `1.2.0`
* Currently updating documentation.