## Changes to API
**Changes:**
* **`server/__main__.py`**:
    * Changed all APIs to accept JSON, except for `/upload` and `/modify` as those are file upload APIs.
    * Replaced some `flask.abort(500)` calls with a `make_response` call that returns generic JSON and a 500 status code.
    * Will work on adding API token support.
* **`server/_db.py`**:
    * Changed all methods and removed the `token` parameter for all file/directory operations.
    * Planning to update documentation.
* **`client/interface.py`**:
    * Changed methods to request as JSON compared to a form-data POST.

**Additions:**
* **`server/__main__.py`**:
    * Added better handling when checking for parameter existence, to prevent re-defining the same variable.
    * Added type annotations to some variables.
    * Added a check at the start of functions that checks if it's a JSON request, and returns a 415 with a JSON message.
* **`server/_db.py`**:
    * Added type annotations and function return annotations.
* **`client/interface.py`**:
    * Added methods to handle deleted files.
    * Added type annotations and function return annotations.
    * Added `endpoint` parameter to `FileInterface.upload`, allowing you specify the route.
    The default is `/upload` if `modify_remote` is false, or `/modify`.
