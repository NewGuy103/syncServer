## Major Application Update

**Features:**

* **Directory Management:**
    * Added tables and functionality for directories.
    * `files` table now has `dir_id` for linking.
    * New `directories` table stores directory information.
    * Cascading deletion removes directory & associated files on user deletion.
    * `/create-dir`, `/remove-dir`, and `/list-dir` routes for managing directories.
* **Enhanced File Handling:**
    * Removed unnecessary `if len(files) == 1` checks.
    * Added file length checks and handling through for loops and `if` statements.
    * Improved error handling for informative feedback.

**Code:**

* Removed redundant `_log_excs()` function.
* Optimized imports for cleaner code.