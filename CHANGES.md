## Replace CipherManager to remove dependency

**Additions:**

**server/_db.py**:

* Added `SimpleCipher` to remove dependency on `newguy103-pycrypter`.

**server/__init__.py**:

* Added `SimpleCipher` to imports.

**Changes:**

**server/_db.py**:

* Replaced `CipherManager` with `SimpleCipher`. Functions that use encryption now use `self.cipher`.

**Other:**
* Updated `server-db.md` to include `SimpleCipher`.
* Versions have not been incremented yet.