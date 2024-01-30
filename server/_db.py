"""
Module providing the FileDatabase class for managing a file storage database
with user authentication, file operations, and encryption capabilities.

Dependencies:
- sqlite3: Standard Python library for SQLite database operations.
- uuid: Standard Python library for generating UUIDs.
- secrets: Standard Python library for cryptographic operations.
- logging: Standard Python library for logging.
- argon2: Argon2 password hashing library (argon2-cffi).
- cryptography: Cryptography library for encryption operations.
- msgpack: MessagePack serialization library.
- pycrypter.CipherManager: Custom module for encryption operations (newguy103-pycrypter).
- typing: Standard Python library for type hints.

Attributes:
- __version__ (str): Module version.

Classes:
- FileDatabase: A class representing a file database with user authentication, file storage,
  and encryption capabilities.

Note:
- Ensure that the required dependencies are installed before using the FileDatabase class.
- The FileDatabase class provides a comprehensive solution for managing files, directories,
  and user authentication in a secure and encrypted manner.
"""

import sqlite3
import uuid
import secrets

import logging

import argon2  # argon2-cffi
import cryptography
import msgpack

from pycrypter import CipherManager  # newguy103-pycrypter
from typing import BinaryIO, Generator, TextIO, Union

__version__ = "1.0.0"

class FileDatabase:
    """
    A class representing a file database with user authentication, file storage,
    and encryption capabilities.

    Attributes:
    - db (sqlite3.Connection): SQLite3 database connection.
    - cursor (sqlite3.Cursor): SQLite3 database cursor.
    - pw_hasher (argon2.PasswordHasher): Argon2 password hasher for user password hashing.
    - cipher_mgr (CipherManager): Manager for encryption-related operations.
    - _cipher_key (bytes | str): Database encryption key.

    Methods:
    - __init__(self, db_name='syncServer.db', db_password=b''): Initializes the FileDatabase instance.
    - _load_conf(self, db_password: bytes | str = ''): Loads the configuration data from the database.

    Note:
    - The class uses SQLite3 for database operations and includes tables for users, files, directories,
      configuration, and file configuration.
    - Encryption configuration is stored securely, and the class provides methods for loading and managing it.
    - More methods are available for user management, file operations, and directory management.
    """

    def __init__(self, db_path='./syncServer.db', db_password=b''):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.db.cursor()

        self.pw_hasher: argon2.PasswordHasher = argon2.PasswordHasher()
        self.cipher_mgr: CipherManager = CipherManager()

        self.cipher_mgr.hash_method = cryptography.hazmat.primitives.hashes.SHA3_512()
        self.cursor.executescript("""
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,   
                username TEXT UNIQUE NOT NULL,
                token TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                data_id TEXT PRIMARY KEY,
                dir_id TEXT,
                
                user_id TEXT,
                filename TEXT,

                file_data BLOB,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (dir_id) REFERENCES directories(dir_id)
                    ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS directories (
                dir_id TEXT PRIMARY KEY,
                user_id TEXT,

                dir_name TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS config (
                config_id TEXT PRIMARY KEY,
                config_data BLOB,
                config_vars BLOB
            );
            
            CREATE TABLE IF NOT EXISTS files_config (
                id INTEGER PRIMARY KEY,
                data_id TEXT,

                config BLOB,
                FOREIGN KEY(data_id) REFERENCES files(data_id)
                    ON DELETE CASCADE
            );
        """)

        self._load_conf(db_password=db_password)

    def _load_conf(self, db_password: bytes | str = ''):
        """
        Load the configuration data from the 'config' table in the database.

        Parameters:
        - db_password (bytes | str): The database password used for decryption.

        Raises:
        - RuntimeError: If there is an issue decrypting the configuration data or if the
          'syncServer-protected' configuration variable is not found.

        Note:
        - The method retrieves and decrypts configuration data from the 'config' table.
        - If the configuration data is not present, default values are used and stored in the 'config' table.
        - The 'syncServer-protected' configuration variable determines whether the database is password-protected.
        - If protected, the provided database password is used for decryption.
        - The decrypted configuration data is stored in 'conf_secrets', 'conf_vars', and 'cipher_conf' attributes.
        """

        self.cursor.execute("""
           SELECT config_data, config_vars FROM config 
           WHERE config_id='main'
        """)
        config = self.cursor.fetchone()

        if not config:
            config_secrets = {
                'use_encryption': False,
                'encryption_config': {
                    'hash_pepper': b'',
                    'password_pepper': b''
                }
            }

            config_vars = {
                'syncServer-db-version': __version__,
                'syncServer-protected': False,

                'syncServer-recoveryKey': b'',
                'syncServer-encryptionEnabled': False
            }

            bytes_encoded_secrets = msgpack.packb(config_secrets)
            bytes_encoded_vars = msgpack.packb(config_vars)

            with self.db:
                self.cursor.execute("""
                   INSERT OR IGNORE INTO config
                   VALUES ('main', ?, ?)
               """, [bytes_encoded_secrets, bytes_encoded_vars])

            config = (msgpack.packb(config_secrets), msgpack.packb(config_vars))

        config_secrets = config[0]
        config_vars = msgpack.unpackb(config[1])

        db_protected = config_vars.get('syncServer-protected', -1)
        if db_protected == -1:
            raise RuntimeError(
                "config variable 'syncServer-protected' not in config_vars dictionary"
            )

        if not db_protected and db_password:
            raise RuntimeError(
                "database password provided but database is not protected"
            )
        if db_protected:
            try:
                msgpack_secrets = self.cipher_mgr.fernet.decrypt_data(
                    config_secrets, password=db_password
                )
                config_secrets = msgpack.unpackb(msgpack_secrets)
            except cryptography.fernet.InvalidToken: # type: ignore
                raise RuntimeError(
                    "could not decrypt config_data, either incorrect password or not encrypted, "
                    "if the original key was lost, decrypt the 'syncServer-recoveryKey' entry  "
                    "in config_vars using the exported recovery key"
                ) from None
        else:
            config_secrets = msgpack.unpackb(config[0])
        
        self.conf_secrets = config_secrets
        self.conf_vars = config_vars

        self._cipher_key = db_password
        self.cipher_conf = config_secrets['encryption_config']

    def set_protection(
            self, set_protection: bool,
            cipher_key: bytes | str = b'',

            hash_pepper: bytes = b'',
            password_pepper: bytes = b''
    ):
        """
        Set or unset protection for the database, including encryption.

        Parameters:
        - set_protection (bool): True to enable protection, False to disable.
        - cipher_key (bytes or str, optional): Encryption key for protecting the database.
          Required when set_protection is True.
        - hash_pepper (bytes, optional): Pepper used in hashing operations for added security.
        - password_pepper (bytes, optional): Pepper used in password-related operations for added security.

        Raises:
        - ValueError: If set_protection is True but cipher_key is not provided.

        Notes:
        - When set_protection is False, encryption and protection features are disabled.
        - When set_protection is True, encryption and protection features are enabled.
          The cipher_key is required for encryption, and hash_pepper and password_pepper
          can be customized for additional security.
        - If encryption is enabled, a recovery key is generated and stored securely.
          The recovery key is also saved in a file ('syncServer-recoveryKey.key').
        """

        if set_protection and not cipher_key:
            raise ValueError(
                "set_protection is True but cipher_key was not provided"
            )

        if not set_protection:  # False
            self.conf_secrets['use_encryption'] = False
            self.conf_vars['syncServer-protected'] = False

            bytes_encoded_secrets = msgpack.packb(self.conf_secrets)
            bytes_encoded_vars = msgpack.packb(self.conf_vars)
            with self.db:
                self.cursor.execute("""
                    UPDATE config
                    SET config_data=?, config_vars=?
                    WHERE config_id='main'
                """, [bytes_encoded_secrets, bytes_encoded_vars])
            return

        encryption_config = self.conf_secrets['encryption_config']
        encryption_config['hash_pepper'] = hash_pepper
        encryption_config['password_pepper'] = password_pepper

        self.conf_secrets['use_encryption'] = True
        self.conf_vars['syncServer-protected'] = True
        self.conf_vars['syncServer-encryptionEnabled'] = True

        encrypted_secrets = self.cipher_mgr.fernet.encrypt_data(
            msgpack.packb(self.conf_secrets), password=cipher_key
        )
        recovery_key = secrets.token_hex(32)

        encrypted_cipher_key = self.cipher_mgr.fernet.encrypt_data(
            self._cipher_key, password=recovery_key
        )
        self.conf_vars['syncServer-recoveryKey'] = encrypted_cipher_key

        with self.db, open('syncServer-recoveryKey.key', 'w', encoding='utf-8') as file:
            self.cursor.execute("""
                UPDATE config
                SET config_data=?, config_vars=?
                WHERE config_id='main'
            """, [
                encrypted_secrets,
                msgpack.packb(self.conf_vars)
            ])
            file.write(recovery_key)

        return

    def verify_user(self, username: str, token: str) -> Union[str, bool]:
        """
        Verify the authenticity of a user's authentication token.

        Parameters:
        - username (str): The username of the user to verify.
        - token (str): The authentication token to be verified.

        Returns:
        - Union[str, bool]: Returns one of the following:
          - True: If the user is verified successfully.
          - "NO_USER": If the specified username is not found in the database.
          - False: If the verification process fails, indicating an incorrect token.
          - Exception: If an unexpected exception occurs during the verification process.

        Notes:
        - Retrieves the stored token for the given username from the database.
        - Compares the provided token with the stored hashed token using Argon2 password hashing.
        - Returns True if the verification is successful, "NO_USER" if the user is not found,
          and False if the verification process fails.
        - Logs an error if an unexpected exception occurs during the verification process,
          and returns the exception instance in case of an unexpected error.
        """

        self.cursor.execute("""
            SELECT token FROM users WHERE username=?
        """, [username])
        db_result = self.cursor.fetchone()

        if not db_result:
            return "NO_USER"

        hashed_pw = db_result[0]

        try:
            self.pw_hasher.verify(hashed_pw, token)
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            return False
        except Exception as exc:
            logging.error("[verify_hash]: Verifying user hash failed: '%s'", exc)
            return exc

        return True

    def add_user(self, username: str, token: str) -> Union[str, int]:
        """
        Add a new user to the database with the specified username and authentication token.

        Parameters:
        - username (str): The username of the new user.
        - token (str): The authentication token associated with the new user.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the user is successfully added to the database.
          - "USER_EXISTS": If a user with the specified username already exists.

        Notes:
        - Checks if a user with the given username already exists in the database.
        - If the user exists, returns "USER_EXISTS" without adding a new user.
        - If the user does not exist, generates a unique user ID and directory ID.
        - Inserts the new user into the 'users' table and creates a root directory for the user.
        - Returns 0 upon successful addition of the new user to the database.
        """

        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_id = self.cursor.fetchone()

        if user_id:
            return "USER_EXISTS"

        hashed_pw = self.pw_hasher.hash(token)
        user_id = str(uuid.uuid4())

        dir_id = str(uuid.uuid4())
        with self.db:
            self.cursor.execute("""
                INSERT INTO users (user_id, username, token)
                VALUES (?, ?, ?)                
            """, [user_id, username, hashed_pw])
            self.cursor.execute("""
                INSERT INTO directories (dir_id, user_id, dir_name)
                VALUES (?, ?, '/')                
            """, [dir_id, user_id])

        return 0

    def remove_user(self, username: str, token: str) -> Union[str, int]:
        """
        Remove a user from the database based on the specified username and authentication token.

        Parameters:
        - username (str): The username of the user to be removed.
        - token (str): The authentication token associated with the user.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the user is successfully removed from the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.

        Notes:
        - Retrieves the stored user ID and hashed token for the given username from the database.
        - Compares the provided token with the stored hashed token using Argon2 password hashing.
        - If the user is not found, returns "NO_USER."
        - If the token verification fails, returns "INVALID_TOKEN."
        - If the verification is successful, irreversibly removes the user from the 'users' table.
        - Returns 0 upon successful removal of the user from the database.
        """

        self.cursor.execute("""
            SELECT token FROM users WHERE username=?
        """, [username])
        db_result = self.cursor.fetchone()

        if not db_result:
            return "NO_USER"

        hashed_pw = db_result[0]
        
        try:
            self.pw_hasher.verify(hashed_pw, token)
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            return "INVALID_TOKEN"
        except Exception as exc:
            logging.error("[remove_user]: Verifying user hash failed: '%s'", exc)
            return exc

        # irreversible delete
        with self.db:
            self.cursor.execute("""
                DELETE FROM users
                WHERE username=?
            """, [username])
        return 0
    
    def dir_checker(self, file_path: str, user_id: str) -> Union[str, tuple[str]]:
        """
        Check the existence of the directory associated with a given file path for a specific user.

        Parameters:
        - file_path (str): The file path to be checked.
        - user_id (str): The user ID associated with the directory.

        Returns:
        - Union[str, Tuple[str]]: Returns one of the following:
          - Tuple[str]: If the directory exists, returns a tuple containing the directory ID.
          - "NO_USER": If the specified user ID is not found in the database.

        Raises:
        - TypeError: If 'file_path' is not of type bytes or str.
        - ValueError: If 'file_path' is not passed in the arguments.

        Notes:
        - Checks if 'file_path' is a valid type (bytes or str).
        - Raises a TypeError if 'file_path' is not of the expected type.
        - Raises a ValueError if 'file_path' is not passed in the arguments.
        - Retrieves the user ID from the 'users' table to ensure the user exists.
        - Parses the file path to extract the directory path without the file name.
        - Queries the 'directories' table to check if the directory exists for the specified user.
        - Returns the directory ID if it exists; otherwise, returns "NO_USER."
        """

        if not isinstance(file_path, (bytes, str)):
            raise TypeError("'file_path' must be bytes or str")
        
        if not file_path:
            raise ValueError("'file_path' was not passed in args")

        self.cursor.execute("""
            SELECT user_id FROM users WHERE user_id=?
        """, [user_id])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"
        
        dirs = file_path.split("/")
        path_without_file = "/".join(dirs[0:-1])

        if path_without_file == "":
            path_without_file = "/"
        
        self.cursor.execute("""
            SELECT dir_id FROM directories
            WHERE dir_name=? AND user_id=?
        """, [path_without_file, user_id])
        db_result = self.cursor.fetchone()
        
        return db_result
    
    def add_file(
            self, username: str,
            token: str, file_path: bytes | str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ) -> Union[str, int]:
        """
        Add a file to the database for a specific user.

        Parameters:
        - username (str): The username of the user adding the file.
        - token (str): The authentication token associated with the user.
        - file_path (bytes or str): The path of the file to be added.
        - file_stream (BinaryIO or TextIO): The file stream to read the file content.
        - chunk_size (int, optional): The size of each chunk when reading the file stream.
          Default is 50 MB.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the file is successfully added to the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the directory for the file does not exist for the specified user.
          - "FILE_EXISTS": If a file with the same name already exists in the specified directory.

        Raises:
        - TypeError: If 'file_path' is not of type bytes or str.
        - IOError: If the file stream is empty.

        Notes:
        - Checks if 'file_path' is a valid type (bytes or str).
        - Raises a TypeError if 'file_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Raises an IOError if the file stream is empty.
        - Checks if the directory for the file exists for the specified user.
        - Returns "FILE_EXISTS" if a file with the same name already exists in the specified directory.
        - If encryption is enabled, encrypts the file content before storing it in the database.
        - Uses chunking to handle large file sizes efficiently.
        - Returns 0 upon successful addition of the file to the database.
        """
        
        if not isinstance(file_path, (bytes, str)):
            raise TypeError("'file_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"

        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified

        first_chunk = file_stream.read(chunk_size)
        if not first_chunk:
            raise IOError("file stream is empty")
        
        dir_exists = self.dir_checker(file_path, user_id)
        if not dir_exists:
            return "NO_DIR_EXISTS"
        
        dir_id = dir_exists[0]
        self.cursor.execute("""
            SELECT data_id FROM files
            WHERE filename=? AND user_id=? AND dir_id=?
        """, [file_path, user_id, dir_id])

        found_filename = self.cursor.fetchone()
        if found_filename:
            return "FILE_EXISTS"
        
        if self.conf_secrets['use_encryption']:
            first_chunk = self.cipher_mgr.fernet.encrypt_data(
                first_chunk, password=self._cipher_key,
                hash_pepper=self.cipher_conf['hash_pepper'],

                password_pepper=self.cipher_conf['password_pepper']
            )

        data_id = str(uuid.uuid4())
        config_data = {
            'encrypted': self.conf_secrets['use_encryption'],
            'chunk_size_used': chunk_size
        }

        with self.db:
            file_data = [data_id, dir_id, user_id, file_path, first_chunk]
            self.cursor.execute("""
                INSERT INTO files (
                    data_id, dir_id, user_id,
                    filename, file_data
                )
                VALUES (?, ?, ?, ?, ?)
            """, file_data)
            self.cursor.execute("""
                INSERT INTO files_config (data_id, config)
                VALUES (?, ?)
            """, [data_id, msgpack.packb(config_data)])

            chunk = file_stream.read(chunk_size)
            while chunk:
                if self.conf_secrets['use_encryption']:
                    chunk = self.cipher_mgr.fernet.encrypt_data(
                        chunk, password=self._cipher_key,
                        hash_pepper=self.cipher_conf['hash_pepper'],

                        password_pepper=self.cipher_conf['password_pepper']
                    )
                
                self.cursor.execute("""
                    UPDATE files
                    SET file_data = file_data || ?
                    WHERE user_id=? AND filename=? AND dir_id=?
                """, [chunk, user_id, file_path, dir_id])
                chunk = file_stream.read(chunk_size)

        return 0

    def modify_file(
            self, username: str,
            token: str, file_path: bytes | str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ) -> Union[str, int]:
        """
        Modify an existing file in the database for a specific user.

        Parameters:
        - username (str): The username of the user modifying the file.
        - token (str): The authentication token associated with the user.
        - file_path (bytes or str): The path of the file to be modified.
        - file_stream (BinaryIO or TextIO): The file stream to read the modified file content.
        - chunk_size (int, optional): The size of each chunk when reading the file stream.
          Default is 50 MB.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the file is successfully modified in the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the directory for the file does not exist for the specified user.
          - "NO_FILE_EXISTS": If the specified file does not exist in the specified directory.

        Raises:
        - TypeError: If 'file_path' is not of type bytes or str.
        - IOError: If the file stream is empty.

        Notes:
        - Checks if 'file_path' is a valid type (bytes or str).
        - Raises a TypeError if 'file_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Raises an IOError if the file stream is empty.
        - Checks if the directory for the file exists for the specified user.
        - Returns "NO_FILE_EXISTS" if the specified file does not exist in the specified directory.
        - If encryption is enabled, encrypts the modified file content before updating it in the database.
        - Uses chunking to handle large file sizes efficiently.
        - Returns 0 upon successful modification of the file in the database.
        """

        if not isinstance(file_path, (bytes, str)):
            raise TypeError("'file_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"

        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified

        first_chunk = file_stream.read(chunk_size)
        if not first_chunk:
            raise IOError("file stream is empty")
        
        dir_exists = self.dir_checker(file_path, user_id)
        if not dir_exists:
            return "NO_DIR_EXISTS"
        
        dir_id = dir_exists[0]
        self.cursor.execute("""
            SELECT data_id FROM files
            WHERE filename=? AND user_id=? AND dir_id=?
        """, [file_path, user_id, dir_id])

        found_filename = self.cursor.fetchone()
        if not found_filename:
            return "NO_FILE_EXISTS"

        data_id = found_filename[0]
        if self.conf_secrets['use_encryption']:
            first_chunk = self.cipher_mgr.fernet.encrypt_data(
                first_chunk, password=self._cipher_key,
                hash_pepper=self.cipher_conf['hash_pepper'],

                password_pepper=self.cipher_conf['password_pepper']
            )
        
        config_data = {
            'encrypted': self.conf_secrets['use_encryption'],
            'chunk_size_used': chunk_size
        }
        
        with self.db:
            self.cursor.execute("""
                UPDATE files
                SET file_data=?
                WHERE user_id=? AND filename=? AND dir_id=?
            """, [first_chunk, user_id, file_path, dir_id])
            self.cursor.execute("""
                UPDATE files_config
                SET config=?
                WHERE data_id=?
            """, [msgpack.packb(config_data), data_id])

            chunk = file_stream.read(chunk_size)
            while chunk:
                if self.conf_secrets['use_encryption']:
                    chunk = self.cipher_mgr.fernet.encrypt_data(
                        chunk, password=self._cipher_key,
                        hash_pepper=self.cipher_conf['hash_pepper'],

                        password_pepper=self.cipher_conf['password_pepper']
                    )
                
                self.cursor.execute("""
                    UPDATE files
                    SET file_data = file_data || ?
                    WHERE user_id=? AND filename=?
                """, [chunk, user_id, file_path])
                chunk = file_stream.read(chunk_size)

        return 0

    def remove_file(
            self, username: str,
            token: str, file_path: bytes | str
    ) -> Union[str, int]:
        """
        Remove an existing file from the database for a specific user.

        Parameters:
        - username (str): The username of the user removing the file.
        - token (str): The authentication token associated with the user.
        - file_path (bytes or str): The path of the file to be removed.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the file is successfully removed from the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the directory for the file does not exist for the specified user.
          - "NO_FILE_EXISTS": If the specified file does not exist in the specified directory.

        Raises:
        - TypeError: If 'file_path' is not of type bytes or str.

        Notes:
        - Checks if 'file_path' is a valid type (bytes or str).
        - Raises a TypeError if 'file_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Checks if the directory for the file exists for the specified user.
        - Returns "NO_FILE_EXISTS" if the specified file does not exist in the specified directory.
        - Irreversibly removes the file from the 'files' table in the database.
        - Returns 0 upon successful removal of the file from the database.
        """

        if not isinstance(file_path, (bytes, str)):
            raise TypeError("'file_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"

        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified
        
        dir_exists = self.dir_checker(file_path, user_id)
        if not dir_exists:
            return "NO_DIR_EXISTS"
        
        dir_id = dir_exists[0]
        self.cursor.execute("""
            SELECT data_id FROM files
            WHERE filename=? AND user_id=? AND dir_id=?
        """, [file_path, user_id, dir_id])

        found_filename = self.cursor.fetchone()
        if not found_filename:
            return "NO_FILE_EXISTS"
        
        with self.db:
            self.cursor.execute("""
                DELETE FROM files
                WHERE user_id=? AND filename=?
            """, [user_id, file_path])

        return 0

    def read_file(
            self, username: str,
            token: str, file_path: bytes | str,
            chunk_size: int = 50 * 1024 * 1024
    ) -> Union[str, Generator[bytes, None, None]]:
        """
        Read the content of an existing file from the database for a specific user.

        Parameters:
        - username (str): The username of the user reading the file.
        - token (str): The authentication token associated with the user.
        - file_path (bytes or str): The path of the file to be read.
        - chunk_size (int, optional): The size of each chunk when reading the file content.
          Default is 50 MB.

        Returns:
        - Union[str, Generator[bytes, None, None]]: Returns one of the following:
          - Generator[bytes, None, None]: A generator yielding file content in chunks.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the directory for the file does not exist for the specified user.
          - "NO_FILE_EXISTS": If the specified file does not exist in the specified directory.

        Raises:
        - TypeError: If 'file_path' is not of type bytes or str.

        Notes:
        - Checks if 'file_path' is a valid type (bytes or str).
        - Raises a TypeError if 'file_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Checks if the directory for the file exists for the specified user.
        - Returns "NO_FILE_EXISTS" if the specified file does not exist in the specified directory.
        - Retrieves file information including data ID and length from the 'files' table.
        - Retrieves file configuration (chunk size, encryption) from the 'files_config' table.
        - Adjusts the 'chunk_size' to match the stored chunk size used during encryption.
        - Yields file content in chunks using a generator.
        - Decrypts the content if encryption is enabled, using the adjusted 'chunk_size.'
        """

        if not isinstance(file_path, (bytes, str)):
            raise TypeError("'file_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"

        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified
        
        dir_exists = self.dir_checker(file_path, user_id)
        if not dir_exists:
            return "NO_DIR_EXISTS"
        
        dir_id = dir_exists[0]
        self.cursor.execute("""
            SELECT data_id, length(file_data) FROM files
            WHERE filename=? AND user_id=? AND dir_id=?
        """, [file_path, user_id, dir_id])

        found_filename = self.cursor.fetchone()
        if not found_filename:
            return "NO_FILE_EXISTS"

        data_id = found_filename[0]
        data_length = found_filename[1]

        self.cursor.execute("""
            SELECT config FROM files_config
            WHERE data_id=?
        """, [data_id])

        msgpack_config = self.cursor.fetchone()[0]
        config = msgpack.unpackb(msgpack_config)

        if config['chunk_size_used'] != chunk_size:
            chunk_size = config['chunk_size_used']

        def generator():
            offset = 0
            while offset < data_length:
                self.cursor.execute("""
                    SELECT substr(file_data, ?, ?) 
                    FROM files
                    WHERE data_id=?
                """, (offset + 1, chunk_size, data_id))

                chunk = self.cursor.fetchone()[0]
                offset += chunk_size

                if config['encrypted']:
                    chunk = self.cipher_mgr.fernet.decrypt_data(
                        chunk, password=self._cipher_key,
                        hash_pepper=self.cipher_conf['hash_pepper'],

                        password_pepper=self.cipher_conf['password_pepper']
                    )
                yield chunk
        
        # Returning generator() instead of yield directly
        # allows the function to return plain values instead of
        # requiring me to use next() and then checking the value
        return generator()
    
    def make_dir(
            self, username: str,
            token: str,
            dir_path: str
    ) -> Union[str, int]:
        """
        Create a new directory in the database for a specific user.

        Parameters:
        - username (str): The username of the user creating the directory.
        - token (str): The authentication token associated with the user.
        - dir_path (str): The path of the directory to be created.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the directory is successfully created in the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "DIR_EXISTS": If the specified directory already exists for the specified user.
          - "MISSING_PATH": If the 'dir_path' is empty.
          - "INVALID_DIR_PATH": If the 'dir_path' is not a valid directory path.

        Raises:
        - TypeError: If 'dir_path' is not of type bytes or str.

        Notes:
        - Checks if 'dir_path' is a valid type (bytes or str).
        - Raises a TypeError if 'dir_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Returns "MISSING_PATH" if 'dir_path' is empty.
        - Returns "INVALID_DIR_PATH" if 'dir_path' is not a valid directory path.
        - Returns "DIR_EXISTS" if the specified directory already exists for the specified user.
        - Inserts a new directory entry into the 'directories' table in the database.
        - Returns 0 upon successful creation of the directory in the database.
        """

        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("'dir_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"
        
        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified
        
        self.cursor.execute("""
            SELECT dir_id FROM directories
            WHERE dir_name=? AND user_id=?
        """, [dir_path, user_id])

        found_filename = self.cursor.fetchone()
        if found_filename:
            return "DIR_EXISTS"
        
        if not dir_path:
            return "MISSING_PATH"
        
        if dir_path[0] != "/":
            dir_path = "/" + dir_path
        
        dirs = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue

            if not dir_name:
                return "INVALID_DIR_PATH"
            
        dir_id = str(uuid.uuid4())
        with self.db:
            self.cursor.execute("""
                INSERT INTO directories (dir_id, user_id, dir_name)
                VALUES (?, ?, ?)
            """, [dir_id, user_id, dir_path])
        
        return 0

    def remove_dir(
            self, username: str,
            token: str,
            dir_path: str
    ) -> Union[str, int]:
        """
        Remove an existing directory and its contents from the database for a specific user.

        Parameters:
        - username (str): The username of the user removing the directory.
        - token (str): The authentication token associated with the user.
        - dir_path (str): The path of the directory to be removed.

        Returns:
        - Union[str, int]: Returns one of the following:
          - 0: If the directory and its contents are successfully removed from the database.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the specified directory does not exist for the specified user.
          - "ROOT_DIR": If attempting to remove the root directory.
          - "INVALID_DIR_PATH": If the 'dir_path' is not a valid directory path.

        Raises:
        - TypeError: If 'dir_path' is not of type bytes or str.

        Notes:
        - Checks if 'dir_path' is a valid type (bytes or str).
        - Raises a TypeError if 'dir_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Returns "ROOT_DIR" if attempting to remove the root directory.
        - Returns "INVALID_DIR_PATH" if 'dir_path' is not a valid directory path.
        - Deletes the specified directory and its contents from the 'directories' table in the database.
        - Returns 0 upon successful removal of the directory and its contents from the database.
        """

        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("'dir_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"
        
        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified
        
        self.cursor.execute("""
            SELECT dir_id FROM directories
            WHERE dir_name=? AND user_id=?
        """, [dir_path, user_id])

        found_dir = self.cursor.fetchone()
        if not found_dir:
            return "NO_DIR_EXISTS"
        
        dir_id = found_dir[0]
        if dir_path == "/":
            return "ROOT_DIR"
        
        dirs = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue

            if not dir_name:
                return "INVALID_DIR_PATH"

        with self.db:
            self.cursor.execute("""
                DELETE FROM directories
                WHERE dir_id=? AND user_id=?
            """, [dir_id, user_id])
            
        return 0

    def list_dir(
            self, username: str,
            token: str, 
            dir_path: str
    ) -> Union[str, list[str]]:
        """
        List the files in a specific directory for a given user.

        Parameters:
        - username (str): The username of the user listing the directory.
        - token (str): The authentication token associated with the user.
        - dir_path (str): The path of the directory to be listed.

        Returns:
        - Union[str, List[str]]: Returns one of the following:
          - List[str]: A list of filenames in the specified directory.
          - "NO_USER": If the specified username is not found in the database.
          - "INVALID_TOKEN": If the provided token does not match the stored token for the user.
          - "NO_DIR_EXISTS": If the specified directory does not exist for the specified user.
          - "INVALID_DIR_PATH": If the 'dir_path' is not a valid directory path.

        Raises:
        - TypeError: If 'dir_path' is not of type bytes or str.

        Notes:
        - Checks if 'dir_path' is a valid type (bytes or str).
        - Raises a TypeError if 'dir_path' is not of the expected type.
        - Retrieves the user ID and verifies the user using the provided username and token.
        - Returns "NO_DIR_EXISTS" if the specified directory does not exist for the specified user.
        - Returns "INVALID_DIR_PATH" if 'dir_path' is not a valid directory path.
        - Retrieves filenames from the 'files' table for the specified directory.
        - Returns a list of filenames in the specified directory.
        """

        if not isinstance(dir_path, (bytes, str)):
            raise TypeError("'dir_path' must be bytes or str")
        
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_data = self.cursor.fetchone()

        if not user_data:
            return "NO_USER"
        
        user_id = user_data[0]
        token_verified = self.verify_user(username, token)
        
        if not token_verified:
            return "INVALID_TOKEN"
        if isinstance(token_verified, Exception):
            return token_verified
        
        self.cursor.execute("""
            SELECT dir_id FROM directories
            WHERE dir_name=? AND user_id=?
        """, [dir_path, user_id])

        found_dir = self.cursor.fetchone()
        if not found_dir:
            return "NO_DIR_EXISTS"
        
        dirs = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue
            elif dir_path == "/":
                break

            if not dir_name:
                return "INVALID_DIR_PATH"

        dir_id = found_dir[0]
        self.cursor.execute("""
            SELECT filename FROM files
            WHERE dir_id=? AND user_id=?
        """, [dir_id, user_id])

        dir_listing = self.cursor.fetchall()
        files = [i[0] for i in dir_listing]
        
        return files
        
        
if __name__ == "__main__":
    raise NotImplementedError(
        "this module cannot be run using __main__ and can only be imported"
    )
