import argparse
import ast
import getpass

import copy
import os
import sqlite3

import subprocess
import tempfile
import uuid

import secrets
import logging

import argon2  # argon2-cffi
import cryptography
import cryptography.exceptions
import msgpack

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from datetime import datetime
from typing import BinaryIO, Generator, Literal, TextIO
from contextlib import contextmanager

__version__: str = "1.3.0"
LOGFILE: str = 'syncServer-serverDB.log'


@contextmanager
def transaction(conn: sqlite3.Connection):
    try:
        cursor: sqlite3.Cursor = conn.cursor()
        with conn:
            yield cursor
    except sqlite3.Error:
        logging.exception("Error thrown during transaction:")
        raise
    finally:
        cursor.close()


class SimpleCipher:
    def __init__(
            self, cipher_key: bytes | str,
            hash_method: hashes.HashAlgorithm = None,

            hash_pepper: bytes = b'', password_pepper: bytes = b''
    ) -> None:
        if not isinstance(hash_pepper, bytes):
            raise TypeError("hash pepper is not bytes")
        
        if not isinstance(password_pepper, bytes):
            raise TypeError("password pepper is not bytes")
        
        match cipher_key:
            case bytes():
                pass
            case str():
                cipher_key: bytes = cipher_key.encode('utf-8')
            case _:
                raise TypeError("encryption key is not bytes or string")
        
        self.__key: bytes = cipher_key
        
        if not hash_method:
            self.hash_method: hashes.SHA3_512 = hashes.SHA3_512()
        else:
            self.hash_method: hashes.HashAlgorithm = hash_method

        self.hash_pepper: bytes = hash_pepper
        self.pw_pepper: bytes = password_pepper

    def encrypt(
            self, data: bytes | str,
            associated_data: bytes = b'',
    ) -> bytes:        
        match data:
            case bytes():
                pass
            case str():
                data: bytes = data.encode('utf-8')
            case _:
                raise TypeError("data is not bytes or string")
        
        salt: bytes = secrets.token_bytes(32)
        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + self.hash_pepper,
            iterations=100_000
        )
        
        aes_key: bytes = kdf.derive(self.pw_pepper + self.__key)
        aes: AESGCM = AESGCM(aes_key)

        nonce: bytes = secrets.token_bytes(12)
        encrypted_data: bytes = aes.encrypt(nonce, data, associated_data)

        return salt + nonce + encrypted_data

    def decrypt(
            self, data: bytes | str,
            associated_data: bytes = b'',
    ) -> bytes:
        match data:
            case bytes():
                pass
            case str():
                data: bytes = data.encode('utf-8')
            case _:
                raise TypeError("data is not bytes or string")
        
        salt: bytes = data[0:32]
        data: bytes = data[32:]
        
        nonce: bytes = data[0:12]
        data: bytes = data[12:]

        kdf: PBKDF2HMAC = PBKDF2HMAC(
            algorithm=self.hash_method,
            length=32,
            salt=salt + self.hash_pepper,
            iterations=100_000
        )
        
        aes_key: bytes = kdf.derive(self.pw_pepper + self.__key)
        aes: AESGCM = AESGCM(aes_key)

        decrypted_data: bytes = aes.decrypt(nonce, data, associated_data)
        return decrypted_data
    
    def hash_data(self, data: bytes | str):
        match data:
            case bytes():
                pass
            case str():
                data: bytes = data.encode('utf-8')
            case _:
                raise TypeError("data is not bytes or string")
        
        digest: hashes.Hash = hashes.Hash(self.hash_method)
        digest.update(data)

        hashed_data: bytes = digest.finalize()
        return hashed_data.hex()


class FileDatabase:
    def __init__(
            self, db_path: str = '', 
            db_password: bytes | str = b'',
            recovery_mode: bool = False,
            dict_cache: bool = False
    ) -> None:
        if not isinstance(db_path, (bytes, str)):
            raise TypeError("database path must be bytes or str")        
        if not isinstance(db_password, (bytes, str)):
            raise TypeError("database password must be bytes or str")
        
        if not isinstance(recovery_mode, bool):
            raise TypeError("recovery mode option must be bool")
        if not isinstance(dict_cache, bool):
            raise TypeError("dict cache option must be bool")
        
        if not db_path:
            data_dir: str = os.environ.get(
                "XDG_DATA_HOME", 
                os.path.join(os.path.expanduser("~"), ".local", "share")
            )
            
            db_dir: str = os.path.join(data_dir, "syncServer-server", __version__)
            os.makedirs(db_dir, exist_ok=True)

            db_path: str = os.path.join(db_dir, 'syncServer.db')

        self.__closed: bool = False

        self.db: sqlite3.Connection = sqlite3.connect(db_path, check_same_thread=False)
        self.pw_hasher: argon2.PasswordHasher = argon2.PasswordHasher()

        self.hash_method: hashes.SHA512 = hashes.SHA512()
        self._using_cache: bool = dict_cache

        with transaction(self.db) as cur:
            cur.executescript("""
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,   
                    username TEXT UNIQUE NOT NULL,
                    token TEXT NOT NULL
                ) STRICT;

                CREATE TABLE IF NOT EXISTS user_apikeys (
                    key_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    
                    key_name TEXT,
                    api_key TEXT,
                    
                    key_perms BLOB,
                    expiry_date TEXT, -- datetime
                    
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                        ON DELETE CASCADE
                ) STRICT;
                CREATE TABLE IF NOT EXISTS files (
                    data_id TEXT PRIMARY KEY,
                    dir_id TEXT,
                    
                    user_id TEXT,
                    filename TEXT,

                    file_data BLOB,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY (dir_id) REFERENCES directories(dir_id)
                        ON DELETE CASCADE
                ) STRICT;
                
                CREATE TABLE IF NOT EXISTS directories (
                    dir_id TEXT PRIMARY KEY,
                    user_id TEXT,

                    dir_name TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                        ON DELETE CASCADE
                ) STRICT;

                CREATE TABLE IF NOT EXISTS config (
                    config_id TEXT PRIMARY KEY,
                    config_data BLOB,
                    config_vars BLOB
                ) STRICT;
                
                CREATE TABLE IF NOT EXISTS deleted_files (
                    delete_id TEXT PRIMARY KEY,
                    data_id TEXT,
                    
                    old_filepath TEXT,
                    delete_date TEXT DEFAULT (
                        datetime('now', 'localtime')  
                        || '.' 
                        || strftime('%f', 'now', 'localtime')
                    ), -- timestamp
                    
                    FOREIGN KEY (data_id) REFERENCES files(data_id)
                        ON DELETE CASCADE
                ) STRICT;
                
                CREATE TABLE IF NOT EXISTS files_config (
                    id INTEGER PRIMARY KEY,
                    data_id TEXT,

                    config BLOB,
                    FOREIGN KEY(data_id) REFERENCES files(data_id)
                        ON DELETE CASCADE
                ) STRICT;
                                    
                CREATE UNIQUE INDEX IF NOT EXISTS user_id ON users(user_id);
                CREATE UNIQUE INDEX IF NOT EXISTS dir_id ON directories(dir_id);
                
                CREATE UNIQUE INDEX IF NOT EXISTS data_id ON files(data_id);
                CREATE UNIQUE INDEX IF NOT EXISTS key_id ON user_apikeys(key_id);
                              
                CREATE INDEX IF NOT EXISTS delete_data ON deleted_files(delete_date);
            """)

        self._load_conf(db_password=db_password, recovery_mode=recovery_mode)

    def _load_conf(self, db_password: bytes | str = '', recovery_mode: bool = False):
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT config_data, config_vars FROM config 
                WHERE config_id='main'
            """)
            config: tuple[bytes, bytes] = cursor.fetchone()
        
        db_version: str = "1.2.0"  # make sure to only update this when updating the database schema
        if not config:
            config_secrets: dict = {
                'use_encryption': False,
                'encryption_config': {
                    'hash_pepper': b'',
                    'password_pepper': b''
                }
            }

            config_vars: dict = {
                'syncServer-db-version': db_version,
                'syncServer-protected': False,

                'syncServer-recoveryKey': b'',
                'syncServer-encryptionEnabled': False  # will plan to use this soon
            }

            bytes_encoded_secrets = msgpack.packb(config_secrets)
            bytes_encoded_vars = msgpack.packb(config_vars)

            with transaction(self.db) as cur:
                cur.execute("""
                   INSERT OR IGNORE INTO config
                   VALUES ('main', ?, ?)
                """, [bytes_encoded_secrets, bytes_encoded_vars])

            config = (msgpack.packb(config_secrets), msgpack.packb(config_vars))

        config_secrets: bytes = config[0]
        config_vars: dict = msgpack.unpackb(config[1])

        self.recovery_mode: bool = recovery_mode
        if recovery_mode:
            # Partially initialize config vars to get the recovery key
            self.conf_vars: dict = config_vars 
            self.conf_secrets = {}

            self.cipher: SimpleCipher = SimpleCipher('')
            self.cipher_conf = {}

            self.db_admin: DatabaseAdmin = DatabaseAdmin(self)
            return
        
        stored_db_version: str = config_vars.get('syncServer-db-version', '')
        if not stored_db_version:
            raise RuntimeError("cannot find syncServer database version in config vars")
        
        if stored_db_version != db_version:
            raise RuntimeError(
                f"database version does not match with current version "
                f"[database_version == {stored_db_version}, current_version == {db_version}]"
            )
        
        db_protected = config_vars.get('syncServer-protected', -1)
        if db_protected == -1:
            raise RuntimeError("config variable 'syncServer-protected' not in config_vars dictionary")
        
        if not db_protected and db_password:
            raise RuntimeError("database password provided but database is not protected")

        init_cipher: SimpleCipher = SimpleCipher(db_password, hash_method=self.hash_method)
        if db_protected:
            try:
                msgpack_secrets = init_cipher.decrypt(config_secrets)
                config_secrets = msgpack.unpackb(msgpack_secrets)
            except cryptography.exceptions.InvalidTag:  # type: ignore
                raise RuntimeError(
                    "could not decrypt config_data, either incorrect password or not encrypted, "
                    "if the original key was lost, decrypt the 'syncServer-recoveryKey' entry  "
                    "in config_vars using the exported recovery key"
                ) from None
        else:
            config_secrets = msgpack.unpackb(config[0])
        
        hash_pepper: bytes = config_secrets.get('hash-pepper', b'')
        pw_pepper: bytes = config_secrets.get('password-pepper', b'')

        self.cipher: SimpleCipher = SimpleCipher(
            db_password, hash_method=self.hash_method,
            hash_pepper=hash_pepper, password_pepper=pw_pepper
        )
        self.conf_secrets: dict = config_secrets
        self.conf_vars: dict = config_vars

        self.cipher_conf: dict = config_secrets['encryption_config']
        self.dirs: DirectoryInterface = DirectoryInterface(self)

        self.deleted_files: DeletedFiles = DeletedFiles(self)
        self.api_keys: APIKeyInterface = APIKeyInterface(self)

        self.db_admin: DatabaseAdmin = DatabaseAdmin(self)
        self.__data_cache: dict = {}

        if self._using_cache:
            with transaction(self.db) as cursor:
                cursor.execute("SELECT user_id, username, token FROM users") 
                user_data: list[tuple] = cursor.fetchall()
                
            for user_id, username, token in user_data:
                user_dict: dict = {
                    'id': user_id,
                    'token': token
                }
                self.__data_cache[username] = user_dict
        
    def _get_userid(self, username: str) -> str:
        self._ensure_open()
        if self._using_cache:
            user_dict: dict = self.__data_cache.get(username)
            if not user_dict:
                return ''
            
            return user_dict['id']
        else:
            with transaction(self.db) as cursor:
                cursor.execute("""
                    SELECT user_id FROM users WHERE username=?
                """, [username])
                db_result: tuple[str] = cursor.fetchone()

            if not db_result:
                return ''
            
            return db_result[0]
    
    def _get_dirid(self, dir_path: str, user_id: str) -> str:
        self._ensure_open()
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT dir_id FROM directories
                WHERE dir_name=? AND user_id=?
            """, [dir_path, user_id])

            db_result: tuple[str] = cursor.fetchone()
            
        if not db_result:
            return ''
            
        return db_result[0]
    
    def _ensure_open(self):
        if self.__closed:
            raise RuntimeError("working on a closed FileDatabase instance")
    
    def close(self):
        if self.__closed:
            return
        
        self.db.close()
        self.__closed: bool = True

        del self.__data_cache
        del self.db
        del self.dirs
        del self.deleted_files
        del self.api_keys
        del self.db_admin
        del self.cipher
        del self.pw_hasher
        del self.hash_method
        del self.conf_secrets
        del self.conf_vars
        del self.cipher_conf
        del self.recovery_mode
    
    def verify_user(self, username: str, token: str) -> str | bool:
        self._ensure_open()
        if self._using_cache:
            user_dict: dict = self.__data_cache.get(username)
            if not user_dict:
                return "NO_USER"
            hashed_pw: str = user_dict['token']  # fail intentionally if missing
        else:
            with transaction(self.db) as cursor:
                cursor.execute("""
                    SELECT token FROM users WHERE username=?
                """, [username])
                db_result: tuple[str] = cursor.fetchone()

            if not db_result:
                return "NO_USER"
            hashed_pw: str = db_result[0]

        try:
            self.pw_hasher.verify(hashed_pw, token)
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            return False
        except Exception as exc:
            logging.error("[verify_hash]: Verifying user hash failed: '%s'", exc)
            return exc

        return True

    def add_user(self, username: str, token: str) -> Literal['USER_EXISTS', 0]:
        """
        Add a new user to the database with the specified username and authentication token.

        Parameters:
        - username (str): The username of the new user.
        - token (str): The authentication token associated with the new user.

        Returns:
        - 0: If the user is successfully added to the database.
        - "USER_EXISTS": If a user with the specified username already exists.

        Notes:
        - Checks if a user with the given username already exists in the database.
        - If the user exists, returns "USER_EXISTS" without adding a new user.
        - If the user does not exist, generates a unique user ID and directory ID.
        - Inserts the new user into the 'users' table and creates a root directory for the user.
        - Returns 0 upon successful addition of the new user to the database.
        """

        self._ensure_open()

        blacklisted_names: set = {'INVALID_APIKEY', 'APIKEY_NOT_AUTHORIZED', 'NO_USER', ''}
        if username in blacklisted_names:
            raise ValueError('cannot use blacklisted username')
        
        user_data: str = self._get_userid(username)
        if user_data:
            return "USER_EXISTS"

        hashed_pw: str = self.pw_hasher.hash(token)
        user_id: str = str(uuid.uuid4())

        dir_id: str = str(uuid.uuid4())
        with transaction(self.db) as cursor:
            cursor.execute("""
                INSERT INTO users (user_id, username, token)
                VALUES (?, ?, ?)                
            """, [user_id, username, hashed_pw])
            cursor.execute("""
                INSERT INTO directories (dir_id, user_id, dir_name)
                VALUES (?, ?, '/')
            """, [dir_id, user_id])

        return 0

    def remove_user(self, username: str) -> Literal["NO_USER"] | int:
        self._ensure_open()
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        if self._using_cache:
            self.__data_cache.pop(username, '')
        
        # irreversible delete
        with transaction(self.db) as cursor:
            cursor.execute("""
                DELETE FROM users
                WHERE user_id=?
            """, [user_id])
        
        return 0
    
    def dir_checker(self, username: str, file_path: str) -> Literal["NO_USER"] | str:
        self._ensure_open()
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string")
        
        if not file_path:
            raise ValueError("'file_path' was not passed in args")

        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dirs: list[str] = file_path.split("/")
        path_without_file: str = "/".join(dirs[0:-1])

        if path_without_file == "":
            path_without_file: str = "/"
        
        dir_id: str = self._get_dirid(path_without_file, user_id)
        if not dir_id:
            return ''

        return dir_id
    
    def add_file(
            self, username: str,
            file_path: str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ) -> int | str:
        self._ensure_open()
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be a string")
        
        if not isinstance(chunk_size, int):
            raise TypeError("'chunk_size' must be an int")

        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        first_chunk: bytes = file_stream.read(chunk_size)
        if not first_chunk:
            raise IOError("file stream is empty")
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])
            file_data: list[tuple[str]] = cursor.fetchall()

        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                if not tmp_delete_data:
                    return "FILE_EXISTS"
        
        if self.conf_secrets['use_encryption']:
            first_chunk: bytes = self.cipher.encrypt(first_chunk)

        data_id: str = str(uuid.uuid4())
        config_data: dict = {'chunk-size': chunk_size}

        with transaction(self.db) as cursor:
            file_data: list = [data_id, dir_id, user_id, file_path, first_chunk]
            cursor.execute("""
                INSERT INTO files (
                    data_id, dir_id, user_id,
                    filename, file_data
                )
                VALUES (?, ?, ?, ?, ?)
            """, file_data)
            cursor.execute("""
                INSERT INTO files_config (data_id, config)
                VALUES (?, ?)
            """, [data_id, msgpack.packb(config_data)])

            chunk: bytes = file_stream.read(chunk_size)
            while chunk:
                if self.conf_secrets['use_encryption']:
                    chunk: bytes = self.cipher.encrypt(chunk)
                
                cursor.execute("""
                    UPDATE files
                    SET file_data = cast(file_data || ? AS BLOB)
                    WHERE data_id=?
                """, [chunk, user_id])
                chunk: bytes = file_stream.read(chunk_size)

        return 0

    def modify_file(
            self, username: str,
            file_path: str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ) -> int | str:
        self._ensure_open()
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")
        
        if not isinstance(chunk_size, int):
            raise TypeError("'chunk_size' must be an int")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        first_chunk: bytes = file_stream.read(chunk_size)
        if not first_chunk:
            raise IOError("file stream is empty")
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])
            file_data: list[tuple[str]] = cursor.fetchall()

        if not file_data:
            return "NO_FILE_EXISTS"

        non_deleted_id: str = ""
        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                
                if tmp_delete_data:
                    continue

                non_deleted_id: str = file_id
                break

        if not non_deleted_id:
            return "NO_FILE_EXISTS"
        
        if self.conf_secrets['use_encryption']:
            first_chunk: bytes = self.cipher.encrypt(first_chunk)
        
        config_data = {'chunk-size': chunk_size}
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                UPDATE files
                SET file_data=?
                WHERE data_id=?
            """, [first_chunk, non_deleted_id])
            cursor.execute("""
                UPDATE files_config
                SET config=?
                WHERE data_id=?
            """, [msgpack.packb(config_data), non_deleted_id])

            chunk: bytes = file_stream.read(chunk_size)
            while chunk:
                if self.conf_secrets['use_encryption']:
                    chunk: bytes = self.cipher.encrypt(chunk)
                
                cursor.execute("""
                    UPDATE files
                    SET file_data = cast(file_data || ? AS BLOB)
                    WHERE data_id=?
                """, [chunk, user_id, non_deleted_id])
                chunk: bytes = file_stream.read(chunk_size)

        return 0

    def remove_file(
            self, username: str,
            file_path: str,

            permanent_delete: bool = False
    ) -> int | str:
        self._ensure_open()
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"
                        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])
            file_data: list[tuple[str]] = cursor.fetchall()

        if not file_data:
            return "NO_FILE_EXISTS"

        non_deleted_id = ""
        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                
                if tmp_delete_data:
                    continue

                non_deleted_id: str = file_id
                break
        
        if not non_deleted_id:
            return "NO_FILE_EXISTS"

        with transaction(self.db) as cursor:
            if permanent_delete:
                cursor.execute("""
                    DELETE FROM files
                    WHERE user_id=? AND filename=? AND data_id=?
                """, [user_id, file_path, non_deleted_id])
            else:
                delete_id: str = str(uuid.uuid4())
                cursor.execute("""
                    INSERT INTO deleted_files (
                        delete_id, data_id, old_filepath
                    ) VALUES (?, ?, ?)
                """, [delete_id, non_deleted_id, file_path])
        
        return 0

    def read_file(
            self, username: str,
            file_path: str,
            chunk_size: int = 50 * 1024 * 1024
    ) -> str | Generator[bytes, None, None]:
        self._ensure_open()
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")
        
        if not isinstance(chunk_size, int):
            raise TypeError("'chunk_size' must be an int")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id, length(file_data) FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])

            file_data: list[tuple[str]] = cursor.fetchall()
        
        if not file_data:
            return "NO_FILE_EXISTS"

        non_deleted_id: str = ""
        data_length: int = 0

        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                
                if tmp_delete_data:
                    continue

                non_deleted_id: str = file_id
                data_length: int = file_tuple[1]

                break

        if not non_deleted_id:
            return "NO_FILE_EXISTS"

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT config FROM files_config
                WHERE data_id=?
            """, [non_deleted_id])

            msgpack_config: bytes = cursor.fetchone()[0]
        
        config: dict = msgpack.unpackb(msgpack_config)

        if config['chunk-size'] != chunk_size:
            chunk_size: int = config['chunk-size']

        def generator():
            offset: int = 1
            with transaction(self.db) as cursor:
                while offset < data_length:
                    cursor.execute("""
                        SELECT substr(file_data, ?, ?) 
                        FROM files WHERE data_id=?
                    """, (offset, chunk_size, non_deleted_id))

                    chunk: bytes = cursor.fetchone()[0]
                    offset += chunk_size

                    if self.conf_secrets['use_encryption']:
                        chunk: bytes = self.cipher.decrypt(chunk)
                    
                    yield chunk
        
        # Returning generator() instead of yield directly
        # allows the function to return plain values instead of
        # requiring me to use next() and then checking the value
        return generator()
        

class DatabaseAdmin:
    def __init__(self, parent: FileDatabase, log_level: int = logging.DEBUG) -> None:
        self.db: sqlite3.Connection = parent.db
        self.recovery_mode: bool = parent.recovery_mode

        self.pw_hasher: argon2.PasswordHasher = parent.pw_hasher
        self.cipher: SimpleCipher = parent.cipher

        self.conf_secrets: dict = parent.conf_secrets
        self.conf_vars: dict = parent.conf_vars

        self.cipher_conf: dict = parent.cipher_conf
        self.hash_method = parent.hash_method

        self.logger: logging.Logger = logging.getLogger(f"{__name__}: serverDB-DBAdmin")
        self.logger.setLevel(log_level)

        fmt_msg: str = (
            '[syncServer-serverDB: DatabaseAdmin]: [%(asctime)s] ' 
            '- [%(levelname)s] - (%(funcName)s): %(message)s'
        )
        formatter: logging.Formatter = logging.Formatter(
            fmt_msg,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler: logging.FileHandler = logging.FileHandler(LOGFILE)

        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def set_protection(
            self, cipher_key: bytes | str,
            recovery_key_path: str = ''
    ) -> int:
        """
        Update encryption key or disable encryption, then write recovery key to file.
        Set `cipher_key` to an empty string to disable encryption.  
        """
        if self.recovery_mode:
            raise RuntimeError("cannot edit database configuration, currently in recovery mode")
        
        if not isinstance(recovery_key_path, str):
            raise TypeError("recovery key path must be a string")
        
        match cipher_key:
            case bytes():
                pass
            case str():
                cipher_key: bytes = cipher_key.encode('utf-8')
            case _:
                raise TypeError("encryption key is not bytes or string")

        if os.path.isfile(recovery_key_path) and cipher_key:
            raise FileExistsError(f"cannot overwrite existing recovery key file: {recovery_key_path}")
        
        if not recovery_key_path and cipher_key:
            raise ValueError("recovery key path cannot be empty")
        
        conf_secrets: dict = copy.deepcopy(self.conf_secrets)
        conf_vars: dict = copy.deepcopy(self.conf_vars)

        if not cipher_key:  # False
            conf_secrets['use_encryption'] = False
            conf_vars['syncServer-protected'] = False

            bytes_encoded_secrets: bytes = msgpack.packb(conf_secrets)
            bytes_encoded_vars: bytes = msgpack.packb(conf_vars)

            try:
                with transaction(self.db) as cursor:
                    cursor.execute("""
                        UPDATE config
                        SET config_data=?, config_vars=?
                        WHERE config_id='main'
                    """, [bytes_encoded_secrets, bytes_encoded_vars])
            except sqlite3.Error:  # type: ignore
                self.logger.exception("(set_protection): Failed to write configuration to database")
                return 2
            
            self.logger.info("(set_protection): Disabled database protection")
            self.conf_secrets: dict = conf_secrets

            self.conf_vars: dict = conf_vars
            return 0 
        
        recovery_key: str = secrets.token_hex(32)
        current_umask: int = os.umask(0)
        
        mainkey_cipher: SimpleCipher = SimpleCipher(cipher_key, hash_method=self.hash_method)
        recoverykey_cipher: SimpleCipher = SimpleCipher(recovery_key, hash_method=self.hash_method)

        encrypted_cipher_key: bytes = recoverykey_cipher.encrypt(cipher_key)

        conf_vars['syncServer-recoveryKey'] = encrypted_cipher_key
        conf_secrets['use_encryption'] = True

        conf_vars['syncServer-protected'] = True
        conf_vars['syncServer-encryptionEnabled'] = True

        encrypted_secrets: bytes = mainkey_cipher.encrypt(msgpack.packb(conf_secrets))
        encoded_vars: bytes = msgpack.packb(conf_vars)

        try:
            with os.fdopen(os.open(recovery_key_path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
                f.write(recovery_key)
            
            self.logger.info("(set_protection: Wrote recovery key to file '%s'", recovery_key_path)
        except IOError:
            self.logger.exception("(set_protection): Failed to write recovery key")
            return 1
        finally:
            os.umask(current_umask)
        
        try:
            with transaction(self.db) as cursor:
                cursor.execute("""
                    UPDATE config
                    SET config_data=?, config_vars=?
                    WHERE config_id='main'
                """, [
                    encrypted_secrets,
                    encoded_vars
                ])
        except Exception:  # type: ignore
            self.logger.exception("(set_protection): Failed to write configuration to database")
            os.remove(recovery_key_path)

            self.logger.info("(set_protection): Removed recovery key file '%s'", recovery_key_path)
            return 2

        self.logger.info("(set_protection): Encrypted config secrets and wrote config to database")

        self.conf_secrets: dict = conf_secrets
        self.conf_vars: dict = conf_vars
        return 0

    def save_conf(self, _secrets: dict = None, _vars: dict = None) -> int:
        if not _secrets:
            pass
        elif self.conf_vars['syncServer-protected']:
            conf_secrets: bytes = self.cipher.encrypt(msgpack.packb(_secrets))
        else:
            conf_secrets: bytes = msgpack.packb(_secrets)
        
        with transaction(self.db) as cursor:
            if _secrets:
                cursor.execute("""
                    UPDATE config
                    SET config_data=?
                    WHERE config_id='main'
                """, [conf_secrets])
            if _vars:
                cursor.execute("""
                    UPDATE config
                    SET config_vars=?
                    WHERE config_id='main'
                """, [msgpack.packb(_vars)])
        
        return 0

    def update_encryption(
            self, old_key: bytes | str = b'',
            new_key: bytes | str = b''
    ) -> int:
        if self.recovery_mode:
            raise RuntimeError("cannot edit database configuration, currently in recovery mode")
        
        match old_key:
            case bytes():
                pass
            case str():
                old_key: bytes = old_key.encode('utf-8')
            case _:
                raise TypeError("old encryption key is not bytes or string")
        
        match new_key:
            case bytes():
                pass
            case str():
                new_key: bytes = new_key.encode('utf-8')
            case _:
                raise TypeError("new encryption key is not bytes or string")
        
        # Have to fetch the user_id and dir_id due to SQLite foreign key constraints
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id, length(file_data), user_id, dir_id
                FROM files
            """)
            file_data: list[tuple[str, int, str, str]] = cursor.fetchall()

        oldkey_cipher: SimpleCipher = SimpleCipher(
            old_key, hash_method=self.hash_method,
            hash_pepper=self.cipher_conf['hash_pepper'],
            password_pepper=self.cipher_conf['password_pepper']
        )
        newkey_cipher: SimpleCipher = SimpleCipher(
            new_key, hash_method=self.hash_method,
            hash_pepper=self.cipher_conf['hash_pepper'],
            password_pepper=self.cipher_conf['password_pepper']
        )
        
        for file_tuple in file_data:
            file_id: str = file_tuple[0]
            data_length: int = file_tuple[1]

            user_id: str = file_tuple[2]
            dir_id: str = file_tuple[3]

            tmp_id: str = secrets.token_hex(32)
            with transaction(self.db) as cursor:
                cursor.execute("""
                    SELECT config FROM files_config
                    WHERE data_id=?
                """, [file_id])

                fetched_conf: tuple[bytes] = cursor.fetchone()
                if not fetched_conf:
                    self.logger.warning("(update_encryption): File ID '%s' has no file config data", file_id)
                    continue

                msgpack_file_conf: bytes = fetched_conf[0]
                file_conf: dict = msgpack.unpackb(msgpack_file_conf)

                chunk_size: int = file_conf['chunk-size']
                copy_offset: int = 1

                write_offset: int = 1
                cursor.execute("""
                    INSERT INTO files (data_id, dir_id, user_id, filename, file_data)
                    VALUES (?, ?, ?, ?, ?)
                """, [tmp_id, dir_id, user_id, '', b''])
                
                while copy_offset < data_length:
                    cursor.execute("""
                        SELECT substr(file_data, ?, ?)
                        FROM files
                        WHERE data_id=?
                    """, [copy_offset, chunk_size, file_id])
                    chunk: bytes = cursor.fetchone()[0]

                    copy_offset += chunk_size
                    cursor.execute("""
                        UPDATE files
                        SET file_data = cast(file_data || ? AS BLOB)
                        WHERE data_id=?
                    """, [chunk, tmp_id])
                
                cursor.execute("""
                    UPDATE files SET file_data=cast(? AS BLOB)
                    WHERE data_id=?
                """, [b'', file_id])
                
                while write_offset < data_length:
                    cursor.execute("""
                        SELECT substr(file_data, ?, ?)
                        FROM files
                        WHERE data_id=?
                    """, [write_offset, chunk_size, tmp_id])
                    data: bytes = cursor.fetchone()[0]

                    if old_key:
                        chunk: bytes = oldkey_cipher.decrypt(data)
                    
                    if new_key:
                        chunk: bytes = newkey_cipher.encrypt(chunk)
                    
                    write_offset += chunk_size
                    cursor.execute("""
                        UPDATE files SET file_data = cast(file_data || ? AS BLOB)
                        WHERE data_id=?
                    """, [chunk, file_id])
                
                cursor.execute("DELETE FROM files WHERE data_id=?", [tmp_id])
            
            vac_cur: sqlite3.Cursor = self.db.cursor()
            vac_cur.execute("VACUUM")
            
            vac_cur.close()
            self.logger.info("(update_encryption): Updated file '%s' for user ID '%s'", file_id, user_id)

        return 0
    
    def key_recovery(self, recovery_key: bytes | str) -> int | dict:
        match recovery_key:
            case bytes():
                pass
            case str():
                recovery_key: bytes = recovery_key.encode('utf-8')
            case _:
                raise TypeError("recovery key is not bytes or string")
        
        recov_cipher: SimpleCipher = SimpleCipher(recovery_key, hash_method=self.hash_method)
        original_encrypted_key: bytes = self.conf_vars.get('syncServer-recoveryKey')

        if not original_encrypted_key:
            raise ValueError("'syncServer-recoveryKey' could not be found in the config variables")
        
        try:
            original_key: bytes = recov_cipher.decrypt(original_encrypted_key)
        except cryptography.exceptions.InvalidTag:
            self.logger.error("(key_recovery): Key decryption failed using recovery key")
            return 1
        
        return original_key


class DirectoryInterface:
    def __init__(self, parent: FileDatabase) -> None:
        self.db: sqlite3.Connection = parent.db

        self.pw_hasher: argon2.PasswordHasher = parent.pw_hasher
        self.cipher: SimpleCipher = parent.cipher

        self.conf_secrets: dict = parent.conf_secrets
        self.conf_vars: dict = parent.conf_vars

        self.cipher_conf: dict = self.conf_secrets['encryption_config']
        self._get_userid = parent._get_userid

        self._get_dirid = parent._get_dirid
    
    def make_dir(
            self, username: str,
            dir_path: str
    ) -> int | str:
        if not isinstance(dir_path, str):
            raise TypeError("'dir_path' must be string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self._get_dirid(dir_path, user_id)
        if dir_id:
            return "DIR_EXISTS"
        
        if not dir_path:
            return "MISSING_PATH"
        
        if dir_path[0] != "/":
            dir_path = "/" + dir_path
        
        dirs: list[str] = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue

            if not dir_name:
                return "INVALID_DIR_PATH"
            
        dir_id: str = str(uuid.uuid4())
        with transaction(self.db) as cursor:
            cursor.execute("""
                INSERT INTO directories (dir_id, user_id, dir_name)
                VALUES (?, ?, ?)
            """, [dir_id, user_id, dir_path])
        
        return 0

    def remove_dir(
            self, username: str,
            dir_path: str
    ) -> int | str:
        if not isinstance(dir_path, str):
            raise TypeError("'dir_path' must be string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self._get_dirid(dir_path, user_id)
        if not dir_id:
            return "NO_DIR_EXISTS"
        
        if dir_path == "/":
            return "ROOT_DIR"
        
        dirs: list[str] = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue

            if not dir_name:
                return "INVALID_DIR_PATH"

        with transaction(self.db) as cursor:
            cursor.execute("""
                DELETE FROM directories
                WHERE dir_id=? AND user_id=?
            """, [dir_id, user_id])
            
        return 0

    def list_dir(
            self, username: str,
            dir_path: str, list_deleted_only: bool = False
    ) -> str | list[str]:
        if not isinstance(dir_path, str):
            raise TypeError("'dir_path' must be string")

        if not isinstance(list_deleted_only, bool):
            raise TypeError("'list_deleted_only' can only be bool")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self._get_dirid(dir_path, user_id)
        if not dir_id:
            return "NO_DIR_EXISTS"
        
        dirs: list[str] = dir_path.split("/")
        for i, dir_name in enumerate(dirs):
            if i == 0:
                continue
            elif dir_path == "/":
                break

            if not dir_name:
                return "INVALID_DIR_PATH"

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT filename, data_id FROM files
                WHERE dir_id=? AND user_id=?
            """, [dir_id, user_id])
            dir_listing: list[tuple[str, str]] = cursor.fetchall()

        def is_deleted(file_id):
            with transaction(self.db) as cursor:
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                """, [file_id])
                delete_data: tuple[str] | None = cursor.fetchone()
            
            return bool(delete_data) 
        
        if list_deleted_only:
            files: list[str] = [i[0] for i in dir_listing if is_deleted(i[1])]
        else:
            files: list[str] = [i[0] for i in dir_listing if not is_deleted(i[1])]
        
        return files
    
    def get_dir_paths(self, username: str) -> str | list[str]:
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT dir_name FROM directories
                WHERE user_id=?
            """, [user_id])

            dirs: list[tuple[str]] = cursor.fetchall()
        
        if not dirs:
            return "NO_DIRS"  # This means even the root directory (/) is missing
        
        return [pathlist[0] for pathlist in dirs]


class DeletedFiles:
    def __init__(self, parent: FileDatabase) -> None:
        self.db: sqlite3.Connection = parent.db

        self.pw_hasher: argon2.PasswordHasher = parent.pw_hasher
        self.cipher: SimpleCipher = parent.cipher

        self.conf_secrets: dict = parent.conf_secrets
        self.conf_vars: dict = parent.conf_vars

        self.cipher_conf: dict = self.conf_secrets['encryption_config']
        self.dir_checker = parent.dir_checker

        self._get_userid = parent._get_userid
    
    def list_deleted(
            self, username: str,
            file_path: str
    ) -> str | list[str] | dict:
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")

        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"

        if file_path == ":all:":
            with transaction(self.db) as cursor:
                cursor.execute("""
                    SELECT filename, data_id FROM files
                    WHERE user_id=?
                """, [user_id])
                file_ids: list[tuple[str, str]] = cursor.fetchall()

            grouped_data: dict[str, list] = {}
            for item in file_ids:
                filename, data_id = item
                if filename in grouped_data:
                    grouped_data[filename].append(data_id)
                else:
                    grouped_data[filename] = [data_id]

            # Convert dictionary values to lists of tuples
            result: list = [[(key, val) for val in grouped_data[key]] for key in grouped_data]
            all_results: dict = {}

            with transaction(self.db) as cursor:
                for path_and_id_tuple in result:
                    for file_path, file_id in path_and_id_tuple:
                        if file_path not in all_results:
                            all_results[file_path] = []
                        
                        cursor.execute("""
                            SELECT delete_date FROM deleted_files
                            WHERE data_id=?
                            ORDER BY delete_date DESC
                        """, [file_id])
                        tmp_del_date: tuple[str] = cursor.fetchone()

                        if tmp_del_date:
                            all_results[file_path].append(tmp_del_date[0])
                    
                    file_path = path_and_id_tuple[0][0]
                    all_results[file_path] = sorted(all_results[file_path], reverse=True)
                
            return all_results

        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])
            file_data: list[tuple[str]] = cursor.fetchall()
        
        if not file_data:
            return "NO_MATCHING_FILES"

        delete_data: list = []
        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT delete_date FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC;
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                if tmp_delete_data:
                    delete_data.append(tmp_delete_data[0])
                    continue

        if not delete_data:
            return "NO_MATCHING_FILES"

        return sorted(delete_data, reverse=True)

    def restore_file(
            self, username: str,
            file_path: str,
            restore_which: int = 0
    ) -> str | int:
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")

        if not isinstance(restore_which, int):
            # Removed implicit restore
            raise TypeError("'restore_which' must be an int")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])

            file_data: list[tuple[str]] = cursor.fetchall()
        
        if not file_data:
            return "NO_FILE_EXISTS"

        delete_data: list = []
        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                if tmp_delete_data:
                    del_data_id = tmp_delete_data[0]
                    delete_data.append(del_data_id)

                    continue

                # Assume all IDs are in the deleted_files table, if not
                # then assume there is one file that is not marked deleted
                return "FILE_CONFLICT"

        if not delete_data:
            return "FILE_NOT_DELETED"
        
        # If the value of restore_which is bigger than the length of deleted file ids
        # minus one (since we index starting from zero), then assume out of bounds
        def in_bounds():
            if restore_which < 0:
                return False
            
            if restore_which > len(delete_data) - 1:
                return False
            
            return True
        
        if not in_bounds():
            return "OUT_OF_BOUNDS"

        # SQLite3 returns the whole list oldest -> latest so we reverse it
        delete_data: list = list(reversed(delete_data))

        with transaction(self.db) as cursor:
            # Fetch the list with the data ids and then get the data id
            # [ ('data-id') ] -> delete_data[restore_which]

            data_id: str = delete_data[restore_which]
            cursor.execute("""
                DELETE FROM deleted_files
                WHERE data_id=?
            """, [data_id])

        return 0
    
    def true_delete(
            self, username: str,
            file_path: str,
            delete_which: int | Literal[':all:'] = 0
    ) -> str | int:
        if not isinstance(file_path, str):
            raise TypeError("'file_path' must be string")

        if not (delete_which == ":all:" or isinstance(delete_which, int)):
            raise TypeError("'delete_which' can only be an int or ':all:'")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        dir_id: str = self.dir_checker(username, file_path)
        if not dir_id:
            return "NO_DIR_EXISTS"

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT data_id FROM files
                WHERE filename=? AND user_id=? AND dir_id=?
            """, [file_path, user_id, dir_id])

            file_data: list[tuple[str]] = cursor.fetchall()
        
        if not file_data:
            return "NO_MATCHING_FILES"

        delete_data: list = []
        with transaction(self.db) as cursor:
            for file_tuple in file_data:
                file_id: str = file_tuple[0]
                cursor.execute("""
                    SELECT data_id FROM deleted_files
                    WHERE data_id=?
                    ORDER BY delete_date DESC
                """, [file_id])

                tmp_delete_data: tuple[str] = cursor.fetchone()
                if tmp_delete_data:
                    del_data_id: str = tmp_delete_data[0]
                    delete_data.append(del_data_id)

                    continue
        
        if not delete_data:
            return "NO_MATCHING_FILES"

        # If the value of delete_which is bigger than the length of deleted file ids
        # minus one (since we index starting from zero), then assume out of bounds
        def in_bounds() -> bool:
            if delete_which == ":all:":
                return True  # skip when deleting all versions
            
            if delete_which < 0:
                return False
            
            if delete_which > len(delete_data) - 1:
                return False
            
            return True
        
        if not in_bounds():
            return "OUT_OF_BOUNDS"

        # SQLite3 returns the whole list oldest -> latest so we reverse it
        delete_data: list[str] = list(reversed(delete_data))

        with transaction(self.db) as cursor:
            if delete_which == ":all:":            
                for file_id_to_delete in delete_data:
                    cursor.execute("""
                        DELETE FROM files
                        WHERE data_id=?
                    """, [file_id_to_delete])
            else:
                delete_which_id: str = delete_data[delete_which]
                cursor.execute("""
                    DELETE FROM files
                    WHERE data_id=?
                """, [delete_which_id])
            
        return 0


class APIKeyInterface:
    def __init__(self, parent: FileDatabase) -> None:
        self.db: sqlite3.Connection = parent.db

        self.pw_hasher: argon2.PasswordHasher = parent.pw_hasher
        self.cipher: SimpleCipher = parent.cipher

        self.conf_secrets: dict = parent.conf_secrets
        self.conf_vars: dict = parent.conf_vars

        self.cipher_conf: dict = self.conf_secrets['encryption_config']

        self.perms_list: list[str] = ['create', 'read', 'update', 'delete', 'all']
        self._get_userid = parent._get_userid
    
    def _hash_key(self, api_key: str) -> str:
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be string")
        
        api_key: bytes = api_key.encode('utf-8')
        
        hash_pepper: bytes = self.cipher_conf.get('hash_pepper', b'')
        hashed_apikey: str = self.cipher.hash_data(api_key + hash_pepper)

        return hashed_apikey
    
    def get_key_owner(self, api_key: str) -> str:
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be a string")

        hashed_apikey: str = self._hash_key(api_key)
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT user_id, key_id FROM user_apikeys
                WHERE api_key=?
            """, [hashed_apikey])
            key_data: tuple[str] = cursor.fetchone()
        
        if not key_data:
            return "INVALID_APIKEY"
        
        user_id: str = key_data[0]
        key_id: str = key_data[1]

        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT username FROM users
                WHERE user_id=?
            """, [user_id])
            user_data: tuple[str] = cursor.fetchone()
            
        if not user_data:
            logging.warning(
                "[APIKeyInterface-keyWithoutOwner]: An key was found in "
                "the database, but has no owner. Key ID: [%s]",
                key_id
            )
            return "INVALID_APIKEY"  # key has no owner but exists in the database
        
        return user_data[0]

    def verify_key(
            self, api_key: str,
            permission_type: str
    ) -> int | str:
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be a string")

        if not isinstance(permission_type, str):
            raise TypeError("'permission_type' must be a string")
        
        if permission_type not in self.perms_list:
            return "INVALID_PERMISSION"
        
        hashed_apikey: str = self._hash_key(api_key)
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT user_id, key_perms FROM user_apikeys
                WHERE api_key=?
            """, [hashed_apikey])
            perms_data: tuple[str] = cursor.fetchone()
            
        if not perms_data:
            return "INVALID_APIKEY"

        encoded_key_perms: bytes = perms_data[1]
        key_perms: list[str] = msgpack.unpackb(encoded_key_perms)

        if permission_type not in key_perms:
            return "APIKEY_NOT_AUTHORIZED"

        return 0

    def create_key(
            self, username: str, 
            key_perms: list[str],

            key_name: str, 
            expires_on: str
    ) -> str:
        if not isinstance(username, str):
            raise TypeError("'username' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")

        if not isinstance(key_perms, list):
            raise TypeError("'key_perms' can only be an list")
        
        for perms in key_perms:
            # 'all' is used to allow access from all API keys in the _verify function
            if perms not in self.perms_list or perms == 'all':
                return "INVALID_KEYPERMS"
        
        try:
            expiry_date: datetime = datetime.strptime(expires_on, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "INVALID_DATETIME"

        date_today: datetime = datetime.now()
        if date_today > expiry_date:
            # Prevent creating an already expired API key
            return "DATE_EXPIRED"
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        salt: bytes = secrets.token_hex(32)
        hashed_userid: str = self.cipher.hash_data(user_id + salt)

        api_key: str = f"syncServer-{hashed_userid}"
        hashed_apikey: str = self._hash_key(api_key)

        key_id: str = str(uuid.uuid4())
        encoded_key_perms: bytes = msgpack.packb(key_perms)

        insert_data: list[str] = [
            key_id, user_id, key_name,
            hashed_apikey, encoded_key_perms, expires_on
        ]
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT key_id FROM user_apikeys
                WHERE key_name=? AND user_id=?
            """, [key_name, user_id])
            key_data: tuple[str] = cursor.fetchone()

            if key_data:
                return "APIKEY_EXISTS"
            
            cursor.execute("""
                INSERT INTO user_apikeys (
                    key_id, user_id, key_name,
                    api_key, key_perms, expiry_date
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, insert_data)
        
        return api_key
    
    def delete_key(
            self, username: str,
            key_name: str,
    ) -> int | str:
        if not isinstance(username, str):
            raise TypeError("'username' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
                
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT key_id FROM user_apikeys
                WHERE key_name=? AND user_id=?
            """, [key_name, user_id])
            key_data: tuple[str] = cursor.fetchone()

            if not key_data:
                return "INVALID_APIKEY"
            
            key_id: str = key_data[0]
            cursor.execute("""
                DELETE FROM user_apikeys
                WHERE key_id=? AND user_id=?
            """, [key_id, user_id])
        
        return 0

    def list_keys(self, username: str) -> str | list[str]:
        if not isinstance(username, str):
            raise TypeError("'username' must be a string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT key_name FROM user_apikeys
                WHERE user_id=?
            """, [user_id])
            key_data: tuple[str] = cursor.fetchall()
            
        if not key_data:
            return []

        return [key_tuple[0] for key_tuple in key_data]
    
    def apikey_get_data(self, api_key: str) -> list[list[str], str] | str:
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be a string")
        
        hashed_apikey: str = self._hash_key(api_key)
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT key_perms, expiry_date FROM user_apikeys
                WHERE api_key=?
            """, [hashed_apikey])
            key_data: tuple[bytes, str] = cursor.fetchone()

        if not key_data:
            return "INVALID_APIKEY"

        key_perms: list[str] = msgpack.unpackb(key_data[0])
        expiry_date: str = key_data[1]
        
        return [key_perms, expiry_date]
    
    def keyname_get_data(self, username: str, key_name: str) -> list[list[str], str] | str:
        if not isinstance(username, str):
            raise TypeError("'username' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")
        
        user_id: str = self._get_userid(username)
        if not user_id:
            return "NO_USER"
        
        with transaction(self.db) as cursor:
            cursor.execute("""
                SELECT key_perms, expiry_date FROM user_apikeys
                WHERE user_id=? AND key_name=?
            """, [user_id, key_name])
            key_data: tuple[bytes, str] = cursor.fetchone()

        if not key_data:
            return "INVALID_APIKEY"
        
        key_perms: list[str] = msgpack.unpackb(key_data[0])
        expiry_date: str = key_data[1]
        
        return [key_perms, expiry_date]
        
    def check_expired(
            self, *, api_key: str = '', 
            key_name: str = '', 
            username: str = ''
    ) -> bool | str:
        if api_key and key_name:
            raise ValueError("must specify either api_key or key_name only")
        
        if not api_key and not key_name:
            raise ValueError("did not provide api_key or key_name")
        
        if key_name and not username:
            raise ValueError("must provide username if key_name is provided")
        
        if not isinstance(api_key, str):
            raise TypeError("'api_key' must be a string")
        
        if not isinstance(key_name, str):
            raise TypeError("'key_name' must be a string")
        
        if not isinstance(username, str):
            raise TypeError("'username' is not a string")
        
        with transaction(self.db) as cursor:
            if api_key:
                hashed_apikey: str = self._hash_key(api_key)
                cursor.execute("""
                    SELECT expiry_date FROM user_apikeys
                    WHERE api_key=?
                """, [hashed_apikey])
                expiry_data: tuple[str] = cursor.fetchone()
            else:
                user_id: str = self._get_userid(username)
                if not user_id:
                    return "NO_USER"
        
                cursor.execute("""
                    SELECT expiry_date FROM user_apikeys
                    WHERE key_name=? AND user_id=?
                """, [key_name, user_id])
                expiry_data: tuple[str] = cursor.fetchone()
            
        if not expiry_data:
            return "INVALID_APIKEY"
        
        expiry_date: datetime = datetime.strptime(expiry_data[0], "%Y-%m-%d %H:%M:%S")
        current_time: datetime = datetime.now()

        expired: bool = current_time > expiry_date
        return expired


class Main:
    def __init__(self) -> None:
        description: str = (
            "Command line tool to manage the syncServer database locally."
            f" Current application version: {__version__}"
        )
        self.parser: argparse.ArgumentParser = argparse.ArgumentParser(
            description=description,
            prog='syncserver.server-db'
        )
        self._add_args()
    
    def _add_args(self) -> None:
        self.parser.add_argument(
            '--database-path', '-db',
            action='store', 
            nargs='?',
            metavar='db-path',
            help="Path to syncServer database."
        )
        self.parser.add_argument(
            '--recover-key', '-rk',
            action='store_true',
            help="Recover the original encryption key with the key password."
        )
        self.parser.add_argument(
            '--edit-vars', '-ev',
            action='store_true',
            help='Edit configuration variables without fully initializing the database.'
        )
        self.parser.add_argument(
            '--edit-config', '-ec',
            action='store_true',
            help="Open the configuration and edit it with nano."
        )
        self.parser.add_argument(
            '--set-protection', '-sp',
            action='store_true',
            help="Set the encryption key that the database will use."
        )
        self.parser.add_argument(
            '--add-user', '-aU',
            action='store_true',
            help="Create a new user using provided credentials"
        )
        self.parser.add_argument(
            '--remove-user', '-rU',
            action='store_true',
            help="Remove an existing user."
        )

    def _fmt_data(self, data: dict | list, indent: int = 0) -> str:
        def format_value(value, indent):
            if isinstance(value, bytes):
                # Convert bytes to a string representation
                return f'{value}'
            elif isinstance(value, bool):
                # Convert boolean values to string representation without quotes
                return str(value)
            elif isinstance(value, dict):
                # Recursively format nested dictionaries
                return format_dict(value, indent + 4)
            elif isinstance(value, list):
                # Recursively format nested lists
                return format_list(value, indent + 4)
            else:
                return f'"{value}"'  # Quotes for other non-boolean values

        def format_list(data, indent=0):
            result = "[\n"
            for item in data:
                result += " " * indent + f'{format_value(item, indent)},\n'
            # Remove the trailing comma and add closing bracket with proper indentation
            result = result.rstrip(",\n") + "\n" + " " * (indent - 4) + "]"
            return result

        def format_dict(data, indent=0):
            result = "{\n"
            for key, value in data.items():
                result += " " * indent + f'"{key}": {format_value(value, indent)},\n'
            # Remove the trailing comma and add closing brace with proper indentation
            result = result.rstrip(",\n") + "\n" + " " * (indent - 4) + "}"
            return result
        
        match data:
            case list():
                return format_list(data, indent=indent)
            case dict():
                return format_dict(data, indent=indent)
            case _:
                raise TypeError("invalid type to format")
    
    def display_conf(self, formatted_data: str) -> str:
        with tempfile.NamedTemporaryFile('w+', delete=True, suffix=".py") as temp_file:
            temp_file.write(formatted_data)
            temp_file.flush()
                
            try:
                subprocess.check_call(
                    ['/bin/nano', temp_file.name], 
                    shell=False
                )
            except subprocess.CalledProcessError as e:
                self.parser.exit(1, f'nano threw an error: {e}\n')
            
            temp_file.seek(0)
            edited_conf_data: str = temp_file.read()
        
        return edited_conf_data
    
    def parse_args(self) -> None:
        args = self.parser.parse_args()
        if not args.database_path:
            args.database_path = ''
        
        recov_mode_db: FileDatabase = FileDatabase(
            db_path=args.database_path,
            recovery_mode=True
        )
        if args.recover_key:
            recov_key: str = getpass.getpass("Enter the exported recovery key: ")
            key: int | bytes = recov_mode_db.db_admin.key_recovery(recov_key)

            if key == 1:
                self.parser.exit(1, "Key decryption failed! Wrong recovery key?")
            
            self.parser.exit(0, f"Found original password: {key}\n")
        
        if args.edit_vars:
            formatted_data: str = self._fmt_data(recov_mode_db.conf_vars, indent=4)
            edited_conf_data: str = self.display_conf(formatted_data)

            try:
                edited_conf: dict = ast.literal_eval(edited_conf_data)
            except SyntaxError:
                self.parser.exit(1, "Invalid configuration syntax, is the syntax in Python?\n")

            recov_mode_db.db_admin.save_conf(None, edited_conf)
            if edited_conf == recov_mode_db.conf_vars:
                self.parser.exit(0, "No modifications to configuration variables.\n")
            
            self.parser.exit(0, "Saved configuration variables successfully!\n")
        
        if recov_mode_db.conf_vars.get('syncServer-protected'):
            db_password: str = getpass.getpass("Enter database password: ")
        else:
            db_password: str = ''
        
        normal_db: FileDatabase = FileDatabase(
            args.database_path,
            db_password
        )

        normal_conf_secrets: dict = normal_db.conf_secrets
        normal_conf_vars: dict = normal_db.conf_vars

        if args.edit_config:
            conf_data: dict = {
                'secrets': normal_conf_secrets, 
                'vars': normal_conf_vars
            }
            formatted_data: str = self._fmt_data(conf_data, indent=4)
            edited_conf_data: str = self.display_conf(formatted_data)
            
            try:
                edited_conf: dict = ast.literal_eval(edited_conf_data)
            except SyntaxError:
                self.parser.exit(1, "Invalid configuration syntax, is the syntax in Python?\n")
            
            if 'secrets' not in edited_conf or 'vars' not in edited_conf:
                self.parser.exit(2, "'secrets' or 'vars' configuration is missing!\n")
            
            secrets_is_same: bool = normal_conf_secrets == edited_conf['secrets']
            vars_is_same: bool = normal_conf_vars == edited_conf['vars']
            if secrets_is_same and vars_is_same:
                self.parser.exit(0, "No modifications to configuration settings.\n")
            
            normal_db.db_admin.save_conf(edited_conf['secrets'], edited_conf['vars'])
            self.parser.exit(0, 'Saved configuration successfully!\n')
        
        if args.set_protection:
            conf_data: dict = {'cipher_key': b"", 'recovery_key_path': ''}
            formatted_data: str = self._fmt_data(conf_data, indent=4)
            edited_conf_data: str = self.display_conf(formatted_data)
            
            try:
                edited_conf: dict = ast.literal_eval(edited_conf_data)
            except SyntaxError:
                self.parser.exit(1, "Invalid configuration syntax, is the syntax in Python?\n")

            cipher_key: bytes | str = edited_conf.get('cipher_key', -1)
            recovery_key_path: bytes | str = edited_conf.get('recovery_key_path')

            if cipher_key == -1:
                self.parser.exit(2, "'cipher_key' value is missing!\n")
            if not recovery_key_path and cipher_key:
                self.parser.exit(2, "'recovery_key_path' value is missing!\n")

            if not isinstance(cipher_key, (bytes, str)):
                self.parser.exit(3, "Cipher key is not bytes or string!\n")
            if not isinstance(recovery_key_path, (bytes, str)):
                self.parser.exit(3, "Recovery key path is not bytes or string!\n")
            
            with transaction(normal_db.db) as cursor:
                cursor.execute("SELECT data_id FROM files")
                file_data: tuple[str] = cursor.fetchone()

            if file_data:
                print(
                    "Files detected! The program will attempt to re-encrypt their contents. "
                    "This may take a while.\n"
                )
                continue_input: str = input("Continue? [y/N]: ")
                if continue_input.lower() != 'y':
                    self.parser.exit(0, "Aborted.\n")
                
            normal_db.db_admin.update_encryption(db_password, cipher_key)
            normal_db.db_admin.set_protection(cipher_key, recovery_key_path)

            self.parser.exit(0, "Updated encryption key!\n")
        
        if args.add_user:
            print("Now starting new user configuration!\n")
            username: str = input("Enter a username: ")
            password: str = getpass.getpass("Enter a password: ")

            if not username or not password:
                self.parser.exit(2, "Username or password is empty!\n")

            result: str | int = normal_db.add_user(username, password)
            if result == "USER_EXISTS":
                self.parser.exit(1, f"User '{username}' already exists!\n")
            
            self.parser.exit(0, f"Added new user '{username}'!\n")

        if args.remove_user:
            username: str = input("Enter the username to delete: ")
            if not username:
                self.parser.exit(2, "No username was provided!\n")
            
            result: int | str = normal_db.remove_user(username)
            if result == "NO_USER":
                self.parser.exit(1, "User does not exist!\n")

            self.parser.exit(0, f"Removed user '{username}' and their data successfully!\n")


def run_cli():
    main: Main = Main()
    main.parse_args()


if __name__ == "__main__":
    run_cli()
