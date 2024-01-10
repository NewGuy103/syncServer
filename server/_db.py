import sqlite3
import uuid
import secrets

import traceback
import logging

import argon2  # argon2-cffi
import cryptography
import msgpack

from pycrypter import CipherManager  # newguy103-pycrypter
from typing import BinaryIO, TextIO

def _log_excs(func_name: str, title_extra_data: str, exc_value: Exception):
    """
    Generates a formatted error log for exceptions raised within a specific function.

    The format is:

    [{func_name} {title_extra_data}][LF]|--| {exc_value}[LF]|--|

    Parameters:
        func_name (str): Name of the function where the exception occurred.
        title_extra_data (str): Additional title or context for the log.
        exc_value (Exception): Exception instance representing the raised error.

    """

    tb_data = traceback.format_exception(exc_value)
    logging.error(
        "[%s %s]\n|%s| %s\n|%s|",
        func_name,
        title_extra_data,
        '-' * 30,
        ''.join(tb_data),
        '-' * 30
    )



class FileDatabase:
    """Add docstring. . ."""
    def __init__(self, db_name='syncServer.db', db_password=b''):
        self.db = sqlite3.connect(db_name, check_same_thread=False)
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
                user_id TEXT,

                filename TEXT,           
                file_data BLOB,
                
                FOREIGN KEY (user_id) REFERENCES users(user_id)
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
                'syncServer-db-version': '1.0.0',
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

    def verify_user(self, username: str, token: str):
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
            _log_excs(
                "Database.verify_user",
                "VERIFY-HASH EXCEPTION",
                exc
            )
            return exc

        return True

    def add_user(self, username: str, token: str):
        self.cursor.execute("""
            SELECT user_id FROM users WHERE username=?
        """, [username])
        user_id = self.cursor.fetchone()

        if user_id:
            return "USER_EXISTS"

        hashed_pw = self.pw_hasher.hash(token)
        
        try:
            with self.db:
                user_id = str(uuid.uuid4())
                self.cursor.execute("""
                    INSERT INTO users VALUES (?, ?, ?)                
                """, [user_id, username, hashed_pw])
        except sqlite3.Error as exc:
            _log_excs(
                "Database.add_user",
                "INSERT ERROR",
                exc
            )
            return exc
        except Exception as exc:
            _log_excs(
                "Database.add_user",
                "INSERT EXCEPTION",
                exc
            )
            return exc

        return 0

    def remove_user(self, username: str, token: str):
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
            _log_excs(
                "Database.remove_user",
                "VERIFY-HASH EXCEPTION",
                exc
            )
            return exc

        try:
            with self.db:
                self.cursor.execute("""
                    DELETE FROM users
                    WHERE username=?
                """, [username])
        except sqlite3.Error as exc:
            _log_excs(
                "Database.add_user",
                "DELETE ERROR",
                exc
            )
            return exc
        except Exception as exc:
            _log_excs(
                "Database.remove_user",
                "DELETE EXCEPTION",
                exc
            )
            return exc

        return 0
                
    def add_file(
            self, username: str,
            token: str, filename: bytes | str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ):
        if not isinstance(filename, (bytes, str)):
            raise TypeError("'filename' must be bytes or str")
        
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
            raise IOError("file_stream is empty")
        
        self.cursor.execute("""
            SELECT data_id FROM files
            WHERE filename=? AND user_id=?
        """, [filename, user_id])

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
            self.cursor.execute("""
                INSERT INTO files (data_id, user_id, filename, file_data)
                VALUES (?, ?, ?, ?)
            """, [data_id, user_id, filename, first_chunk])
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
                    WHERE user_id=? AND filename=?
                """, [chunk, user_id, filename])
                chunk = file_stream.read(chunk_size)

        return 0

    def modify_file(
            self, username: str,
            token: str, filename: bytes | str,

            file_stream: BinaryIO | TextIO,
            chunk_size: int = 50 * 1024 * 1024
    ):
        if not isinstance(filename, (bytes, str)):
            raise TypeError("'filename' must be bytes or str")

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
            raise IOError("file_stream is empty")

        self.cursor.execute("""
            SELECT data_id FROM files
            WHERE filename=? AND user_id=?
        """, [filename, user_id])

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
                WHERE user_id=? AND filename=?
            """, [user_id, filename, first_chunk])
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
                """, [chunk, user_id, filename])
                chunk = file_stream.read(chunk_size)

        return 0

    def remove_file(
            self, username: str,
            token: str, filename: bytes | str
    ):
        if not isinstance(filename, (bytes, str)):
            raise TypeError("'filename' must be bytes or str")
        
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
            SELECT data_id FROM files
            WHERE filename=? AND user_id=?
        """, [filename, user_id])

        found_filename = self.cursor.fetchone()
        if not found_filename:
            return "NO_FILE_EXISTS"
        
        with self.db:
            self.cursor.execute("""
                DELETE FROM files
                WHERE user_id=? AND filename=?
            """, [user_id, filename])

        return 0

    def read_file(
            self, username: str,
            token: str, filename: bytes | str,
            chunk_size: int = 50 * 1024 * 1024
    ):
        if not isinstance(filename, (bytes, str)):
            raise TypeError("'filename' must be bytes or str")
        
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
            SELECT data_id, length(file_data) FROM files
            WHERE filename=? AND user_id=?
        """, [filename, user_id])

        db_result = self.cursor.fetchone()
        if not db_result:
            return "NO_FILE_EXISTS"
        
        data_id = db_result[0]
        data_length = db_result[1]

        self.cursor.execute("""
            SELECT config FROM files_config
            WHERE data_id=?
        """, [data_id])

        msgpack_config = self.cursor.fetchone()[0]
        config = msgpack.unpackb(msgpack_config)

        if config['chunk_size_used'] != chunk_size:
            chunk_size = config['chunk_size_used']
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

if __name__ == "__main__":
    raise NotImplementedError(
        "this module cannot be run using __main__ and can only be imported"
    )


