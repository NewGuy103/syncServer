"""
syncServer Flask Application

Description:
This module defines a Flask application (syncServer) for handling file synchronization operations.
It includes routes for uploading, modifying, deleting, reading files, as well as operations on directories.

Usage:
python -m newguy103-syncserver

Dependencies:
- Flask: A micro web framework for Python.

Attributes:
- APP: Flask application instance.
- __version__: Current version of the syncServer application.

Classes:
- Routes: Class containing methods for handling different routes in the application.

Routes:
- /upload: POST endpoint for uploading files.
- /modify: POST endpoint for modifying files.
- /delete: POST endpoint for deleting files.
- /restore: POST endpoint for restoring deleted files.
- /list-deleted: POST endpoint to list deleted versions of a file.
- /true-delete: POST endpoint to true delete a deleted version of a file.
- /read: POST endpoint for reading files.
- /create-dir: POST endpoint for creating directories.
- /remove-dir: POST endpoint for removing directories.
- /list-dir: POST endpoint for listing directory contents.
- /: Root endpoint, returns a JSON response indicating the server is alive.
"""


import logging
import json
import getpass

import secrets
import types
import os

import flask

from flask import Flask, request

#from ._db import FileDatabase 
from _db import FileDatabase  # use the above import once making setup.py

__version__: str = "1.0.0"
APP: flask.Flask = Flask(__name__)

class Routes:
    def __init__(
        self, db_password: bytes | str = None
    ):
        self.db: FileDatabase = FileDatabase(db_password=db_password)
        self.read_chunk_size: int = 50 * 1024 * 1024  # 50MB

    def _verify_credentials(self, username: str, token: str) -> flask.Response | int:
        """
        Return response depending on token verification status
        
        Parameters:
            username (str): Username to verify
            password (str): Password to verify
        """
        if not username or not token:
            err_response = flask.make_response({
                'error': "No verification credentials were sent.",
                'ecode': "MISSING_CREDENTIALS"
            }, 401)
            return err_response

        token_verified_result = self.db.verify_user(username, token)
        if not token_verified_result or token_verified_result == "NO_USER":
            err_response = flask.make_response({
                'error': "User credentials are invalid.",
                'ecode': "INVALID_CREDENTIALS"
            })
            return err_response
        
        if isinstance(token_verified_result, Exception):
            logging.error("[FLASK-VERIFY-USER]: Refer to [Database.verify_user] error logs for information")
            return flask.abort(500)

        return 0

    def file_uploads(self):
        files = request.files
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")
        
        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if len(files) == 0:
            return flask.make_response({
                'error': 'No files provided to upload',
                'ecode': 'MISSING_FILES'
            }, 400)
        
        successful_runs = []
        failed_runs = {}

        response_code = 200

        for file in files.values():
            if not file.name:
                return_name = f'unnamed-remote-[{file.filename}]-{secrets.randbelow(10**6)}'
                failed_runs[return_name] = {
                    'error': "No remote path was specified for this filename",
                    'ecode': "NO_REMOTE_PATH"
                }
                response_code = 400
                continue
            elif not isinstance(file.name, (bytes, str)):
                return_name = f'wrong-content-type-[{file.name}]-{secrets.randbelow(10**6)}'
                failed_runs[return_name] = {
                    'error': 'Remote file path is not bytes or string',
                    'ecode': 'INVALID_CONTENT'
                }
                response_code = 400
                continue
            
            stream_data = file.stream.read(1)
            if not stream_data:
                failed_runs[file.name] = {
                    'error': "File stream is empty",
                    'ecode': "EMPTY_STREAM"
                }
                response_code = 400
                continue
            
            file.stream.seek(0)
            result = self.db.add_file(
                username, file.name, 
                file.stream
            )
            match result:
                case "NO_DIR_EXISTS":
                    failed_runs[file.name] = {
                        'error': "Directory path does not exist",
                        'ecode': result
                    }
                    response_code = 400
                case "FILE_EXISTS":
                    failed_runs[file.name] = {
                        'error': (
                            "Target file path already exists. Use /modify to edit a file or"
                            " check the filename."
                        ),
                        'ecode': result
                    }
                    response_code = 409
                case 0:
                    successful_runs.append(file.name)
                case _:
                    logging.error(
                        "[/upload]: add_file function returned unexpected data: '%s'",
                        result
                    )
                    return flask.make_response({
                        'error': "Internal Server Error",
                        'ecode': "SERVER_ERROR"
                    }, 500)
        
        response = None
        match len(files):
            case 1 if failed_runs.keys():
                response = failed_runs
            case 1 if successful_runs:
                response = {
                    'batch': False,
                    'success': True
                }
            case _:
                response = {
                    'batch': True,
                    'ok': successful_runs,
                    'fail': failed_runs
                }
                response_code = 200

        return flask.make_response(response, response_code)

    def file_updates(self):
        files = request.files
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if len(files) == 0:
            return flask.make_response({
                'error': 'No files provided to modify',
                'ecode': 'MISSING_FILES'
            }, 400)
        
        successful_runs = []
        failed_runs = {}

        response_code = 200

        for file in files.values(): 
            if not file.name:
                return_name = f'unnamed-remote-[{file.filename}]-{secrets.randbelow(10**6)}'
                failed_runs[return_name] = {
                    'error': "No remote path was specified for this filename",
                    'ecode': "NO_REMOTE_PATH"
                }
                response_code = 400
                continue
            elif not isinstance(file.name, (bytes, str)):
                return_name = f'wrong-content-type-[{file.name}]-{secrets.randbelow(10**6)}'
                failed_runs[return_name] = {
                    'error': 'Remote file path is not bytes or string',
                    'ecode': 'INVALID_CONTENT'
                }
                response_code = 400
                continue

            stream_data = file.stream.read(1)
            if not stream_data:
                failed_runs[file.name] = {
                    'error': "File stream is empty",
                    'ecode': "EMPTY_STREAM"
                }
                response_code = 400
                continue
            
            file.stream.seek(0)
            result = self.db.modify_file(
                username, file.name, 
                file.stream
            )
            match result:
                case "NO_DIR_EXISTS":
                    failed_runs[file.name] = {
                        'error': "Directory path does not exist",
                        'ecode': result
                    }
                    response_code = 400
                case "NO_FILE_EXISTS":
                    failed_runs[file.name] = {
                        'error': (
                            "Target file path does not exist. Use /upload to create a file or"
                            " check the filename."
                        ),
                        'ecode': result
                    }
                    response_code = 404
                case 0:
                    successful_runs.append(file.name)
                case _:
                    logging.error(
                        "[/modify]: modify_file function returned unexpected data: '%s'",
                        result
                    )
                    return flask.make_response({
                        'error': "Internal Server Error",
                        'ecode': "SERVER_ERROR"
                    }, 500)
        
        response = None
        match len(files):
            case 1 if failed_runs.keys():
                response = failed_runs
            case 1 if successful_runs:
                response = {
                    'batch': False,
                    'success': True
                }
            case _:
                response = {
                    'batch': True,
                    'ok': successful_runs,
                    'fail': failed_runs
                }
                response_code = 200

        return flask.make_response(response, response_code)

    def file_deletes(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        file_paths: list[str] = data.get('file-paths', None)
        if file_paths is None:
            return flask.make_response({
                'error': 'No file paths provided to read',
                'ecode': 'MISSING_FILEPATHS'
            }, 400)

        true_delete: bool = data.get('true-delete', None)
        if true_delete is None:
            return flask.make_response({
                'error': "True delete parameter was not found",
                'ecode': "MISSING_PARAMETER"
            }, 400)
        
        if true_delete not in [True, False]:
            return flask.make_response({
                'error': "True delete parameter can only be bool",
                'ecode': "INVALID_PARAMETER"
            }, 400)
        
        if not isinstance(data['file-paths'], list):
            return flask.make_response({
                'error': "File paths can only be a list",
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        # Check each path in file-paths and filter out the ones that aren't 
        # bytes or string, and isn't empty
        filenames: list[str] = [
            str(item) for item in data['file-paths'] 
            if isinstance(item, (str, bytes)) and item
        ]
        
        successful_runs = []
        failed_runs = {}

        response_code = 200

        for file in filenames:
            result = self.db.remove_file(
                username, file,
                permanent_delete=true_delete
            )
            match result:
                case "NO_DIR_EXISTS":
                    failed_runs[file] = {
                        'error': "Directory path does not exist",
                        'ecode': result
                    }
                    response_code = 400
                case "NO_FILE_EXISTS":
                    failed_runs[file] = {
                        'error': (
                            "Target file path does not exist. Use /upload to upload a file or"
                            " check the filename."
                        ),
                        'ecode': result
                    }
                    response_code = 404
                case 0:
                    successful_runs.append(file)
                case _:
                    logging.error(
                        "[/delete]: remove_file function returned unexpected data: '%s'",
                        result
                    )
                    return flask.make_response({
                        'error': "Internal Server Error",
                        'ecode': "SERVER_ERROR"
                    }, 500)
        
        response = None
        match len(filenames):
            case 1 if failed_runs.keys():
                response = failed_runs
            case 1 if successful_runs:
                response = {
                    'batch': False,
                    'success': True
                }
            case 0: 
                response = {
                    'error': "filenames path is empty",
                    'ecode': "EMPTY_PATHLIST"
                }
                response_code = 400
            case _:
                response = flask.jsonify({
                    'batch': True,
                    'ok': successful_runs,
                    'fail': failed_runs
                })
                response_code = 200
            
        return flask.make_response(response, response_code)

    def file_restores(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        file_path: str = data.get('file-path', None)
        if file_path is None:
            return flask.make_response({
                'error': 'No file path provided to restore',
                'ecode': 'MISSING_FILEPATH'
            }, 400)

        restore_which: bool = data.get('restore-which', None)
        if restore_which is None:
            return flask.make_response({
                'error': "restore-which parameter was not found",
                'ecode': "MISSING_PARAMETER"
            }, 400)
        
        if restore_which not in [True, False]:
            return flask.make_response({
                'error': "restore-which parameter can only be bool",
                'ecode': "INVALID_PARAMETER"
            }, 400)
        
        if not isinstance(file_path, (bytes, str)):
            return flask.make_response({
                'error': 'file path provided is not bytes or str',
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        if file_path[0] != "/": 
            file_path: str = "/" + file_path
        
        response_code = 200
        result = self.db.deleted_files.restore_file(
            username, file_path, restore_which)

        match result:
            case 0:
                response = {'success': True} 
            case "NO_DIR_EXISTS":
                response = {
                    'error': "Directory path does not exist",
                    'ecode': result
                }
                response_code = 400
            case "NO_FILE_EXISTS":
                response = {
                    'error': (
                        "Target file path does not exist. Use /upload to upload a file or"
                        " check the filename."
                    ),
                    'ecode': result
                }
                response_code = 404
            case "FILE_CONFLICT":
                response = {
                    'error': "File with the same name exists and is not deleted",
                    'ecode': result
                }
                response_code = 409
            case "FILE_NOT_DELETED":
                response = {
                    'error': "No files with that name is deleted",
                    'ecode': result
                }
                response_code = 400
            case "OUT_OF_BOUNDS":
                response = {
                    'error': 'Attempted to access a deleted file out of bounds',
                    'ecode': result
                }
                response_code = 400
            case _:
                logging.error(
                    "[/restore]: restore_file function returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)
            
        return flask.make_response(response, response_code)
    
    def list_deleted(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        file_path: str = data.get('file-path', None)
        if file_path is None:
            return flask.make_response({
                'error': 'No file path provided to read',
                'ecode': 'MISSING_FILEPATH'
            }, 400)

        if not isinstance(file_path, (bytes, str)):
            return flask.make_response({
                'error': 'file path provided is not bytes or str',
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        if file_path != ":all:" and file_path[0] != "/":
            file_path: str = "/" + file_path
        
        response_code = 200
        result = self.db.deleted_files.list_deleted(
            username, file_path)
        
        match result:
            case dict() if file_path == ":all:":
                response = {
                    'batch': True,
                }
                response.update(result)
            case list():
                response = {
                    'batch': False,
                    'success': True,
                    'delete-order': result
                }
            case "NO_DIR_EXISTS":
                response = {
                    'error': "Directory path does not exist",
                    'ecode': result
                }
                response_code = 400
            case "NO_MATCHING_FILES":
                response = {
                    'error': "No files were deleted with that name",
                    'ecode': result
                }
                response_code = 404
            case _:
                logging.error(
                    "[/list-deleted]: list_deleted function returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)
        
        return flask.make_response(response, response_code)
    
    def remove_deleted(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        file_path: bytes | str = data.get('file-path', None)
        if file_path is None:
            return flask.make_response({
                'error': 'No file path provided to delete',
                'ecode': 'MISSING_FILEPATH'
            }, 400)

        delete_which: int = data.get('delete-which', None)
        if delete_which is None:
            return flask.make_response({
                'error': "delete-which parameter was not found",
                'ecode': "MISSING_PARAMETER"
            }, 400)

        # check if delete_which is 'all' or an int
        if not (delete_which != "all" or isinstance(delete_which, int)):
            return flask.make_response({
                'error': "delete-which parameter can only be int or 'all'",
                'ecode': "INVALID_PARAMETER"
            }, 400)

        if not isinstance(file_path, (bytes, str)):
            return flask.make_response({
                'error': 'file path provided is not bytes or str',
                'ecode': "INVALID_CONTENT"
            }, 400)

        response_code = 200
        result = self.db.deleted_files.true_delete(
            username, file_path,
            delete_which=delete_which
        )
        match result:
            case 0:
                response = {'success': True} 
            case "NO_DIR_EXISTS":
                response = {
                    'error': "Directory path does not exist",
                    'ecode': result
                }
                response_code = 400
            case "NO_FILE_EXISTS":
                response = {
                    'error': (
                        "Target file path does not exist. Use /upload to upload a file or"
                        " check the filename."
                    ),
                    'ecode': result
                }
                response_code = 404
            case "NO_MATCHING_FILES":
                response = {
                    'error': "No files with that name is deleted",
                    'ecode': result
                }
                response_code = 400
            case "OUT_OF_BOUNDS":
                response = {
                    'error': 'Attempted to access a deleted file out of bounds',
                    'ecode': result
                }
                response_code = 400
            case _:
                logging.error(
                    "[/true-delete]: true_delete function returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)
        
        return flask.make_response(response, response_code)

    def file_reads(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        file_path: str = data.get('file-path', None)
        if file_path is None:
            return flask.make_response({
                'error': 'No file path provided to read',
                'ecode': 'MISSING_FILEPATH'
            }, 400)

        if not isinstance(file_path, (bytes, str)):
            return flask.make_response({
                'error': 'file path provided is not bytes or str',
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        if file_path[0] != "/": 
            file_path: str = "/" + file_path

        result = self.db.read_file(username, file_path)
        response = None

        match result:
            case "NO_DIR_EXISTS":
                err_response = {
                    'error': "Directory path does not exist",
                    'ecode': result
                }
                response_code = 400
            case "NO_FILE_EXISTS":
                err_response = {
                    'error': (
                        "Target file path does not exist. Use /upload to upload a file or"
                        " check the filename."
                    ),
                    'ecode': result
                }
                response_code = 404
            case _ if isinstance(result, types.GeneratorType):
                response: flask.Response = flask.Response(
                    result, status=200,
                    direct_passthrough=True
                )
                dirs = file_path.split("/")

                filename = ''.join(dirs[-1])
                response.headers['Content-Disposition'] = f'attachment; filename={filename}'
            case _:
                logging.error(
                    "[/read]: remove_file function returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)
         
        return response or flask.make_response(flask.jsonify(err_response), response_code)
    
    def dir_creations(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        dir_path: str = data.get('dir-path', None)
        if dir_path is None:
            return flask.make_response({
                'error': 'No directory path provided to create',
                'ecode': 'MISSING_DIRPATH'
            }, 400)
        
        if not isinstance(dir_path, (bytes, str)):
            return flask.make_response({
                'error': "Directory path provided is not bytes or string",
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        result = self.db.make_dir(
            username, dir_path
        )

        response_code = 200
        match result:
            case "DIR_EXISTS":
                response = {
                    'error': 'Target directory exists, use /remove-dir to remove a directory.',
                    'ecode': result
                }
                response_code = 409
            case "MISSING_PATH":
                response = {
                    'error': 'Target directory path missing',
                    'ecode': result
                }
                response_code = 400
            case "INVALID_DIR_PATH":
                response = {
                    'error': 'Directory path is malformed or invalid',
                    'ecode': result
                }
                response_code = 400
            case 0:
                response = {'success': True}
            case _:
                logging.error(
                    "'self.db.make_dir' returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)
            
        return flask.make_response(response, response_code)
    
    def dir_deletions(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        dir_path: str = data.get('dir-path', None)
        if dir_path is None:
            return flask.make_response({
                'error': 'No directory path provided to create',
                'ecode': 'MISSING_DIRPATH'
            }, 400)
        
        if not isinstance(dir_path, (bytes, str)):
            return flask.make_response({
                'error': "Directory path provided is not bytes or string",
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        result = self.db.remove_dir(
            username, dir_path
        )

        response_code = 200
        match result:
            case "NO_DIR_EXISTS":
                response = {
                    'error': 'Target directory does not exist, use /create-dir to create a directory.',
                    'ecode': result
                }
                response_code = 404
            case "ROOT_DIR":
                response = {
                    'error': 'Cannot delete root directory',
                    'ecode': result
                }
                response_code = 400
            case "INVALID_DIR_PATH":
                response = {
                    'error': 'Directory path is malformed or invalid',
                    'ecode': result
                }
                response_code = 400
            case 0:
                response = {'success': True}
            case _:
                logging.error(
                    "'self.db.remove_dir' returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)

        return flask.make_response(response, response_code)
    
    def dir_listing(self):
        if not request.is_json:
            return flask.make_response({
                'error': "Provided request must be in a JSON format",
                'ecode': "415"
            }, 415)
        
        data = request.json
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        dir_path: str = data.get('dir-path', None)
        if dir_path is None:
            return flask.make_response({
                'error': 'No directory path provided to create',
                'ecode': 'MISSING_DIRPATH'
            }, 400)
        
        if not isinstance(dir_path, (bytes, str)):
            return flask.make_response({
                'error': "Directory path provided is not bytes or string",
                'ecode': "INVALID_CONTENT"
            }, 400)
        
        result: str | list[str] = self.db.list_dir(
            username, dir_path
        )

        response_code = 200
        match result:
            case "NO_DIR_EXISTS":
                response = {
                    'error': 'Target directory does not exist, use /create-dir to create a directory.',
                    'ecode': result
                }
                response_code = 404
            case "INVALID_DIR_PATH":
                response = {
                    'error': 'Directory path is malformed or invalid',
                    'ecode': result
                }
                response_code = 400
            case list():
                response = {
                    'dir-listing': result,
                    'success': True
                }
            case _:
                logging.error(
                    "'self.db.list_dir' returned unexpected data: '%s'",
                    result
                )
                return flask.make_response({
                    'error': "Internal Server Error",
                    'ecode': "SERVER_ERROR"
                }, 500)

        return flask.make_response(flask.jsonify(response), response_code)
    
    @staticmethod
    def root_route():
        return flask.jsonify({'alive': True})

def main():
    db_password: str = getpass.getpass(
        "Enter database password [or empty if not protected]: ")
    
    flask_route_port: int = os.environ.get('SYNCSERVER_PORT', 8561)

    routes: Routes = Routes(db_password=db_password)
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] - [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('app.log')
        ]
    )

    # routes
    APP.add_url_rule("/upload", view_func=routes.file_uploads, methods=['POST'])
    APP.add_url_rule("/modify", view_func=routes.file_updates, methods=['POST'])

    APP.add_url_rule("/delete", view_func=routes.file_deletes, methods=['POST'])
    APP.add_url_rule("/restore", view_func=routes.file_restores, methods=['POST'])
    
    APP.add_url_rule("/read", view_func=routes.file_reads, methods=['POST'])
    APP.add_url_rule("/list-deleted", view_func=routes.list_deleted, methods=['POST'])

    APP.add_url_rule("/true-delete", view_func=routes.remove_deleted, methods=['POST'])
    APP.add_url_rule("/create-dir", view_func=routes.dir_creations, methods=['POST'])
    APP.add_url_rule("/remove-dir", view_func=routes.dir_deletions, methods=['POST'])

    APP.add_url_rule("/list-dir", view_func=routes.dir_listing, methods=['POST'])
    APP.add_url_rule("/", view_func=routes.root_route)

    APP.run(debug=False, port=flask_route_port)

if __name__ == '__main__':
    main()
