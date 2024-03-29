import logging
import getpass

import secrets
import types
import os

import flask

from flask import Flask, request

# from ._db import FileDatabase 
from _db import FileDatabase  # use the above import once making setup.py

__version__: str = "1.1.0"
APP: flask.Flask = Flask(__name__)


if __name__ == '__main__':
    db_password: str = getpass.getpass(
        "Enter database password [or empty if not protected]: ")
    database: FileDatabase = FileDatabase(db_password=db_password)


def SERVER_ERROR():
    return flask.make_response({
        'error': "Internal Server Error",
        'ecode': "SERVER_ERROR"
    }, 500)


def _verify(headers: dict, _api_permission_type: str = '') -> flask.Response | int:
    """
    Return response depending on token verification status
            
    Parameters:
        username (str): Username to verify
        password (str): Password to verify
    """

    global database

    api_key = headers.get('Authorization', '')
    if api_key:
        result = database.api_keys.verify_key(api_key, _api_permission_type)
        match result:
            case "INVALID_APIKEY":
                response = flask.make_response({
                    'error': "Invalid API Key",
                    'ecode': result
                }, 400)
            case "APIKEY_NOT_AUTHORIZED":
                response = flask.make_response({
                    'error': "You are not authorized to do this action.",
                    'ecode': result
                }, 401)
            case 0:
                response = 0
            case _:
                logging.error(
                    "[FLASK-API-VERIFY]: API Key verifier function returned unexpected data: '%s'",
                    result    
                )
                return SERVER_ERROR()
                
        return response
            
    username: str = headers.get('syncServer-Username', '')
    password: str = headers.get('syncServer-Password', '')
    
    token_verified_result = database.verify_user(username, password)
    if not token_verified_result or token_verified_result == "NO_USER":
        err_response = flask.make_response({
            'error': "User credentials are invalid.",
            'ecode': "INVALID_CREDENTIALS"
        }, 400)
        return err_response
            
    if isinstance(token_verified_result, Exception):
        logging.error("[FLASK-VERIFY-USER]: Refer to [Database.verify_user] error logs for information")
        return SERVER_ERROR()

    return 0


@APP.post("/upload")
def file_uploads():
    global database

    files = request.files
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='create')
    if verify_result != 0:
        return verify_result

    if len(files) == 0:
        return flask.make_response({
            'error': 'No files provided to upload',
            'ecode': 'MISSING_FILES'
        }, 400)
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
        result = database.add_file(
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
                return SERVER_ERROR()
            
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


@APP.post("/modify")
def file_updates():
    global database

    files = request.files
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='update')
    if verify_result != 0:
        return verify_result

    if len(files) == 0:
        return flask.make_response({
            'error': 'No files provided to upload',
            'ecode': 'MISSING_FILES'
        }, 400)
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')

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
        result = database.modify_file(
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
                return SERVER_ERROR()
            
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


@APP.post("/delete")
def file_deletes():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='delete')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
        result = database.remove_file(
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
                return SERVER_ERROR()
            
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


@APP.post("/restore")
def file_restores():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='update')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
            
    if not isinstance(restore_which, int):
        return flask.make_response({
            'error': "restore-which parameter can only be an integer",
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
    result = database.deleted_files.restore_file(
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
                "[/restore]: deleted_files.restore_file function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
                
    return flask.make_response(response, response_code)


@APP.post('/list-deleted')
def list_deleted():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='read')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
    result = database.deleted_files.list_deleted(
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
                "[/list-deleted]: deleted_files.list_deleted function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
            
    return flask.make_response(response, response_code)


@APP.post('/remove-deleted')
def remove_deleted():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='delete')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
    if not (delete_which != ":all:" or isinstance(delete_which, int)):
        return flask.make_response({
            'error': "delete-which parameter can only be int or ':all:'",
            'ecode': "INVALID_PARAMETER"
        }, 400)

    if not isinstance(file_path, (bytes, str)):
        return flask.make_response({
            'error': 'file path provided is not bytes or str',
            'ecode': "INVALID_CONTENT"
        }, 400)

    response_code = 200
    if file_path != ":all:" and file_path[0] != "/":
        file_path: str = "/" + file_path

    result = database.deleted_files.true_delete(
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
                "[/remove-deleted]: deleted_files.true_delete function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
            
    return flask.make_response(response, response_code)


@APP.post('/read')
def file_reads():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='read')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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

    result = database.read_file(username, file_path)
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
            return SERVER_ERROR()
            
    return response or flask.make_response(flask.jsonify(err_response), response_code)
        

@APP.post('/create-dir')
def dir_creations():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='create')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
            
    result: int | str = database.dirs.make_dir(
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
                "[/create-dir]: make_dir function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
                
    return flask.make_response(response, response_code)


@APP.post('/remove-dir')
def dir_deletions():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='delete')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
            
    result: int | str = database.dirs.remove_dir(
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
                "[/remove-dir]: remove_dir function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()

    return flask.make_response(response, response_code)


@APP.post('/list-dir')
def dir_listing():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='read')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
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
            
    result: str | list[str] = database.dirs.list_dir(
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
                "[/list-dir]: list_dir function returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()

    return flask.make_response(flask.jsonify(response), response_code)


@APP.post('/api/create-key')
def create_api_key():
    global database

    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers
    
    verify_result = _verify(headers, _api_permission_type='create')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
    
    key_name: str = data.get('key-name', '')
    if not key_name:
        return flask.make_response({
            'error': "No API key name was provided",
            'ecode': "MISSING_KEYNAME"
        }, 400)
    if not isinstance(key_name, str):
        return flask.make_response({
            'error': "API key name can only be a string",
            'ecode': "INVALID_TYPE"
        }, 400)
            
    key_perms: list[str] = data.get('key-permissions', [])
    if not key_perms:
        return flask.make_response({
            'error': "API key permissions was not provided",
            'ecode': "MISSING_KEYPERMS"
        }, 400)
    if not isinstance(key_perms, list):
        return flask.make_response({
            'error': "API key permission can only be a list",
            'ecode': "INVALID_TYPE"
        })
            
    expires_on: str = data.get('key-expiry-date', '')
    if not expires_on:
        return flask.make_response({
            'error': "API key expiry date was not provided",
            'ecode': "MISSING_EXPIRYDATE"
        }, 400)
    if not isinstance(expires_on, str):
        return flask.make_response({
            'error': "API key expiry date can only be a string",
            'ecode': "INVALID_TYPE"
        }, 400)
            
    result = database.api_keys.create_key(
        username, key_perms, key_name, expires_on
    )

    response_code = 200
    response = None
    match result:
        case 'INVALID_KEYPERMS':
            response = {
                'error': "API key permissions include an invalid permission",
                'ecode': result
            }                
            response_code = 400
        case 'INVALID_DATETIME':
            response = {
                'error': "API key expiry date is not in the valid format: '%Y-%m-%d %H:%M:%S'",
                'ecode': result
            }
            response_code = 400
        case 'APIKEY_EXISTS':
            response = {
                'error': "An API key with the same name exists.",
                'ecode': result
            }
            response_code = 409
        case _ if result.startswith('syncServer-'):
            response = {
                'success': True,
                'api-key': result
            }
        case _:
            logging.error(
                "[/api/create-key]: api_keys.create_key returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
            
    return flask.make_response(response, response_code)


@APP.post('/api/delete-key')
def delete_api_key():
    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
            
    data = request.json
    headers = request.headers

    verify_result = _verify(headers, _api_permission_type='delete')
    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
    key_name: str = data.get('key-name', '')
    if not key_name:
        return flask.make_response({
            'error': "No API key name was provided",
            'ecode': "MISSING_KEYNAME"
        }, 400)
    if not isinstance(key_name, str):
        return flask.make_response({
            'error': "API key name can only be a string",
            'ecode': "INVALID_TYPE"
        }, 400)
            
    result = database.api_keys.delete_key(
        username, key_name
    )
    response_code = 200
    response = None
    match result:
        case 'INVALID_APIKEY':
            response = {
                'error': "No API key with that name exists.",
                'ecode': result
            }
            response_code = 404
        case 0:
            response = {'success': True}
        case _:
            logging.error(
                "[/api/delete-key]: api_keys.delete_key returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
            
    return flask.make_response(response, response_code)


@APP.post('/api/list-keys')
def list_api_keys():
    if not request.is_json:
        return flask.make_response({
            'error': "Provided request must be in a JSON format",
            'ecode': "415"
        }, 415)
    
    headers = request.headers
    verify_result = _verify(headers, _api_permission_type='read')

    if verify_result != 0:
        return verify_result
            
    username: str = database.api_keys.get_key_owner(headers.get('Authorization', ""))
    if username == "INVALID_APIKEY":
        username: str = headers.get('syncServer-Username', '')
            
    result = database.api_keys.list_keys(
        username
    )
    response_code = 200
    response = None
    match result:
        case 'NO_AVAILABLE_APIKEYS':
            response = {
                'error': "No API keys are defined.",
                'ecode': result
            }
            response_code = 404
        case list():
            response = {
                'success': True,
                'key-names': result
            }
        case _:
            logging.error(
                "[/api/list-keys]: api_keys.list_keys returned unexpected data: '%s'",
                result
            )
            return SERVER_ERROR()
            
    return flask.make_response(response, response_code)


@APP.get('/')
@APP.get('/api')
def api_route():
    return flask.jsonify({'alive': True})


def main():
    flask_route_port: int = os.environ.get('SYNCSERVER_PORT', 8561)
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] - [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('app.log')
        ]
    )
    APP.run(debug=False, port=flask_route_port)


if __name__ == '__main__':
    main()
