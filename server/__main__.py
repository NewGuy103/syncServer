import logging
import json
import getpass

import types

import flask

from flask import Flask, request
from pycrypter import ThreadManager

# from ._db import FileDatabase 
from _db import FileDatabase  # use the above import once making setup.py

APP = Flask(__name__)


class Routes:
    def __init__(
        self, db_password: bytes | str = None
    ):
        self.db = FileDatabase(db_password=db_password)
        self.thread_mgr: ThreadManager = ThreadManager()

        self.read_chunk_size = 50 * 1024 * 1024  # 50MB

    def _verify_credentials(self, username: str, token: str):
        """
        Return response depending on token verification status
        
        Parameters:
            username (str): Username to verify
            password (str): Password to verify
        
        Returns:
            [if not username or token]: {'error': 'No verification credentials was sent'} HTTP 401
            [if token not verified/no user]: {'error': 'Invalid verification credentials'}, HTTP 401
            [if an Exception occured during verification]: HTTP 500
        """
        if not username or not token:
            err_response = flask.make_response(
                {'error': 'No verification credentials was sent'}, 401
            )
            return err_response

        token_verified_result = self.db.verify_user(username, token)
        if not token_verified_result or token_verified_result == "NO_USER":
            err_response = flask.make_response(
                {'error': 'Invalid verification credentials'}, 401
            )
            return err_response
        if isinstance(token_verified_result, Exception):
            logging.error("[FLASK-VERIFY-USER]: Refer to [Database.verify_user] error logs for information")
            return flask.abort(500)

        return 0

    def file_uploads(self):
        """Route /upload"""
        files = request.files
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if len(files) == 0:
            return flask.make_response({
                'error': "No files were passed to upload"
            }, 400)
        
        successful_runs = []
        failed_runs = {}

        response_code = 200

        for file in files.values():
            result = self.db.add_file(
                username, token, file.name, 
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
                    return flask.abort(500)
        
        if len(files) == 1 and failed_runs.keys():
            return flask.make_response(
                flask.jsonify(failed_runs), 
                response_code
            )
        elif len(files) == 1 and successful_runs:
            return flask.make_response({
                'batch': False,
                'success': True
            }, response_code)

        return flask.make_response(flask.jsonify({
            'batch': True,
            'ok': successful_runs,
            'fail': failed_runs
        }), 200)

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
                'error': "No filenames were passed to upload"
            }, 400)

        successful_runs = []
        failed_runs = {}

        response_code = 200

        for file in files.values():
            result = self.db.modify_file(
                username, token, file.name, 
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
                            "Target file path does not exist. Use /upload to upload a file or"
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
                    return flask.abort(500)
        
        if len(files) == 1 and failed_runs.keys():
            return flask.make_response(
                flask.jsonify(failed_runs), 
                response_code
            )
        elif len(files) == 1 and successful_runs:
            return flask.make_response({
                'batch': False,
                'success': True
            }, response_code)

        return flask.make_response(flask.jsonify({
            'batch': True,
            'ok': successful_runs,
            'fail': failed_runs
        }), 200)

    def file_deletes(self):
        body = request.form
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if not body.get('file-paths'):
            return flask.make_response({
                'error': 'No file paths provided to delete'
            }, 400)

        try:
            filenames = json.loads(body['file-paths'])
        except json.JSONDecodeError:
            return flask.make_response({
                'error': 'Could not parse JSON: Expected a list-like JSON string'
            }, 400)

        successful_runs = []
        failed_runs = {}

        response_code = 200
        
        for file in filenames:
            result = self.db.remove_file(
                username, token, file
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
                    return flask.abort(500)
        
        if len(filenames) == 1 and failed_runs.keys():
            return flask.make_response(
                flask.jsonify(failed_runs), 
                response_code
            )
        elif len(filenames) == 1 and successful_runs:
            return flask.make_response({
                'batch': False,
                'success': True
            }, response_code)

        return flask.make_response(flask.jsonify({
            'batch': True,
            'ok': successful_runs,
            'fail': failed_runs
        }), 200)

    def file_reads(self):
        body = request.form
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if not body.get('file-path'):
            return flask.make_response({
                'error': 'No file path provided to read'
            }, 400)

        file_path = body['file-path']
        if file_path[0] != "/":
            file_path = "/" + file_path

        result = self.db.read_file(username, token, file_path)
        response = flask.make_response()
        
        match result:
            case "NO_DIR_EXISTS":
                response.data = flask.jsonify({
                    'error': "Directory path does not exist",
                    'ecode': result
                })
                response.status_code = 400
            case "NO_FILE_EXISTS":
                response.data = flask.jsonify({
                    'error': (
                        "Target file path does not exist. Use /upload to upload a file or"
                        " check the filename."
                    ),
                    'ecode': result
                })
                response.status_code = 404
            case _ if isinstance(result, types.GeneratorType):
                response = flask.Response(
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
                return flask.abort(500)
         
        return response
    
    def dir_creations(self):
        body = request.form
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if not body.get('dir-path'):
            return flask.make_response({
                'error': 'No directory path provided to create'
            }, 400)
        
        dir_path = body.get('dir-path')
        result = self.db.make_dir(
            username, token, dir_path
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
                response = {
                    'success': True
                }
            case _:
                logging.error(
                    "'self.db.make_dir' returned unexpected data: '%s'",
                    result
                )
                return flask.abort(500)

        return flask.make_response(response, response_code)
    
    def dir_deletions(self):
        body = request.form
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if not body.get('dir-path'):
            return flask.make_response({
                'error': 'No directory path provided to delete'
            }, 400)
        
        dir_path = body.get('dir-path')
        result = self.db.remove_dir(
            username, token, dir_path
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
                response = {
                    'success': True
                }
            case _:
                logging.error(
                    "'self.db.remove_dir' returned unexpected data: '%s'",
                    result
                )
                return flask.abort(500)

        return flask.make_response(response, response_code)
    
    def dir_listing(self):
        body = request.form
        headers = request.headers

        username = headers.get('syncServer-Username')
        token = headers.get("syncServer-Token")

        verify_result = self._verify_credentials(username, token)
        if verify_result != 0:
            return verify_result

        if not body.get('dir-path'):
            return flask.make_response({
                'error': 'No directory path provided to delete'
            }, 400)
        
        dir_path = body.get('dir-path')
        result = self.db.list_dir(
            username, token, dir_path
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
                return flask.abort(500)

        return flask.make_response(flask.jsonify(response), response_code)
    
    @staticmethod
    def root_route():
        return flask.jsonify({'alive': True})

def main(db_password: bytes | str):
    routes = Routes(db_password=db_password)
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
    APP.add_url_rule("/read", view_func=routes.file_reads, methods=['POST'])

    APP.add_url_rule("/create-dir", view_func=routes.dir_creations, methods=['POST'])
    APP.add_url_rule("/remove-dir", view_func=routes.dir_deletions, methods=['POST'])

    APP.add_url_rule("/list-dir", view_func=routes.dir_listing, methods=['POST'])
    APP.add_url_rule("/", view_func=routes.root_route)
    APP.run(debug=False)


if __name__ == '__main__':
    password = getpass.getpass("Enter database password [or empty if not protected]: ")
    main(password)
