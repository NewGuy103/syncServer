import logging
import json
import getpass

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
                'error': "No filenames were passed to upload"
            }, 400)
        
        # non-batch operation [1 file]
        if len(files) == 1:
            first_file = list(request.files.values())[0]
            result = self.db.add_file(
                username, token, first_file.filename,
                first_file.stream
            )

            if result == "FILE_EXISTS":
                return flask.make_response({
                    'error': 'Target filename exists. Use /modify to modify file or check the filename.'
                }, 409)

            return flask.make_response({
                'batch': False,
                'success': True
            }, 200)
        
        successful_runs = []
        failed_runs = {}

        for file in files.values():
            result = self.db.add_file(
                username, token, file.filename, 
                file.stream
            )

            if result == "FILE_EXISTS":
                failed_runs[file.filename] = result
                continue
            
            successful_runs.append(file.filename)

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

        # non-batch operation [1 file]
        if len(files) == 1:
            first_file = list(request.files.values())[0]
            result = self.db.modify_file(
                username, token, first_file.filename,
                first_file.stream
            )

            if result == "NO_FILE_EXISTS":
                return flask.make_response({
                    'error': 'Target filename does not exist. Use /upload to upload a new file or check the filename.'
                }, 404)

            return flask.make_response({
                'batch': False,
                'success': True
            }, 200)

        successful_runs = []
        failed_runs = {}

        for file in files.values():
            result = self.db.modify_file(
                username, token, file.filename,
                file.stream
            )

            if result == "FILE_EXISTS":
                failed_runs[file.filename] = result
                continue

            successful_runs.append(file.filename)

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

        if not body.get('filenames'):
            return flask.make_response({
                'error': 'No filenames provided to delete'
            }, 400)

        try:
            filenames = json.loads(body['filenames'])
        except json.JSONDecodeError:
            return flask.make_response({
                'error': 'Could not parse JSON: Expected a list-like JSON string'
            }, 400)

        # non batch operation [1 file]
        if len(filenames) == 1:
            file = filenames[0]
            result = self.db.remove_file(username, token, file)

            if result == "NO_FILE_EXISTS":
                return flask.make_response({
                    'error': 'Target filename does not exist. Use /upload to upload a new file or check the filename.'
                }, 404)

            return flask.make_response({
                'batch': False,
                'success': True
            }, 200)

        # batch operation [2+ files]
        successful_runs = []
        failed_runs = {}
        for file in filenames:
            result = self.db.remove_file(username, token, file)

            if result == "NO_FILE_EXISTS":
                failed_runs[file] = result
                continue

            successful_runs.append(file)

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

        if not body.get('filename'):
            return flask.make_response({
                'error': 'No filenames provided to read'
            }, 400)

        file = body['filename']
        result = self.db.read_file(username, token, file)
        
        if result == "NO_FILE_EXISTS":
            return flask.make_response({
                'error': 'Target filename does not exist. Use /upload to upload a new file or check the filename.'
            }, 404)

        response = flask.Response(
            result, direct_passthrough=True,
        )
        response.headers['Content-Disposition'] = f'attachment; filename={body["filename"]}'
        return response
    
    @staticmethod
    def root_route():
        return flask.jsonify({'alive': True})

def main(db_password: bytes | str):
    routes = Routes(db_password=db_password)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
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

    APP.add_url_rule("/", view_func=routes.root_route)
    APP.run(debug=False)


if __name__ == '__main__':
    password = getpass.getpass("Enter database password [or empty if not protected]: ")
    main(password)
