import getpass
import os

from ._server import config_app
from ._db import FileDatabase


def main():
    password: str = getpass.getpass('Enter database password [or empty if not protected]: ')
    fdb: FileDatabase = FileDatabase(db_password=password)

    _app = config_app(fdb)
    flask_route_port: int = int(os.environ.get('SYNCSERVER_PORT', 8561))

    _app.run(debug=False, port=flask_route_port)


if __name__ == '__main__':
    main()
