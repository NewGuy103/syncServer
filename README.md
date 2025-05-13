# newguy103-syncserver

A rewrite of the old Flask version of this app, rewritten in FastAPI using modern dev tooling.

This application is a simple file server that implements OAuth2, API keys and interacting
with files on the server. A project to learn about paths, ORMs and tests.

Changes can be found under the [changelog/](changelog) folder.

## Requirements

* Python 3.12+ in a virtual environment and [uv](https://docs.astral.sh/uv/).
* A PostgreSQL instance.
* A [Valkey](https://valkey.io/) instance.

## Installation

`newguy103-syncserver` can be pulled using the GitHub Container Registry:

```bash
docker pull ghcr.io/newguy103/syncserver
```

If you want to clone the repository directly:

```bash
git clone https://github.com/newguy103/syncserver
cd syncserver
uv venv
source .venv/bin/activate
uv sync
```

This will clone the repository locally and install the required dependencies for the server.

If you want to also run the client, make sure to include `--extra client` to uv sync.

### Dependencies

The app requires these server dependencies:

* aiofiles
* asyncpg
* cryptography
* fastapi[standard]
* passlib[argon2]
* pydantic
* pydantic-settings
* sqlmodel
* uvicorn[standard]
* valkey

If you want to also run the PySide6 client, you need to install the following:

* PySide6
* keyring
* platformdirs

## Usage

To run the server, you can use Docker:

```bash
docker run \
--name newguy103-syncserver \
--publish 8000:8000 \
--volume ./syncserver_data:/app/syncserver \
ghcr.io/newguy103/syncserver:latest
```

Or if you cloned the repository directly:

```bash
fastapi run app/server/main.py
```

There is an example docker compose file in the [docker](docker/docker-compose.yml) directory,
which you can use to run the app.

### Environment

The app requires these environment variables:

* `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_DB` and `POSTGRES_PASSWORD` for the database connection.
* `VALKEY_URI` as the URI to the Valkey server.

Other optional environment variables can be found in the project docs.

## Testing

There are tests available in the [tests/](tests) directory, and these use Pytest.

To run them, execute `./scripts/tests.sh`. This is required, as the script
will set the environment variables for the tests to be a specific directory.

## Disclaimer

PySide6 is licensed under LGPL 3.0. You can find the source code here:
[PySide6 Source Code](https://code.qt.io/cgit/pyside/pyside-setup.git/).

This project is licensed under Mozilla Public License 2.0.

## Version

0.1.0
