# Database Component Information

This page will show the database component and how it works.

## Overview

The `syncserver.server` database uses PostgreSQL and `asyncpg` as it's connector.

The app uses [SQLModel](https://sqlmodel.tiangolo.com/) as the ORM, because it utilizes Pydantic and SQLAlchemy.

## Tables

The models used to generate the database tables can be found in
[`app/models/dbtables.py`](https://github.com/NewGuy103/syncServer/blob/main/app/server/models/dbtables.py).

## Code documentation

The database code can be found under
[`app/internal/database.py`](https://github.com/NewGuy103/syncServer/blob/main/app/server/internal/database.py),
and uses Python type hints.

## Migrations

The app uses alembic to handle both setting up the schema and database migrations. The script
`migrations.sh` runs all required commands.
