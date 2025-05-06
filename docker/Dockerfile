FROM python:3.13
ENV PYTHONUNBUFFERED=1

LABEL org.opencontainers.image.source="https://github.com/NewGuy103/syncServer"
LABEL org.opencontainers.image.documentation="https://newguy103.github.io/syncServer/"

LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL org.opencontainers.image.authors="NewGuy103"

WORKDIR /app/

# Install uv
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#installing-uv
COPY --from=ghcr.io/astral-sh/uv:0.7.2 /uv /uvx /bin/

# Place executables in the environment at the front of the path
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#using-the-environment
ENV PATH="/app/.venv/bin:$PATH"

# Compile bytecode
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#compiling-bytecode
ENV UV_COMPILE_BYTECODE=1

# uv Cache
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#caching
ENV UV_LINK_MODE=copy

# Install dependencies
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#intermediate-layers
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project


ENV PYTHONPATH=/app

COPY ./pyproject.toml ./uv.lock ./alembic.ini /app/
COPY ./app /app/app

COPY ./scripts /app/scripts
COPY ./migrations /app/migrations

# Add scripts to path
ENV PATH="/app/scripts:$PATH"

# Sync the project
# Ref: https://docs.astral.sh/uv/guides/integration/docker/#intermediate-layers
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync

EXPOSE 8000
VOLUME [ "/app/syncserver" ]

ENTRYPOINT [ "fastapi", "run", "app/server/main.py" ]
CMD [ "--host", "0.0.0.0", "--port", "8000" ]
