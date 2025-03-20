FROM python:3.12
LABEL org.opencontainers.image.source=https://github.com/newguy103/syncServer

WORKDIR /app

COPY app /app/app
COPY requirements.txt /app/

RUN pip install --no-cache-dir --no-input -r requirements.txt
EXPOSE 8000

VOLUME [ "/app/syncserver" ]

ENTRYPOINT [ "fastapi", "run", "app/main.py" ]
CMD [ "--host", "0.0.0.0", "--port", "8000" ]
