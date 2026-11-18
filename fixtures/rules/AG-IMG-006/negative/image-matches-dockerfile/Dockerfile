FROM python:3.12-slim@sha256:ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
WORKDIR /app
COPY server.py .
RUN useradd -m app
USER app
ENTRYPOINT ["python", "server.py"]
