FROM python:3.11-slim-bookworm

# nodejs is used (when available) by the acceptance stage to syntax-check the
# frontend script (`node --check`); the application itself uses only the
# Python standard library.  Installation is best-effort so the image still
# builds in network-restricted environments; verify.sh skips the JS check if
# node is absent.
RUN apt-get update \
    && (apt-get install -y --no-install-recommends nodejs \
        || echo "warning: nodejs unavailable; JS syntax check will be skipped") \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts
RUN chmod +x scripts/verify.sh scripts/live_smoke.py

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    DB_PATH=/data/directory.db

EXPOSE 8080
VOLUME ["/data"]

CMD ["python", "-m", "app.server"]
