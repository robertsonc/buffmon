# buffmon ingest service + dashboard.
# Build from services/:  docker build -t buffmon-ingest:0.1.0 .
FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN useradd --system --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin buffmon

WORKDIR /app
COPY requirements.lock ./
RUN pip install -r requirements.lock

COPY pyproject.toml README.md thresholds.yaml ./
COPY buffmon ./buffmon
RUN pip install --no-deps . && chown -R root:root /app && chmod -R a-w /app

USER 10001:10001
ENV BUFFMON_HOST=0.0.0.0 \
    BUFFMON_PORT=8080 \
    BUFFMON_THRESHOLDS_FILE=/app/thresholds.yaml
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/v1/health', timeout=2).status == 200 else 1)"]

CMD ["python", "-m", "buffmon"]
