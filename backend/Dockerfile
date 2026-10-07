# ---------------------------------------------------------------------------
# THREAT-NEXUS - backend image.
#
#   docker build -t insha-backend .
#   docker run --rm -p 5000:5000 insha-backend
#   docker run --rm insha-backend python src/main.py --log samples/demo.log --export both
#
# The image is self-contained: no bind mounts are required. Mount volumes only
# if you want the SQLite database and reports to survive container removal.
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# Fail fast, no .pyc clutter, unbuffered logs so `docker logs` is live.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Bind on all interfaces inside the container; published by -p on the host.
ENV HOST=0.0.0.0 \
    PORT=5000 \
    DB_PATH=instance/logs.db \
    REPORTS_DIR=reports \
    ANALYSIS_THRESHOLD=5 \
    MAX_UPLOAD_MB=16 \
    FLASK_ENV=production \
    NO_COLOR=1 \
    SECRET_KEY=change-me-in-production

WORKDIR /app

# Dependencies first so source edits do not invalidate the pip layer.
# requirements-docker.txt adds gunicorn: the Flask development server is fine
# on a laptop but not for a deployed container.
COPY requirements.txt requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .

# Run unprivileged. Writable state lives in two directories the app creates at
# import time; pre-creating them with the right owner avoids a first-request 500.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/instance /app/reports \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# stdlib only - slim images have no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,sys,urllib.request; \
url='http://127.0.0.1:%s/api/v1/health' % os.environ.get('PORT','5000'); \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

# gunicorn, via sh so PORT / WEB_CONCURRENCY stay tunable by env.
# Real-time alerts (Flask-SocketIO, threading mode) need:
#   * exactly ONE worker - Socket.IO keeps its connected clients in memory, so
#     with several workers an alert emitted in one never reaches browsers
#     connected to another. Concurrency comes from threads instead.
#   * the gthread worker class with enough threads - every open WebSocket
#     holds one thread for as long as the dashboard tab stays open.
#   --access-logfile -   request log to stdout so `docker logs` works
#   --error-logfile  -   same for the error log
CMD ["sh", "-c", "exec gunicorn \
     --bind 0.0.0.0:${PORT:-5000} \
     --worker-class gthread \
     --workers ${WEB_CONCURRENCY:-1} \
     --threads ${THREADS:-50} \
     --timeout 120 \
     --graceful-timeout 30 \
     --access-logfile - \
     --error-logfile - \
     src.app:app"]