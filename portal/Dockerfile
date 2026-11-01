FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --system --uid 10001 --home /app portal
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
# A new named volume copies this directory's owner, so the non-root user can write to /data.
RUN mkdir /data && chown portal:portal /data

USER portal
ENV PORTAL_DATA_DIR=/data PORTAL_SECRET_KEY_FILE=/data/secret.key
VOLUME ["/data"]
EXPOSE 8000 8443
# Public app by default; the ingest service overrides the command (see deploy/docker-compose.yml).
# Client IP comes from X-Real-IP, trusted only from Caddy (PORTAL_TRUSTED_PROXIES); see app/security.py.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
