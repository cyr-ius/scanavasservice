#!/usr/bin/env bash
set -euo pipefail

# wait_and_start.sh
# waits for ClamAV, MinIO, Kafka, then launches FastAPI + scanner worker

# Prefer docker-compose provided variables when present.
# Use CLAMD_HOSTS (comma separated list host:port) if set, otherwise fall back to single CLAMD_HOST/CLAMD_PORT.
: "${CLAMD_HOSTS:=${CLAMD_HOSTS:-}}"
if [ -n "${CLAMD_HOSTS}" ]; then
  CLAMD_FIRST="$(echo "${CLAMD_HOSTS}" | awk -F',' '{print $1}')"
  CLAMD_HOST="$(echo "${CLAMD_FIRST}" | cut -d':' -f1)"
  CLAMD_PORT="$(echo "${CLAMD_FIRST}" | cut -d':' -f2)"
else
  : "${CLAMD_HOST:=clamav}"
  : "${CLAMD_PORT:=3310}"
fi

: "${S3_ENDPOINT_URL:=${S3_ENDPOINT_URL:-http://minio:9000}}"
: "${KAFKA_SERVERS:=${KAFKA_SERVERS:-kafka:9092}}"
: "${FASTAPI_PORT:=${FASTAPI_PORT:-8000}}"
: "${STARTUP_WAIT_SECS:=${STARTUP_WAIT_SECS:-120}}"

echo "Waiting up to ${STARTUP_WAIT_SECS}s for dependencies..."
echo "WORKDIR: $(pwd)"
echo "Python: $(python --version)"

end=$((SECONDS + STARTUP_WAIT_SECS))

# --- Wait for ClamAV TCP port ---
until nc -z "${CLAMD_HOST}" "${CLAMD_PORT}" >/dev/null 2>&1; do
  if (( SECONDS >= end )); then
    echo "Timeout waiting for ClamAV (${CLAMD_HOST}:${CLAMD_PORT})"
    exit 1
  fi
  echo "Waiting for ClamAV ${CLAMD_HOST}:${CLAMD_PORT}..."
  sleep 2
done
echo "ClamAV reachable (${CLAMD_HOST}:${CLAMD_PORT})."

# --- Wait for MinIO HTTP health ---
MINIO_HOST=$(echo "${S3_ENDPOINT_URL}" | sed -E 's#^https?://##' | cut -d'/' -f1)
until curl -sSf "http://${MINIO_HOST}/minio/health/live" >/dev/null 2>&1; do
  if (( SECONDS >= end )); then
    echo "Timeout waiting for MinIO (${MINIO_HOST})"
    exit 1
  fi
  echo "Waiting for MinIO (${MINIO_HOST})..."
  sleep 2
done
echo "MinIO reachable (${MINIO_HOST})."

# --- Wait for Kafka ---
KAFKA_HOST=$(echo "${KAFKA_SERVERS}" | cut -d',' -f1 | cut -d':' -f1)
KAFKA_PORT=$(echo "${KAFKA_SERVERS}" | cut -d',' -f1 | cut -d':' -f2)
until nc -z "${KAFKA_HOST}" "${KAFKA_PORT}" >/dev/null 2>&1; do
  if (( SECONDS >= end )); then
    echo "Timeout waiting for Kafka (${KAFKA_HOST}:${KAFKA_PORT})"
    exit 1
  fi
  echo "Waiting for Kafka ${KAFKA_HOST}:${KAFKA_PORT}..."
  sleep 2
done
echo "Kafka reachable (${KAFKA_HOST}:${KAFKA_PORT})."

echo ""
echo "All dependencies ready. Starting services..."
echo ""

# --- Start FastAPI in background ---
echo "[1/2] Starting FastAPI on port ${FASTAPI_PORT}..."
uvicorn app.api:app --host 0.0.0.0 --port "${FASTAPI_PORT}" &
FASTAPI_PID=$!

# Wait for FastAPI to be ready
until curl -sSf "http://127.0.0.1:${FASTAPI_PORT}/api/heartbeat" >/dev/null 2>&1; do
  if (( SECONDS >= end )); then
    echo "Timeout waiting for FastAPI"
    kill "${FASTAPI_PID}" || true
    exit 1
  fi
  echo "Waiting for FastAPI to start..."
  sleep 2
done
echo "✓ FastAPI ready on port ${FASTAPI_PORT}"

# --- Start scanner worker ---
echo "[2/2] Starting scanner worker..."
echo ""

exec python -m app