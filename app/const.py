"""Constants."""

import os

from .helpers import parse_hosts

# General configuration
LIB_LOG_LEVEL = os.getenv("LIB_LOG_LEVEL", "WARNING").upper()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", 10))
RESULT_TO_KAFKA_TOPIC = os.getenv("RESULT_TO_KAFKA_TOPIC", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


# Scan retry configuration
DELAY = float(os.getenv("DELAY", 20))  # seconds
RETRY = int(os.getenv("RETRY", 3))

# Kafka configuration
KAFKA_SERVERS = os.getenv("KAFKA_SERVERS", "kafka:9092").split(",")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "files_to_scan")
KAFKA_TOPIC_RSLT = os.getenv("KAFKA_TOPIC_RSLT", KAFKA_TOPIC)
KAFKA_LOG_RETENTION_MS = int(os.getenv("KAFKA_LOG_RETENTION_MS", 86400000))
KAFKA_SECURITY_PROTOCOL = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
KAFKA_SASL_MECHANISM = os.getenv("KAFKA_SASL_MECHANISM", "PLAIN")
KAFKA_SASL_USERNAME = os.getenv("KAFKA_SASL_USERNAME", "")
KAFKA_SASL_PASSWORD = os.getenv("KAFKA_SASL_PASSWORD", "")

# SSL configuration
SSL_CHECK_HOSTNAME = os.getenv("SSL_CHECK_HOSTNAME", "false").lower() == "true"
SSL_VERIFY_MODE = os.getenv("SSL_VERIFY_MODE", "false").lower() == "true"

# S3 configuration
S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
S3_BUCKET = os.getenv("S3_BUCKET", "scans")
S3_ENDPOINT = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
S3_SCAN_QUARANTINE = os.getenv("S3_SCAN_QUARANTINE", "quarantine")
S3_SCAN_RESULT = os.getenv("S3_SCAN_RESULT", "processed")
S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")

# ClamAV configuration
CLAMD_CNX_TIMEOUT = float(os.getenv("CLAMD_CNX_TIMEOUT", 120))
CLAMD_HOSTS = parse_hosts(os.getenv("CLAMD_HOSTS", "clamav:3310"))
CLAMD_CHUNK_SIZE = int(os.getenv("CLAMD_CHUNK_SIZE", 1024 * 4))

# Monitor configuration for scan servers
BUSY_WEIGHT = float(os.getenv("BUSY_WEIGHT", 1.0))
FAILURE_WEIGHT = float(os.getenv("FAILURE_WEIGHT", 5.0))
COOLDOWN_THRESHOLD = int(os.getenv("COOLDOWN_THRESHOLD", 3))  # failures before cooldown
COOLDOWN_SECONDS = float(os.getenv("COOLDOWN_SECONDS", 60))  # cooldown duration
EMA_ALPHA = float(
    os.getenv("EMA_ALPHA", 0.2)
)  # exponential moving average alpha for avg times


# OIDC configuration
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "")

CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
CLIENT_SCOPES = os.getenv("CLIENT_SCOPES", "openid,profile,email,groups").split(",")

# Application version
VERSION = os.getenv("VERSION", "0.0.0")
