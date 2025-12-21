"""Utils for the application."""

import ssl
from typing import Any

from .const import (
    KAFKA_SASL_MECHANISM,
    KAFKA_SASL_PASSWORD,
    KAFKA_SASL_USERNAME,
    KAFKA_SECURITY_PROTOCOL,
    KAFKA_SERVERS,
    SSL_CHECK_HOSTNAME,
    SSL_VERIFY_MODE,
)


def _ssl_context():
    """Create SSL context for Kafka connections if needed."""

    context = ssl.create_default_context()
    context.check_hostname = SSL_CHECK_HOSTNAME
    context.verify_mode = ssl.CERT_REQUIRED if SSL_VERIFY_MODE else ssl.CERT_NONE
    return context


def kafka_params() -> dict[str, Any]:
    """Return Kafka connection parameters."""
    return {
        "bootstrap_servers": KAFKA_SERVERS,
        "security_protocol": KAFKA_SECURITY_PROTOCOL
        if KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD
        else "PLAINTEXT",
        "sasl_mechanism": KAFKA_SASL_MECHANISM if KAFKA_SASL_MECHANISM else None,
        "sasl_plain_username": KAFKA_SASL_USERNAME if KAFKA_SASL_USERNAME else None,
        "sasl_plain_password": KAFKA_SASL_PASSWORD if KAFKA_SASL_PASSWORD else None,
        "ssl_context": _ssl_context() if SSL_VERIFY_MODE else None,
    }
