"""Helpers for the application."""

import asyncio
import functools
import logging
import random
import re
import unicodedata
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


def normalize_ascii(value: str) -> str:
    return (
        unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    )


def truncate_string(text: str, max_length: int = 64) -> str:
    """Truncate string to max_length and add ellipsis."""
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


def sanitize_tag_value(value: Any, max_length: int = 256) -> str:
    """Sanitize S3 tag value according to AWS constraints."""
    # Convert to string
    text = str(value)

    # Remove invalid characters (keep only allowed: alphanumeric, space, +, -, =, ., _, :, /, @)
    text = re.sub(r"[^a-zA-Z0-9\s+\-=._:/@]", "", text)

    # Remove newlines, tabs, and control characters
    text = re.sub(r"[\n\r\t\x00-\x1F]", "", text)

    # Truncate to max length
    if len(text) > max_length:
        text = text[:max_length]

    # If empty after sanitization, use default
    return text or "unknown"


def sanitize_tag_key(value: str, max_length: int = 128) -> str:
    """Sanitize S3 tag key according to AWS constraints."""
    text = str(value).lower()
    text = re.sub(r"[^a-z0-9\s+\-=._:/@]", "", text)
    text = re.sub(r"[\n\r\t\x00-\x1F]", "", text)

    if len(text) > max_length:
        text = text[:max_length]

    return text or "unknown"


def parse_hosts(s: str, port: int = 3310) -> list[tuple[str, int]]:
    """Parse 'host:port,host:port' string from environment variable."""
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            h, p = part.split(":", 1)
            try:
                out.append((h, int(p)))
            except ValueError:
                continue
        else:
            out.append((part, port))
    return out


def retry(
    exceptions: Any = Exception,
    tries: int = -1,
    delay: float = 0,
    max_delay: int | None = None,
    backoff: int = 1,
    jitter: int | tuple[int, int] = 0,
    logger: Any = logger,
) -> Callable[..., Any]:
    """Retry Decorator.

    :param exceptions: an exception or a tuple of exceptions to catch. default: Exception.
    :param tries: the maximum number of attempts. default: -1 (infinite).
    :param delay: initial delay between attempts. default: 0.
    :param max_delay: the maximum value of delay. default: None (no limit).
    :param backoff: multiplier applied to delay between attempts. default: 1 (no backoff).
    :param jitter: extra seconds added to delay between attempts. default: 0.
                   fixed if a number, random if a range tuple (min, max)
    :param logger: logger.warning(fmt, error, delay) will be called on failed attempts.
                   default: retry.logging_logger. if None, logging is disabled.
    :returns: the result of the f function.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        """Add decorator."""

        @functools.wraps(func)
        async def newfn(*args: Any, **kwargs: Any) -> Any:
            """Load function."""
            _tries, _delay = tries, delay
            while _tries:
                try:
                    return await func(*args, **kwargs)
                except exceptions as error:  # pylint: disable=broad-except
                    _tries -= 1
                    if not _tries:
                        logger.error("%s, timeout exceeded", error)
                        raise TimeoutExceededError(error) from error

                    if logger is not None:
                        logger.warning("%s, trying again in %s seconds", error, _delay)

                    await asyncio.sleep(_delay)
                    _delay *= backoff

                    if isinstance(jitter, tuple):
                        _delay += random.uniform(*jitter)
                    else:
                        _delay += jitter

                    if max_delay is not None:
                        _delay = min(_delay, max_delay)

        return newfn

    return decorator


class TimeoutExceededError(Exception):
    """Timeout exceeded exception."""
