import logging

from .const import LIB_LOG_LEVEL, LOG_LEVEL


def _configure_logging(log_level: str, lib_log_level: str = "WARNING"):
    """Configure all loggers."""
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Configure uvicorn loggers
    for lib in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
        logger = logging.getLogger(lib)
        logger.handlers = []
        logger.propagate = False
        logger.setLevel(log_level)
        logger.addHandler(console_handler)

    # Configure third-party loggers
    for lib in ["fastapi", "aiokafka", "aiobotocore", "redis"]:
        logger = logging.getLogger(lib)
        logger.setLevel(lib_log_level)
        if not logger.hasHandlers():
            logger.addHandler(console_handler)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)


# Configure at import time
_configure_logging(LOG_LEVEL, LIB_LOG_LEVEL)

# Export standard logging
getLogger = logging.getLogger
