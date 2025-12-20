import logging

from const import LIB_LOG_LEVEL, LOG_LEVEL


class Mylogger:
    """Custom logger class."""

    def __init__(self, log_level: str, lib_log_level: str = "WARNING"):
        """Init."""
        _formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self.console_handler = logging.StreamHandler()
        self.console_handler.setFormatter(_formatter)
        self.log_level = log_level

        for lib in ["uvicorn", "uvicorn.error", "uvicorn.access"]:
            logger_ = logging.getLogger(lib)
            logger_.handlers = []
            logger_.propagate = False
            logger_.setLevel(log_level)
            logger_.addHandler(self.console_handler)

        for lib in ["fastapi", "aiokafka", "aiobotocore", "redis"]:
            liblog = logging.getLogger(lib)
            liblog.setLevel(lib_log_level)
            if not liblog.hasHandlers():
                liblog.addHandler(self.console_handler)

    def getLogger(self, name):
        """Return logger."""
        logger_ = logging.getLogger(name)
        logger_.handlers = []
        logger_.propagate = False
        logger_.setLevel(self.log_level)
        logger_.addHandler(self.console_handler)

        return logger_


mylogging = Mylogger(LOG_LEVEL, LIB_LOG_LEVEL)
