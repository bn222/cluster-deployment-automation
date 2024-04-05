import logging
import os
import sys
import typing
from typing import Optional
from typing import TextIO


class ExtendedLogger(logging.Logger):
    def __init__(self, logger: logging.Logger):
        self._wrapped_logger = logger

    def __getattribute__(self: 'ExtendedLogger', name: str) -> typing.Any:
        # ExtendedLogger is-a logging.Logger, but it delegates most calls to
        # the wrapped-logger (which is also a logging.Logger).
        if name == 'error_and_exit':
            return object.__getattribute__(self, name)
        logger = object.__getattribute__(self, '_wrapped_logger')
        return logger.__getattribute__(name)

    def error_and_exit(self: 'ExtendedLogger', msg: str, *, exit_code: int = -1) -> typing.NoReturn:
        self.error(msg)
        sys.exit(exit_code)


def configure_logger(lvl: Optional[int] = None) -> ExtendedLogger:
    logger = logging.getLogger("CDA")

    if lvl is None:
        lvl = logging.INFO
        s = os.environ.get("CDA_LOG_LEVEL")
        if s:
            s = s.strip().upper()
            if s in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                lvl = typing.cast(int, getattr(logging, s))

    logger.setLevel(lvl)

    fmt = "%(asctime)s %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    handler = logging.StreamHandler()
    handler.setLevel(lvl)
    handler.setFormatter(formatter)

    global prev_handler
    if prev_handler is not None:
        logger.removeHandler(prev_handler)
    prev_handler = handler
    logger.addHandler(handler)

    return ExtendedLogger(logger)


prev_handler: Optional['logging.StreamHandler[TextIO]'] = None

logger = configure_logger()
