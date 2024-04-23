import datetime
import logging
import os
import sys
import typing
from typing import Optional


_eval_level_global: Optional[int] = None


def _eval_level(level: Optional[int | str]) -> int:
    if level is not None:
        if isinstance(level, str):
            s1 = level.strip().upper()
            if s1 not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                raise ValueError(f"Invalid log level {repr(level)}")
            return typing.cast(int, getattr(logging, s1))
        return level

    global _eval_level_global
    if _eval_level_global is not None:
        return _eval_level_global

    level = logging.INFO
    s = os.environ.get("CDA_LOG_LEVEL")
    if s:
        s = s.strip().upper()
        if s in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            level = typing.cast(int, getattr(logging, s))
    _eval_level_global = level
    return level


class ExtendedLogger(logging.Logger):
    def __init__(self, name: str) -> None:

        fmt = "%(asctime)s %(levelname)s: %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        formatter = logging.Formatter(fmt, datefmt)

        main_handler = logging.StreamHandler()
        main_handler.setLevel(_eval_level(None))
        main_handler.setFormatter(formatter)

        self._formatter = formatter
        self._main_handler = main_handler
        self._file_handler: Optional[logging.FileHandler] = None

        super().__init__(name, level=logging.NOTSET + 1)
        self.addHandler(main_handler)

    def setLevel(self, level: Optional[int | str] = None, *, debug_to_file: bool = False) -> None:
        level = _eval_level(level)
        self._main_handler.setLevel(level)

        if debug_to_file and self._file_handler is None:
            # We only setup the file handler during setLevel. Unit tests
            # generally don't call this, so we don't write the logs to file.
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            file_handler = logging.FileHandler(f"/tmp/cda-{timestamp}-{os.getpid()}.log")
            file_handler.setFormatter(self._formatter)
            self._file_handler = file_handler
            self.addHandler(file_handler)

    def error_and_exit(self: 'ExtendedLogger', msg: str, *, exit_code: int = -1) -> typing.NoReturn:
        self.error(msg)
        sys.exit(exit_code)


# We want that our logger is of type ExtendedLogger to make typing happy. But
# we don't want that other instances of logging.getLogger() are.
#
# The way by overwriting the logger class here brings some limitation:
# - you MUST NOT call logging.getLogger("CDA") *before* importing this module.
# - you MUST NOT have another thread calling logging.getLogger() while importing
#   this module.
# This is normal! While the logging class is thread-safe, you must always
# setup the loggers before using them.
logging.Logger.manager.setLoggerClass(ExtendedLogger)
logger = typing.cast(ExtendedLogger, logging.getLogger("CDA"))
logging.Logger.manager.setLoggerClass(logging.Logger)
assert isinstance(logger, ExtendedLogger)
