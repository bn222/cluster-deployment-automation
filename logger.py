import logging
import os
import typing
from typing import Optional
from typing import Any
from io import StringIO


class ExtendedLogger:
    def __init__(self, logger: logging.Logger, byte_limit: int = 50 * 1024 * 1024):
        self._wrapped_logger = logger
        self._total_bytes = 0
        self._byte_limit = byte_limit
        self._string_buffer = StringIO()
        self._limit_disabled = False

    def _process_buffered_log(self, log_level: str = 'info') -> None:
        string_buffer = object.__getattribute__(self, '_string_buffer')
        logged_content = string_buffer.getvalue()
        string_buffer.seek(0)
        string_buffer.truncate(0)

        if logged_content:
            limit_disabled = object.__getattribute__(self, '_limit_disabled')
            if limit_disabled:
                print(logged_content, end='')
                return

            total_bytes = object.__getattribute__(self, '_total_bytes')
            byte_limit = object.__getattribute__(self, '_byte_limit')
            new_bytes = len(logged_content.encode('utf-8'))

            if total_bytes + new_bytes > byte_limit:
                remaining_bytes = byte_limit - total_bytes
                if remaining_bytes <= 50:
                    object.__setattr__(self, '_limit_disabled', True)
                    wrapped_logger = object.__getattribute__(self, '_wrapped_logger')
                    wrapped_logger.error(f"Log limit of {byte_limit} bytes exceeded. Total: {total_bytes}, New: {new_bytes}, Remaining: {remaining_bytes}")
                    os._exit(-1)

                truncation_msg = " [TRUNCATED - Log limit exceeded]"
                available_bytes = remaining_bytes - len(truncation_msg.encode('utf-8'))

                object.__setattr__(self, '_limit_disabled', True)
                wrapped_logger = object.__getattribute__(self, '_wrapped_logger')

                if available_bytes > 0:
                    truncated_content = logged_content.encode('utf-8')[:available_bytes].decode('utf-8', errors='ignore')
                    getattr(wrapped_logger, log_level)(truncated_content)

                wrapped_logger.error(truncation_msg)

                wrapped_logger.error(f"Log limit of {byte_limit} bytes exceeded. Total: {total_bytes}, New: {new_bytes}, Remaining: {remaining_bytes}")
                os._exit(-1)
            else:
                print(logged_content, end='')
                object.__setattr__(self, '_total_bytes', total_bytes + new_bytes)

    def __getattribute__(self: 'ExtendedLogger', name: str) -> Any:
        if name in ('error_and_exit', '_wrapped_logger', '_total_bytes', '_byte_limit', '_string_buffer', '_limit_disabled', '_process_buffered_log'):
            return object.__getattribute__(self, name)
        if name in ('debug', 'info', 'warning', 'error', 'critical', 'exception'):
            logger = object.__getattribute__(self, '_wrapped_logger')
            original_method = logger.__getattribute__(name)

            def counting_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = original_method(*args, **kwargs)
                self._process_buffered_log(name)
                return result

            return counting_wrapper

        logger = object.__getattribute__(self, '_wrapped_logger')
        return logger.__getattribute__(name)

    def error_and_exit(self: 'ExtendedLogger', msg: str, *, exit_code: int = -1) -> typing.NoReturn:
        self.error(msg)
        os._exit(exit_code)


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

    fmt = "%(asctime)s %(levelname)s [th:%(thread)s] (%(filename)s:%(lineno)d): %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    extended_logger = ExtendedLogger(logger)

    global prev_handler
    if prev_handler is not None:
        logger.removeHandler(prev_handler)

    string_handler = logging.StreamHandler(extended_logger._string_buffer)
    string_handler.setLevel(lvl)
    string_handler.setFormatter(formatter)
    prev_handler = string_handler
    logger.addHandler(string_handler)

    return extended_logger


prev_handler: Optional[logging.StreamHandler[Any]] = None

logger = configure_logger()
