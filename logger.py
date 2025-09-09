import logging
import os
from typing import Any
from io import StringIO


class CdaLogger:
    def __init__(self, byte_limit: int = 50 * 1024 * 1024, lvl: int = logging.INFO):
        self.byte_limit = byte_limit
        self.total_bytes = 0
        self.buffer = StringIO()

        # Create logger
        self.logger = logging.getLogger("CDA")
        self.logger.setLevel(lvl)
        self.logger.handlers.clear()

        # Add only buffer handler to capture logs
        self.buffer_handler = logging.StreamHandler(self.buffer)
        prefix_fmt = "%(asctime)s %(levelname)s [th:%(thread)s] (%(filename)s:%(lineno)d)"
        date_fmt = "%Y-%m-%d %H:%M:%S"
        formatter = logging.Formatter(f"{prefix_fmt}: %(message)s", date_fmt)
        self.buffer_handler.setFormatter(formatter)
        self.logger.addHandler(self.buffer_handler)

    def _clear_buffer(self) -> None:
        self.buffer.seek(0)
        self.buffer.truncate(0)

    def _get_and_clear_buffer(self) -> str:
        content = self.buffer.getvalue()
        self._clear_buffer()
        return content

    def _remaining_bytes(self) -> int:
        return self.byte_limit - self.total_bytes

    def _check_and_output(self, level_name: str) -> None:
        content = self.buffer.getvalue()

        if not content:
            return

        content_bytes = len(content.encode('utf-8'))

        if content_bytes <= self._remaining_bytes():
            print(content, end='', flush=True)
            self.total_bytes += content_bytes
        else:
            if self._remaining_bytes() > 50:
                # Truncate and show partial
                truncated = content.encode('utf-8')[: self._remaining_bytes() - 40].decode('utf-8', errors='ignore')
                self.logger.error(truncated + " [TRUNCATED]")
                truncated_content = self._get_and_clear_buffer()
                print(truncated_content, flush=True)

            # Use logger for error message
            self.logger.error(f"Log limit of {self.byte_limit} bytes exceeded")
            error_content = self._get_and_clear_buffer()
            print(error_content, end='', flush=True)
            os._exit(-1)

    def debug(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.debug(msg, *args, **kwargs)
        self._check_and_output('debug')

    def info(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.info(msg, *args, **kwargs)
        self._check_and_output('info')

    def warning(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.warning(msg, *args, **kwargs)
        self._check_and_output('warning')

    def error(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.error(msg, *args, **kwargs)
        self._check_and_output('error')

    def critical(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.critical(msg, *args, **kwargs)
        self._check_and_output('critical')

    def exception(self, msg: Any, *args, **kwargs) -> None:
        self._clear_buffer()
        self.logger.exception(msg, *args, **kwargs)
        self._check_and_output('error')

    def error_and_exit(self, msg: str, *, exit_code: int = -1) -> None:
        self.error(msg)
        os._exit(exit_code)


def configure_cda_logger() -> CdaLogger:
    # Get log level from environment
    log_level = logging.INFO
    env_level = os.environ.get("CDA_LOG_LEVEL")
    if env_level:
        env_level = env_level.strip().upper()
        if env_level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            log_level = getattr(logging, env_level)

    return CdaLogger(lvl=log_level)


logger = configure_cda_logger()
