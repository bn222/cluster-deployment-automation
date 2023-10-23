import logging
from typing import Optional
from typing import TextIO


def configure_logger(lvl: int) -> logging.Logger:
    logger = logging.getLogger("CDA")
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
    return logger


prev_handler: Optional[logging.StreamHandler[TextIO]] = None
logger = configure_logger(logging.INFO)
