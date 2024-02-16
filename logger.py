import logging


def configure_logger(stream_lvl: int, file_lvl: int) -> logging.Logger:
    logger = logging.getLogger("CDA")
    lvl = min(stream_lvl, file_lvl)
    logger.setLevel(lvl)

    fmt = "%(asctime)s %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    fh = logging.FileHandler("cda-debug.log", mode='w')
    fh.setLevel(file_lvl)
    fh.setFormatter(formatter)

    handler = logging.StreamHandler()
    handler.setLevel(stream_lvl)
    handler.setFormatter(formatter)

    if logger.handlers is not None:
        for h in reversed(logger.handlers):
            logger.removeHandler(h)

    logger.addHandler(handler)
    logger.addHandler(fh)
    return logger


logger = configure_logger(logging.INFO, logging.DEBUG)
