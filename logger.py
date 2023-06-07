import logging


def configure_logger(lvl):
    global logger
    logger = logging.getLogger("CDA")
    logger.setLevel(lvl)

    fmt = "%(asctime)s %(levelname)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)

    logger.addHandler(handler)


logger = None
configure_logger(logging.DEBUG)
