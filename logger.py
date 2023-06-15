import logging


def configure_logger(lvl):
    global logger
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


prev_handler = None
logger = None
configure_logger(logging.INFO)
