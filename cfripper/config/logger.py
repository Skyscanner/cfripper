import logging
import os


def setup_logging():
    if not os.environ.get("AWS_ACCOUNT"):
        logging.basicConfig(level=logging.DEBUG)
        return logging

    logging.basicConfig(level=logging.WARN)
    return logging
