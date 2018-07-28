import os
import logging

# variables section
current_path = os.path.dirname(os.path.abspath(__file__))
path = os.path.join(current_path, os.pardir, os.pardir, "logs")
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


def create_dir(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise


def setup_logger(name, log_file, level=logging.DEBUG):
    """Function setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


create_dir(path)

# Default logger
log_file = os.path.join(path, "shield.log")
setup_logger('shield_app', log_file)
