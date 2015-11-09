import logging


__VERSION__ = '0.2.3'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.handlers = [logging.StreamHandler()]
