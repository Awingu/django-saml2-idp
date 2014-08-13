import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.handlers = [logging.StreamHandler()]
