import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
logger.addHandler(s_handler)
