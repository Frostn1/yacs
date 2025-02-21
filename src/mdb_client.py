import contextlib
from typing import Generator

from loguru import logger
from pymongo import MongoClient


DEFAULT_CONNECTION_STRING = "localhost:27017"


@contextlib.contextmanager
def MongoDBClient(
    connection_str: str = DEFAULT_CONNECTION_STRING,
) -> Generator[MongoClient, None, None]:
    try:
        conn = MongoClient(connection_str)
        logger.info("Connected to MongoDB")
        yield conn
    except Exception as e:
        logger.error("Unable to connect to MongoDB: {}".format(e))
        exit(1)
    finally:
        conn.close()
