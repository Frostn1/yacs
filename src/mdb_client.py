import contextlib
from typing import Generator, Iterable

from loguru import logger
from pymongo import MongoClient
from pymongo.collection import Collection

DEFAULT_CONNECTION_STRING = "localhost:27017"


@contextlib.contextmanager
def MongoDBClient(
    connection_str: str = DEFAULT_CONNECTION_STRING,
) -> Generator[MongoClient, None, None]:
    try:
        conn = MongoClient(connection_str)
        logger.info("Connected to MongoDB")
        yield conn
    finally:
        conn.close()


def insert_cves_to_collection(cve_collection: Collection, cves: Iterable[dict]) -> None:
    cve_collection.insert_many(cves)
    logger.info("Finished insertion")
