import contextlib
from typing import Generator, Iterable

from loguru import logger
from pymongo import MongoClient, UpdateOne
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


def update_cves_in_collection(cve_collection: Collection, cves: Iterable[dict]) -> None:
    ops = [
        UpdateOne(
            filter={"cve.CVE_data_meta.ID": cve["cve"]["CVE_data_meta"]["ID"]},
            update={"$set": cve},
            upsert=True,
        )
        for cve in cves
    ]
    cve_collection.bulk_write(ops)
    logger.debug("Finished insertion")
