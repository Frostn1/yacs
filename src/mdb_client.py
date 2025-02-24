import contextlib
import enum
from typing import Callable, Generator, Iterable

from loguru import logger
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.operations import ReplaceOne

DEFAULT_CONNECTION_STRING = "localhost:27017"


class UpdateOperation(enum.StrEnum):
    INITIAL = "initial"
    SYNC = "sync"


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


async def _sync_cves(cves_collection: Collection, cves: Iterable[dict]) -> None:
    replacments = (
        ReplaceOne(
            filter={"cve.CVE_data_meta.ID": cve["cve"]["CVE_data_meta"]["ID"]},
            replacement=cve,
            upsert=True,
        )
        for cve in cves
    )
    result = await cves_collection.bulk_write(list(replacments))
    logger.info(f"Finished synching - {result.bulk_api_result}")


async def _initial_cves(cves_collection: Collection, cves: Iterable[dict]) -> None:
    await cves_collection.insert_many(cves)
    logger.info("Finished initial insertion")


UPDATE_OPERATIONS_MAP: dict[
    UpdateOperation, Callable[[Collection, Iterable[dict]], None]
] = {
    UpdateOperation.SYNC: _sync_cves,
    UpdateOperation.INITIAL: _initial_cves,
}
