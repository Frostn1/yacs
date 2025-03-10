import contextlib
import enum
from typing import AsyncIterable, Callable, Generator, Iterable

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


async def _async_sync_cves(cves_collection: Collection, cves: AsyncIterable[dict]) -> None:
    replacments = [
        ReplaceOne(
            filter={"cve.CVE_data_meta.ID": cve["cve"]["CVE_data_meta"]["ID"]},
            replacement=cve,
            upsert=True,
        )
        for cve in cves
    ]
    result = await cves_collection.bulk_write(replacments)
    logger.info(f"Finished synching - {result.bulk_api_result}")


async def _async_initial_cves(cves_collection: Collection, cves: AsyncIterable[dict]) -> None:
    await cves_collection.insert_many([cve async for cve in cves])
    logger.info("Finished initial insertion")

def _sync_cves(cves_collection: Collection, cves: Iterable[dict]) -> None:
    replacments = [
        ReplaceOne(
            filter={"cve.CVE_data_meta.ID": cve["cve"]["CVE_data_meta"]["ID"]},
            replacement=cve,
            upsert=True,
        )
        for cve in cves
    ]
    result = cves_collection.bulk_write(replacments)
    logger.info(f"Finished synching - {result.bulk_api_result}")


def _initial_cves(cves_collection: Collection, cves: Iterable[dict]) -> None:
    cves_collection.insert_many([cve for cve in cves])
    logger.info("Finished initial insertion")


UPDATE_OPERATIONS_MAP: dict[
    UpdateOperation, Callable[[Collection, AsyncIterable[dict]], None]
] = {
    UpdateOperation.SYNC: _async_sync_cves,
    UpdateOperation.INITIAL: _async_initial_cves,
}

UPDATE_OPERATIONS_MAP: dict[
    UpdateOperation, Callable[[Collection, Iterable[dict]], None]
] = {
    UpdateOperation.SYNC: _sync_cves,
    UpdateOperation.INITIAL: _initial_cves,
}
