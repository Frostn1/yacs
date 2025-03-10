import asyncio
from datetime import datetime

from pymongo import AsyncMongoClient, MongoClient
from src.mdb_client import MongoDBClient, UpdateOperation
from src.mirror_nvd import (
    get_checkpoints,
    update_checkpoints,
    update_cves,
    update_cves_by_years,
)


async def main() -> None:
    start = datetime.now()
    with MongoClient() as mdb_client:
        meta_collection = mdb_client["nvd_mirror2"]["meta"]
        cve_collection = mdb_client["nvd_mirror2"]["cves"]
        update_cves_by_years(
            cve_collection, range(2020, 2026), UpdateOperation.INITIAL
        )
    end = datetime.now()
    print(f"Time taken: {end - start} seconds")


if __name__ == "__main__":
    asyncio.run(main())
