#!/usr/bin/python
from collections import deque
from datetime import datetime
from aiohttp import ClientSession
from loguru import logger
from pymongo.collection import Collection
from pytz import UTC
from requests import get
from typing import AsyncIterable, Iterable
from io import BytesIO
from gzip import GzipFile
from orjson import loads as orjson_loads
from src.mdb_client import UPDATE_OPERATIONS_MAP, UpdateOperation
from src.nvd_structs import MetaFile


NVD_MIN_YEAR = 2002
NVD_MAX_YEAR = datetime.today().year
NVD_METAFILES_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta"
NVD_CVES_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


async def _fetch_metafile(year: int = NVD_MIN_YEAR) -> MetaFile:
    """
    Fetch metafile for a singular year from NVD

    Args:
        year (int, optional): Year to fetch on. Defaults to NVD_MIN_YEAR.

    Returns:
        MetaFile: Meta data for said year
    """
    url = NVD_METAFILES_URL.format(year=year)
    logger.info(f"Fetching meta file - {url}")
    async with ClientSession() as session:
        async with session.get(url=url) as response:
            metadata = dict([i.split(":", maxsplit=1) for i in response.text.split()])
            return MetaFile(**metadata)


async def _fetch_cves(year: int = NVD_MIN_YEAR) -> AsyncIterable[dict]:
    """
    Fetches CVEs for a specific year from NVD

    Args:
        year (int, optional): Year to pull CVEs on. Defaults to NVD_MIN_YEAR.

    Returns:
        Iterable[dict]: Iterable of all CVEs for said year

    Yields:
        AsyncIterable[Iterable[dict]]: Iterable of all CVEs for said year
    """
    url = NVD_CVES_URL.format(year=year)
    logger.info(f"Fetching CVEs - {url}")
    response = get(url=url, timeout=60, stream=True)
    async with ClientSession() as session:
        async with session.get(url=url, timeout=60, stream=True) as response:
            async with GzipFile(fileobj=BytesIO(response.content)) as f:
                async for v in orjson_loads(f.read())["CVE_Items"]:
                    yield v


async def fetch_metafiles(
    min_year: int = NVD_MIN_YEAR, max_year: int = datetime.today().year
) -> AsyncIterable[tuple[int, MetaFile]]:
    """
    Fetch metafiles for a range of years from NVD

    Args:
        min_year (int, optional): Start year to fetch for, inclusive. Defaults to NVD_MIN_YEAR.
        max_year (int, optional): End year to fetch for, inclusive. Defaults to datetime.today().year.

    Returns:
        AsyncIterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    return (
        (year, await _fetch_metafile(year)) for year in range(min_year, max_year + 1)
    )


# TODO Look over adding a custom class for checkpoint
async def get_checkpoints(async_meta_collection: Collection) -> dict[int, datetime]:
    """
    Gets checkpoints for CVEs, i.e. to know when to update the cves DB

    Args:
        async_meta_collection (Async Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        dict[int, datetime]: CVE Checkpoints
    """
    checkpoints = await async_meta_collection.find(
        {"type": "cve checkpoint"}, {"feed": 1, "lastModifiedDate": 1}
    )
    return {
        checkpoint["feed"]: checkpoint["lastModifiedDate"] for checkpoint in checkpoints
    }


async def fetch_cve_years_need_of_update(
    async_meta_collection: Collection,
) -> AsyncIterable[tuple[int, MetaFile]]:
    """
    Fetches CVE years that need to be updated

    Args:
        async_meta_collection (Async Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    checkpoints = await get_checkpoints(async_meta_collection)
    return (
        (year, metafile)
        async for year, metafile in await fetch_metafiles()
        if year not in checkpoints.keys()
        or metafile.lastModifiedDate > UTC.localize(checkpoints[year])
    )


async def update_checkpoints(
    async_meta_collection: Collection,
    min_year: int = NVD_MIN_YEAR,
    max_year: int = NVD_MAX_YEAR,
) -> None:
    """
    Update checkpoints for meta files

    Args:
        async_meta_collection (Async Collection): Collection to update metas in
    """
    deque(
        await async_meta_collection.update_one(
            {"type": "cve checkpoint", "feed": year},
            {"$set": vars(metafile) | {"feed": year}},
            upsert=True,
        )
        async for year, metafile in await fetch_metafiles(min_year, max_year)
        if logger.info(f"Updating checkpoint - {year}") or True
    )


async def update_cves_by_years(
    async_cve_collection: Collection,
    years: Iterable[int],
    operation: UpdateOperation = UpdateOperation.SYNC,
) -> None:
    """
    Update CVEs by years

    Args:
        async_cve_collection (Async Collection): Collection to update CVEs in
        years (Iterable[int]): Years to update
        operation (UpdateOperation, optional):  Operation to perform in DB. Defaults to UpdateOperation.SYNC.
    """
    deque(
        await UPDATE_OPERATIONS_MAP.get(operation)(
            async_cve_collection, _fetch_cves(year)
        )
        for year in years
        if logger.info(f"Updating CVEs - {year}") or True
    )


async def update_cves(
    async_cve_collection: Collection,
    meta_collection: Collection,
    operation: UpdateOperation = UpdateOperation.SYNC,
) -> None:
    """
    Update all CVEs

    Args:
        async_cve_collection (Async Collection): Collection to update CVEs in
        meta_collection (Collection): Collection to update metas in
        operation (UpdateOperation, optional): Operation to perform on DB. Defaults to UpdateOperation.SYNC.
    """
    await update_cves_by_years(
        async_cve_collection,
        (
            year
            async for year, _ in await fetch_cve_years_need_of_update(meta_collection)
        ),
        operation,
    )
