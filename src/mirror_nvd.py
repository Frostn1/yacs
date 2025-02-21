#!/usr/bin/python
from collections import deque
import enum
from loguru import logger
from pymongo.collection import Collection
from requests import get
from typing import Iterable
from io import BytesIO
from gzip import GzipFile
from orjson import loads as orjson_loads
from src.mdb_client import UPDATE_OPERATIONS_MAP, MongoDBClient, UpdateOperation
from src.nvd_structs import MetaFile


import pymongo
import argparse
from os import environ as env
from datetime import datetime
import pytz
import requests
import gzip
import io
import json


NVD_MIN_YEAR = 2002
NVD_METAFILES_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.meta"
NVD_CVES_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


def _fetch_metafile(year: int = NVD_MIN_YEAR) -> MetaFile:
    """
    Fetch metafile for a singular year from NVD

    Args:
        year (int, optional): Year to fetch on. Defaults to NVD_MIN_YEAR.

    Returns:
        MetaFile: Meta data for said year
    """
    url = NVD_METAFILES_URL.format(year=year)
    logger.info(f"Fetching meta file - {url}")
    response = get(url=url)
    metadata = dict([i.split(":", maxsplit=1) for i in response.text.split()])
    return MetaFile(**metadata)


# Download specific CVE year
def _fetch_cves(year: int = NVD_MIN_YEAR) -> Iterable[dict]:
    """
    Fetches CVEs for a specific year from NVD

    Args:
        year (int, optional): Year to pull CVEs on. Defaults to NVD_MIN_YEAR.

    Returns:
        Iterable[dict]: Iterable of all CVEs for said year

    Yields:
        Iterator[Iterable[dict]]: Iterable of all CVEs for said year
    """
    url = NVD_CVES_URL.format(year=year)
    logger.info(f"Fetching CVEs - {url}")
    response = get(url=url, timeout=60, stream=True)
    with GzipFile(fileobj=BytesIO(response.content)) as f:
        yield from orjson_loads(f.read())["CVE_Items"]
    logger.error(f"Failed fetching CVEs - {year}")


def fetch_metafiles(
    min_year: int = NVD_MIN_YEAR, max_year: int = datetime.today().year
) -> Iterable[tuple[int, MetaFile]]:
    """
    Fetch metafiles for a range of years from NVD

    Args:
        min_year (int, optional): Start year to fetch for, inclusive. Defaults to NVD_MIN_YEAR.
        max_year (int, optional): End year to fetch for, inclusive. Defaults to datetime.today().year.

    Returns:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    return ((year, _fetch_metafile(year)) for year in range(min_year, max_year + 1))


# TODO Look over adding a custom class for checkpoint
def get_checkpoints(meta_collection: Collection) -> dict[int, datetime]:
    """
    Gets checkpoints for CVEs, i.e. to know when to update the cves DB

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        dict[int, datetime]: CVE Checkpoints
    """
    checkpoints = meta_collection.find(
        {"type": "cve checkpoint"}, {"feed": 1, "lastModifiedDate": 1}
    )
    return {
        checkpoint["feed"]: checkpoint["lastModifiedDate"] for checkpoint in checkpoints
    }


def fetch_cve_years_need_of_update(
    meta_collection: Collection,
) -> Iterable[tuple[int, MetaFile]]:
    """
    Fetches CVE years that need to be updated

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    checkpoints = get_checkpoints(meta_collection)
    return (
        (year, metafile)
        for year, metafile in fetch_metafiles()
        if year not in checkpoints.keys()
        or metafile.lastModifiedDate > pytz.UTC.localize(checkpoints[year])
    )


def update_checkpoints(meta_collection: Collection) -> None:
    """
    Update checkpoints for meta files

    Args:
        meta_collection (Collection): Collection to update metas in
    """
    deque(
        meta_collection.update_one(
            {"type": "cve checkpoint", "feed": year},
            {"$set": vars(metafile) | {"feed": year}},
            upsert=True,
        )
        for year, metafile in fetch_metafiles()
        if logger.info(f"Updateing checkpoint - {year}") or True
    )


def update_cves(
    cvs_collection: Collection, operation: UpdateOperation = UpdateOperation.SYNC
) -> None:
    """
    Update all CVEs

    Args:
        cvs_collection (Collection): Collection to update CVEs in
        operation (UpdateOperation, optional): Operation to perform on DB9. Defaults to UpdateOperation.SYNC.
    """
    deque(
        UPDATE_OPERATIONS_MAP.get(operation)(cvs_collection, _fetch_cves(year))
        for year, _ in fetch_cve_years_need_of_update()
        if logger.info(f"Updating CVEs - {year}") or True
    )
