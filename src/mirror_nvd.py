#!/usr/bin/python
from loguru import logger
from pymongo.collection import Collection
from requests import get
from typing import Iterable
from io import BytesIO
from gzip import GzipFile
from orjson import loads as orjson_loads


import pymongo
import argparse
from os import environ as env
from datetime import datetime
import pytz
import requests
import gzip
import io
import json

from src.mdb_client import MongoDBClient
from src.nvd_structs import MetaFile

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
def get_checkpoints(collection: Collection) -> dict[int, datetime]:
    """
    Gets checkpoints for CVEs, i.e. to know when to update the cves DB

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        dict[int, datetime]: CVE Checkpoints
    """
    checkpoints = collection.find(
        {"type": "cve checkpoint"}, {"feed": 1, "lastModifiedDate": 1}
    )
    return {
        checkpoint["feed"]: checkpoint["lastModifiedDate"] for checkpoint in checkpoints
    }


def fetch_cve_years_need_of_update(
    collection: Collection,
) -> Iterable[tuple[int, MetaFile]]:
    """
    Fetches CVE years that need to be updated

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    checkpoints = get_checkpoints(collection)
    return (
        (year, metafile)
        for year, metafile in fetch_metafiles()
        if year not in checkpoints.keys()
        or metafile.lastModifiedDate > pytz.UTC.localize(checkpoints[year])
    )


# Wrapper to download all CVE years
def download_and_upsert_nvd(years_need_updates, t="sync"):
    db = conn["nvd_mirror"]
    coll = db["cves"]
    for year in years_need_updates:
        data = get_nvd_part(year)
        logger.info(f"{year} has {len(data)} CVEs to insert")
        # Sync by updating only the specific CVEs that need updating
        if t == "sync":
            ops = [
                pymongo.operations.ReplaceOne(
                    filter={"cve.CVE_data_meta.ID": doc["cve"]["CVE_data_meta"]["ID"]},
                    replacement=doc,
                    upsert=True,
                )
                for doc in data
            ]
            result = coll.bulk_write(ops)
            logger.info(f"Done inserting: {result.bulk_api_result}")
        # Just insert if we're doing the initial data dump
        elif t == "initial":
            coll.insert_many(data)
            logger.info(f"Done inserting {len(data)} items")
        logger.info(f"Finished inserting {year}'s CVEs")


with MongoDBClient() as conn:
    eval_needed_updates(conn["nvd_mirror"]["meta"])
exit(1)


def update_checkpoint(conn, metafiles):
    db = conn["nvd_mirror"]
    coll = db["meta"]
    for feed, metadata in metafiles.items():
        metadata["feed"] = feed
        coll.update_one(
            {"type": "cve checkpoint", "feed": feed}, {"$set": metadata}, upsert=True
        )
        logger.info(f"Checkpoint for feed {feed} is updated")


def get_special(conn, feed):
    assert feed in ["modified", "recent"]
    link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{feed}.meta"
    logger.info(f"Getting meta file: {link}")
    res = requests.get(link)
    metadata = dict()
    o = res.text.split()
    for _ in o:
        _ = _.split(":")
        metadata[_[0]] = ":".join(_[1:])
    metadata["lastModifiedDate"] = datetime.strptime(
        metadata["lastModifiedDate"], "%Y-%m-%dT%H:%M:%S%z"
    )
    metadata["feed"] = feed
    metadata = {feed: metadata}
    checkpoints = get_checkpoints(conn)
    utc = pytz.UTC
    if feed not in checkpoints.keys() or checkpoints[feed].replace(
        tzinfo=utc
    ) < metadata[feed]["lastModifiedDate"].replace(tzinfo=utc):
        logger.info(f"Updates available in the '{feed}' feed")
        link = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{feed}.json.gz"
        res = requests.get(link, timeout=60, stream=True)
        # Gunzip in memory
        gz_file = res.content
        fd = io.BytesIO(gz_file)
        with gzip.GzipFile(fileobj=fd) as f:
            data = json.loads(f.read())["CVE_Items"]
        logger.info(f"'{feed}' feed has {len(data)} items to insert")
        db = conn["nvd_mirror"]
        coll = db["cves"]
        ops = [
            pymongo.operations.ReplaceOne(
                filter={"cve.CVE_data_meta.ID": doc["cve"]["CVE_data_meta"]["ID"]},
                replacement=doc,
                upsert=True,
            )
            for doc in data
        ]
        result = coll.bulk_write(ops)
        logger.info(f"Done inserting: {result.bulk_api_result}")
        update_checkpoint(conn, metadata)
        return True
    else:
        logger.info(
            f"No updates to the '{feed}' feed. Latest update was at {str(checkpoints[feed])}"
        )
        return False


def get_cpe_feed(conn, t="sync"):
    assert t in ["sync", "initial"]
    feed = "cpe"
    link = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.meta"
    logger.info("Getting meta file: cpe")
    res = requests.get(link)
    metadata = dict()
    o = res.text.split()
    for _ in o:
        _ = _.split(":")
        metadata[_[0]] = ":".join(_[1:])
    metadata["lastModifiedDate"] = datetime.strptime(
        metadata["lastModifiedDate"], "%Y-%m-%dT%H:%M:%S%z"
    )
    metadata["feed"] = feed
    metadata = {feed: metadata}
    checkpoints = get_checkpoints(conn)
    utc = pytz.UTC
    if feed not in checkpoints.keys() or checkpoints[feed].replace(
        tzinfo=utc
    ) < metadata[feed]["lastModifiedDate"].replace(tzinfo=utc):
        logger.info("Updates available in the 'cpe' feed")
        link = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
        res = requests.get(link, timeout=60, stream=True)
        # Gunzip in memory
        gz_file = res.content
        fd = io.BytesIO(gz_file)
        with gzip.GzipFile(fileobj=fd) as f:
            data = json.loads(f.read())["matches"]
        logger.info(f"'{feed}' feed has {len(data)} items to insert")
        db = conn["nvd_mirror"]
        coll = db["cpes"]
        """
        if t == "sync":
            ops = [pymongo.operations.ReplaceOne(filter={"cpe23Uri": doc["cpe23Uri"]},
                replacement = doc,
                upsert = True) for doc in data]
            result = coll.bulk_write(ops)
            logger.info(f"Done inserting: {result.bulk_api_result}")
        """
        coll.drop()
        coll.insert_many(data)
        logger.info(f"Done inserting {len(data)} items")
        update_checkpoint(conn, metadata)
        return True
    else:
        logger.info(
            f"No updates to the 'cpe' feed. Latest update was at {str(checkpoints['cpe'])}"
        )
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-m",
        "--mode",
        help="One of 'initial', 'sync', or 'update'\n\t'initial' - dumbly insert all of the CVEs from NVD into MongoDB\n\t'sync' - download whole years worth of CVEs and replace them all if they've been updated recently\n\t'update' - use the \"modified\" and \"recent\" JSON blobs to target which CVEs to update",
        required=True,
    )
    parser.add_argument(
        "-t", "--type", help="either cve or cpe type to get data for", default="cve"
    )
    args = parser.parse_args()
    args.mode = args.mode.lower().strip()
    if args.type == "cve":
        if args.mode == "initial":
            # Below is for initial sync
            conn = connect_mdb()
            years_need_updates, metafiles = eval_needed_updates(conn)
            download_and_upsert_nvd(years_need_updates, t="initial")
            update_checkpoint(conn, metafiles)
            conn.close()
            logger.info("Atlas connection closed. Done!")
        elif args.mode == "sync":
            conn = connect_mdb()
            years_need_updates, metafiles = eval_needed_updates(conn)
            download_and_upsert_nvd(years_need_updates, t="sync")
            update_checkpoint(conn, metafiles)
            conn.close()
            logger.info("Atlas connection closed. Done!")
        elif args.mode == "update":
            conn = connect_mdb()
            get_special(conn, "modified")
            get_special(conn, "recent")
            conn.close()
            logger.info("Atlas connection closed. Done!")
        else:
            logger.error("--mode must be one of 'initial', 'sync', or 'update'")
            exit(1)
    elif args.type == "cpe":
        conn = connect_mdb()
        get_cpe_feed(conn, t="initial")
        conn.close()
        logger.info("Atlas connection closed. Done!")
