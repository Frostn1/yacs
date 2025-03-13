from collections import deque
from typing import Iterable

from loguru import logger
from pymongo.collection import Collection

from src.mdb_client import insert_cves_to_collection

from src.nvd.nvd_api import (
    NVD_MAX_YEAR,
    NVD_MIN_YEAR,
    _fetch_cves,
    _fetch_metafile,
)
from src.nvd.utils import years_need_of_cve_update


def download_metafiles(
    meta_collection: Collection,
    years_to_update: Iterable[int] = range(NVD_MIN_YEAR, NVD_MAX_YEAR + 1),
) -> None:
    """
    Update checkpoints for meta files

    Args:
        meta_collection (Collection): Collection to update metas in
        years_to_update (Iterable[int]): Years to update
    """
    deque(
        meta_collection.update_one(
            {"year": year},
            {"$set": vars(_fetch_metafile(year)) | {"year": year}},
            upsert=True,
        )
        for year in years_to_update
        if logger.info(f"Updating CVEs - {year}") or True
    )


def download_cves(
    cve_collection: Collection,
    years_to_update: Iterable[int] = range(NVD_MIN_YEAR, NVD_MAX_YEAR + 1),
) -> None:
    """
    Update CVEs by years

    Args:
        cve_collection (Collection): Collection to update CVEs in
        years_to_update (Iterable[int]): Years to update
    """
    deque(
        insert_cves_to_collection(cve_collection, _fetch_cves(year))
        for year in years_to_update
        if logger.info(f"Updating CVEs - {year}") or True
    )


def smart_download_cves(
    cve_collection: Collection, meta_collection: Collection
) -> None:
    """
    Update CVEs by knowing which years had updates in NVD compared to local copy.
    Then update only those ones.

    Args:
        cve_collection (Collection): Collection to update CVEs in
        meta_collection (Collection): Collection of meta files. i.e. know what data we have in local copy
    """
    download_cves(cve_collection, years_need_of_cve_update(meta_collection))
