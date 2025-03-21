from collections import deque
from typing import Iterable

from loguru import logger
from pymongo.collection import Collection


# from cve_searcher.nvd.nvd_api import (
#     NVD_MAX_YEAR,
#     NVD_MIN_YEAR,
#     _fetch_cves,
#     _fetch_metafile,
# )
from src.mongodb import update_cves_in_collection
from src.nvd.nvd_api import NVD_MAX_YEAR, NVD_MIN_YEAR, _fetch_cves, _fetch_metafile
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
        if logger.info(f"Downloading Meta File - {year}") or True
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
        update_cves_in_collection(cve_collection, _fetch_cves(year))
        for year in years_to_update
        if logger.info(f"Downloading CVEs - {year}") or True
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
    need_of_update = list(years_need_of_cve_update(meta_collection))
    download_cves(cve_collection, need_of_update)
    download_metafiles(meta_collection, need_of_update)


def try_create_index(collection: Collection, index: dict, **kwargs) -> None:
    try:
        collection.create_index(index, **kwargs)
    except Exception:
        logger.warning(
            f"Failed to create index {index}. Does this index already exists ?"
        )


def setup_db(cve_collection: Collection, meta_collection: Collection) -> None:
    try_create_index(
        cve_collection, {"cve.description.description_data.value_text": "text"}
    )
    try_create_index(cve_collection, {"configurations.nodes.cpe_match.cpe23Uri": 1})
    try_create_index(cve_collection, {"cve.CVE_data_meta.ID": 1}, unique=True)
    download_metafiles(meta_collection)
    download_cves(cve_collection)
