from datetime import datetime
from typing import Iterable
from pymongo.collection import Collection
from pytz import UTC

from src.nvd.nvd_api import fetch_metafiles



def query_metas(meta_collection: Collection) -> dict[int, datetime]:
    """
    Gets metas for CVEs, i.e. to know when to update the CVEs DB

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Returns:
        dict[int, datetime]: CVE metas
    """
    metas = meta_collection.find({"year": 1, "lastModifiedDate": 1})
    return {checkpoint["year"]: checkpoint["lastModifiedDate"] for checkpoint in metas}


def years_need_of_cve_update(
    meta_collection: Collection,
) -> Iterable[int]:
    """
    Fetches CVE years that need to be updated

    Args:
        collection (Collection): Collection, usually under meta, that holds CVE checkpoints

    Yields:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    metas = query_metas(meta_collection)
    yield from (
        year
        for year, metafile in fetch_metafiles()
        if year not in metas.keys()
        or metafile.lastModifiedDate > UTC.localize(metas[year])
    )
