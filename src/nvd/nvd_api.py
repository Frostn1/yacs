from datetime import datetime
from gzip import GzipFile
from io import BytesIO
from typing import Iterable

from loguru import logger
from requests import get
from orjson import loads as orjson_loads
from src.nvd.nvd_structs import MetaFile


NVD_MIN_YEAR = 2002
NVD_MAX_YEAR = datetime.today().year
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


def fetch_metafiles(
    min_year: int = NVD_MIN_YEAR, max_year: int = datetime.today().year
) -> Iterable[tuple[int, MetaFile]]:
    """
    Fetch metafiles for a range of years from NVD

    Args:
        min_year (int, optional): Start year to fetch for, inclusive. Defaults to NVD_MIN_YEAR.
        max_year (int, optional): End year to fetch for, inclusive. Defaults to datetime.today().year.

    Yields:
        Iterable[tuple[int, MetaFile]]: Iterable of tuples, year and meta file for said year
    """
    yield from ((year, _fetch_metafile(year)) for year in range(min_year, max_year + 1))


def fetch_cves(
    min_year: int = NVD_MIN_YEAR, max_year: int = datetime.today().year
) -> Iterable[tuple[int, Iterable[dict]]]:
    """
    Fetch CVEs for a range of years from NVD

    Args:
        min_year (int, optional): Start year to fetch for, inclusive. Defaults to NVD_MIN_YEAR.
        max_year (int, optional): End year to fetch for, inclusive. Defaults to datetime.today().year.

    Yields:
        Iterable[tuple[int, dict]]: Iterable of tuples, year and cves for said year
    """
    yield from ((year, _fetch_cves(year)) for year in range(min_year, max_year + 1))
