import asyncio
from itertools import chain
from re import Match, I as Insensitive, M as Multiline, findall, search
import sys
from typing import Callable, Iterable
from loguru import logger
from pymongo.collection import Collection
from packaging.version import Version
from src.confidence import Confidence
from src.cpematch import CPEMatch, is_version
from src.cvematch import CVEMatch
from src.cvequery import CVEQuery
from src.mdb_client import MongoDBClient
from src.utils import (
    async_any,
    extract_cpe_from_cve,
    is_product_name_in_cpe,
    is_vendor_name_in_cpe,
    normalize_app_name,
)


GENERIC_VERSION_REGEX = r"v?\d\S*"
CHARS_TO_STRIP = "!\"#$%&'()*+, -./:;<=>?@[\]^_`{|}~"
VERSION_PREFIX = "vx"


async def get_cves_by_query(
    cves_collection: Collection, query: CVEQuery
) -> Iterable[dict]:
    query = {
        "$or": [
            {
                "cve.description.description_data": {
                    "$elemMatch": {
                        "value": {
                            "$regex": f"(\s|^){normalize_app_name(query.product)}(\s|$)",
                            "$options": "si",
                        }
                    }
                }
            },
            {
                "configurations.nodes": {
                    "$elemMatch": {
                        "cpe_match": {
                            "$elemMatch": {
                                "$or": [
                                    {
                                        "cpe23Uri": {
                                            "$regex": f"^cpe:2\.3:\w:[^:]+:{query.product}:",
                                            "$options": "i",
                                        }
                                    },
                                    {
                                        "cpe23Uri": {
                                            "$regex": f"^cpe:2\.3:\w:{query.vendor}:",
                                            "$options": "i",
                                        }
                                    },
                                ]
                            }
                        }
                    }
                }
            },
        ],
    }
    count = cves_collection.count_documents(query)
    logger.debug(f"Query - {count} documents")
    return (doc for doc in cves_collection.find(query))


async def _validate_cpe_version(cve: dict, query: CVEQuery) -> bool:
    """
    Validate version is in vulnerable cpe version range

    Args:
        cve (dict): CVE to use for CPE
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Is version in CPE vulnerable version range
    """
    return await async_any(cpe.is_inrange(query.version) for cpe in extract_cpe_from_cve(cve))


async def _validate_product_name_in_cpe(cve: dict, query: CVEQuery) -> bool:
    """
    Validate application name is contained in cpe

    Args:
        cve (dict): CVE to check against
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Whether or not app name is in CPE
    """

    return await async_any(
        await is_product_name_in_cpe(query.product, cpe.cpe23Uri)
        async for cpe in extract_cpe_from_cve(cve)
    )


async def _validate_vendor_name_in_cpe(cve: dict, query: CVEQuery) -> bool:
    """
    Validate vendor name is contained in cpe

    Args:
        cve (dict): CVE to check against
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Whether or not vendor name is in CPE
    """

    return await async_any(
        await is_vendor_name_in_cpe(query.vendor, cpe.cpe23Uri)
        async for cpe in extract_cpe_from_cve(cve)
    )


async def _extract_versions_from_regex(matches: list[Match]) -> tuple[Version, ...]:
    """
    Extracts all version referenced in regex match

    Args:
        matches (list[Match]): List of matches in summary

    Returns:
        tuple[Version, ...]: All versions found
    """
    if not matches:
        return tuple()

    versions = chain(
        *(
            map(
                lambda m: m.group().strip(CHARS_TO_STRIP + VERSION_PREFIX),
                filter(
                    lambda x: x,
                    map(
                        lambda group: search(
                            GENERIC_VERSION_REGEX, group, flags=Insensitive | Multiline
                        ),
                        list(filter(lambda g: g.strip(), match)),
                    ),
                ),
            )
            for match in matches
        )
    )
    return tuple(set(Version(version) for version in versions if is_version(version)))


async def _is_version_in_between(
    found_versions: list[Version], version: Version
) -> bool:
    """
    Validate if version is between max and min version in `found_versions`

    Args:
        found_versions (list[Version]): List of version found in summary
        version (Version): Version to check against

    Returns:
        bool: Is in between
    """
    if not found_versions:
        return False
    max_version = max(found_versions)
    min_version = min(found_versions)
    return min_version <= version <= max_version


async def _is_version_before(found_versions: list[Version], version: Version) -> bool:
    """
    Checks if version is before any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version before
    """
    return any(version < found_version for found_version in found_versions)


async def _is_version_after(found_versions: list[Version], version: Version) -> bool:
    """
    Checks if version is after any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version after
    """
    return any(version > found_version for found_version in found_versions)


async def _is_version_in_versions(
    found_versions: list[Version], version: Version
) -> bool:
    """
    Checks if version is after any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version after
    """
    return version in found_versions


async def _validate_version_in_summary(cve: dict, query: CVEQuery) -> bool:
    """_summary_

    Args:
        cve (dict): _description_
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: _description_
    """
    description = cve["cve"]["description"]["description_data"][0]["value"]
    regexes: dict[str, Callable[[list[Version], Version], bool]] = {
        # Between versions
        "((v?\d\S*?)(\sthrough\s)(v?\d\S*?)(\s|$))|((version|versions)\s(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(between\s(version\s|versions\s)?(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(before\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?after\s(version\s|versions\s)?(v?\d\S*?)(\s|$))|(after\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?before\s(version\s|versions\s)?(v?\d\S*?)(\s|$))": _is_version_in_between,
        # Before versions
        "(((versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(versions\s)?)(v?\d\S*?)(,(\s(and\s)?(v?\d\S*))+))|((((version\s|versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(version\s|versions\s)?)|(<(=)?\s+?))(v?\d\S*?)(\s|$)(?!and\safter))|(version|versions)?(\s(v?\d\S*?)\s(\()?and\s(below|prior|before|earlier)(\))?)": _is_version_before,
        # # After versions
        "(?!and)\s((((after)\s(version\s|versions\s)?)|(>(=)?\s+?))(v?\d\S*?)(\s|$)(?!and))|(\s(v?\d\S?)\s(\()and\s(after|later)(\)))": _is_version_after,
        # # Raw versions
        "(\s(version\s)?(v?\d\S*?)(\s|$)(?!and))": _is_version_in_versions,
    }
    for regex, validate_function in regexes.items():
        versions = _extract_versions_from_regex(
            findall(regex, description, flags=Insensitive | Multiline)
        )

        if validate_function(versions, query.version):
            return True
    return False


async def _validate_product_in_summary(cve: dict, query: CVEQuery) -> bool:
    return (
        bool(query.product)
        and query.product in cve["cve"]["description"]["description_data"][0]["value"]
    )


async def is_legitimate_cve(cve: dict, query: CVEQuery) -> CVEMatch:
    """
    Checks if CVE is legitimate for version,

    Args:
        cve (dict): CVE to check
        query (CVEQuery): Parameters to use

    Returns:
        bool: is CVE legitimate
    """
    confidence: list[Confidence] = [
        Confidence("Product name contained in summary", _validate_product_in_summary),
        Confidence("Product name contained in CPE URI", _validate_product_name_in_cpe),
        Confidence("Vendor name contained in CPE URI", _validate_vendor_name_in_cpe),
        Confidence("Version is in CPE Version Range", _validate_cpe_version),
        Confidence("Version is in Summary", _validate_version_in_summary),
    ]

    return CVEMatch(cve, query, confidence)


async def search_vulnerabilities(
    cves_collection: Collection,
    queries: list[CVEQuery],
    threshhold: float = 0.6,
) -> Iterable[tuple[CVEQuery, Iterable[CVEMatch]]]:
    """
    Search for vulnerabilities in versions listed and using NVD mirror DB

    Args:
        cves_collection (Collection): NVD Mirror DB to query against
        queries (list[CVEQuery]): List of queries to perform
        threshhold (float, optional): Confidence threshhold. Defaults to 0.75.

    Returns:
        Iterable[CVEQuery, Iterable[tuple[float, dict]]]: Iterable of tuples, Query and Iterable of CVEMatches for that query
    """

    return (
        (
            query,
            (
                cvematch
                async for cvematch in (
                    await is_legitimate_cve(cve, query)
                    for cve in await get_cves_by_query(cves_collection, query)
                )
                if await cvematch.confidence_score >= threshhold
            ),
        )
        for query in queries
    )


async def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client["my_nvd_mirror"]["cves"]
        query = CVEQuery("f5", "nginx", Version("1.18.0"))
        async for query, cves in await search_vulnerabilities(cve_collection, [query]):
            # cves = list(cves)
            # print(f"Query - {query} , Found {len(cves)} cves")

            async for cvematch in cves:
                logger.info(
                    f"Found CVE [Confidence {await cvematch.get_raw_confidences}] - {query.version} {cvematch.cve['cve']['CVE_data_meta']['ID']}"
                )


async def execute():
    async with asyncio.TaskGroup() as group:
        group.create_task(main())


if __name__ == "__main__":
    asyncio.run(execute())
