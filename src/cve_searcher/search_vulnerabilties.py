from itertools import chain
from re import Match, I as Insensitive, M as Multiline, findall, search
from typing import Callable, Iterable, Iterator
from loguru import logger
from pymongo.collection import Collection
from packaging.version import Version
from src.cve_searcher.confidence import Confidence
from src.cve_searcher.cpematch import is_version
from src.cve_searcher.cvematch import CVEMatch
from src.cve_searcher.cvequery import CVEQuery
from src.cve_searcher.utils import (
    extract_cpe_from_cve,
    extract_cpe_from_cve_per_product,
    is_application_name_in_cpe,
    is_date,
    is_vendor_name_in_cpe,
)


GENERIC_VERSION_REGEX = r"v?\d\S*"
CHARS_TO_STRIP = r"!\"#$%&'()*+, -./:;<=>?@[\]^_`{|}~"
VERSION_PREFIX = "vx"


def get_cves_by_query(cve_collection: Collection, query: CVEQuery) -> Iterable[dict]:
    """
    Get CVE's from cve_collection ( NVD copy ), by query which is product, and vendor

    Args:
        cve_collection (Collection): cve collection from NVD
        query (CVEQuery): Query to search for

    Returns:
        Iterable[dict]: All cves found
    """
    query = {
        "$or": [
            {
                "$text": {
                    "$search": query.product,
                    "$caseSensitive": False,
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
                                            "$regex": rf"^cpe:2\.3:\w:[^:]+:{query.product}:",
                                            "$options": "si",
                                        }
                                    },
                                    {
                                        "cpe23Uri": {
                                            "$regex": rf"^cpe:2\.3:\w:{query.vendor}:",
                                            "$options": "si",
                                        }
                                    },
                                ]
                            }
                        }
                    }
                }
            },
        ]
    }

    projections = {
        "_id": 0,
        "cve.CVE_data_meta.ID": 1,
        "cve.description.description_data.value_text": 1,
        "configurations.nodes.cpe_match": 1,
    }

    logger.debug(f"Query - {query}")
    if cve_collection.count_documents(query) == 0:
        logger.warning("No CVE's found for query. Did you remember to setup the DB ?")
    return cve_collection.find(query, projections)


def _validate_cpe_version(cve: dict, query: CVEQuery) -> bool:
    """
    Validate version is in vulnerable cpe version range

    Args:
        cve (dict): CVE to use for CPE
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Is version in CPE vulnerable version range
    """
    return any(
        query.version and cpe.is_inrange(query.version)
        for cpe in extract_cpe_from_cve_per_product(cve, query.product)
    )


def _validate_product_name_in_cpe(cve: dict, query: CVEQuery) -> bool:
    """
    Validate application name is contained in cpe

    Args:
        cve (dict): CVE to check against
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Whether or not app name is in CPE
    """
    return any(
        map(
            lambda cpe: is_application_name_in_cpe(query.product, cpe.cpe23Uri),
            extract_cpe_from_cve(cve),
        )
    )


def _validate_vendor_name_in_cpe(cve: dict, query: CVEQuery) -> bool:
    """
    Validate vendor name is contained in cpe

    Args:
        cve (dict): CVE to check against
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: Whether or not vendor name is in CPE
    """
    return any(
        map(
            lambda cpe: is_vendor_name_in_cpe(query.vendor, cpe.cpe23Uri),
            extract_cpe_from_cve(cve),
        )
    )


def _extract_versions_from_regex(matches: list[Match]) -> tuple[Version, ...]:
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
                    lambda x: x and not is_date(x),
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

def _is_version_in_between(found_versions: list[Version], version: Version) -> bool:
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


def _is_version_before(found_versions: list[Version], version: Version) -> bool:
    """
    Checks if version is before any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version before
    """
    return any(version < found_version for found_version in found_versions)


def _is_version_after(found_versions: list[Version], version: Version) -> bool:
    """
    Checks if version is after any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version after
    """
    return any(version > found_version for found_version in found_versions)


def _is_version_in_versions(found_versions: list[Version], version: Version) -> bool:
    """
    Checks if version is after any version in `found_versions`

    Args:
        found_versions (list[Version]): Version to check against
        version (Version): Version to verify

    Returns:
        bool: Is version after
    """
    return version in found_versions


def _validate_version_in_summary(cve: dict, query: CVEQuery) -> bool:
    """_summary_

    Args:
        cve (dict): _description_
        query (CVEQuery): Query parameters to use for search

    Returns:
        bool: _description_
    """
    description = cve["cve"]["description"]["description_data"][0].get("value", "")
    if not description:
        return False
    regexes: dict[str, Callable[[list[Version], Version], bool]] = {
        # Between versions
        r"((v?\d\S*?)(\sthrough\s)(v?\d\S*?)(\s|$))|((version|versions)\s(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(between\s(version\s|versions\s)?(v?\d\S*?)\s(and|to|through)\s(v?\d\S*?)(\s|$))|(before\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?after\s(version\s|versions\s)?(v?\d\S*?)(\s|$))|(after\s(version\s|versions\s)?(v?\d\S*?)\s(and\s)?before\s(version\s|versions\s)?(v?\d\S*?)(\s|$))": _is_version_in_between,
        # Before versions
        r"(((versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(versions\s)?)(v?\d\S*?)(,(\s(and\s)?(v?\d\S*))+))|((((version\s|versions\s)?(?!v?\d\S*?)(prior(\sto)?|before|below|through)\s(version\s|versions\s)?)|(<(=)?\s+?))(v?\d\S*?)(\s|$)(?!and\safter))|(version|versions)?(\s(v?\d\S*?)\s(\()?and\s(below|prior|before|earlier)(\))?)": _is_version_before,
        # After versions
        r"(?!and)\s((((after)\s(version\s|versions\s)?)|(>(=)?\s+?))(v?\d\S*?)(\s|$)(?!and))|(\s(v?\d\S?)\s(\()and\s(after|later)(\)))": _is_version_after,
        # Raw versions
        r"(\s(version\s)?(v?\d\S*?)(\s|$)(?!and))": _is_version_in_versions,
    }
    for regex, validate_function in regexes.items():
        versions = _extract_versions_from_regex(
            findall(regex, description, flags=Insensitive | Multiline)
        )

        if query.version is not None and validate_function(versions, query.version):
            return True
    return False


def _validate_product_in_summary(cve: dict, query: CVEQuery) -> bool:
    return bool(query.product) and query.product in cve["cve"]["description"][
        "description_data"
    ][0].get("value", "")


def create_cvematch(cve: dict, query: CVEQuery) -> CVEMatch:
    """
    Checks if CVE is legitimate for version,

    Args:
        cve (dict): CVE to check
        query (CVEQuery): Parameters to use

    Returns:
        bool: is CVE legitimate
    """
    confidence: list[Confidence] = [
        Confidence(
            "Product name contained in summary", _validate_product_in_summary, 0.25
        ),
        Confidence(
            "Product name contained in CPE URI",
            _validate_product_name_in_cpe,
            0.35,
            [Confidence("Version is in CPE Version Range", _validate_cpe_version, 0.4)],
        ),
        Confidence(
            "Vendor name contained in CPE URI", _validate_vendor_name_in_cpe, 0.2
        ),
        Confidence("Version is in Summary", _validate_version_in_summary, 0.3),
    ]
    return CVEMatch(cve, query, confidence)


def search_vulnerabilities(
    cve_collection: Collection,
    query: CVEQuery,
    threshhold: float = 0.6,
) -> Iterator[CVEMatch]:
    """
    Search for vulnerabilities in versions listed and using NVD mirror DB

    Args:
        cve_collection (Collection): local cve collection
        query (CVEQuery): Query to perform with parameters
        threshhold (float, optional): Threshold of confidence. Defaults to 0.6.



    Yields:
        Iterator[CVEMatch]: CVE Matches found
    """
    yield from filter(
        lambda cvematch: cvematch.confidence_score >= threshhold,
        (
            create_cvematch(cve, query)
            for cve in get_cves_by_query(cve_collection, query)
        ),
    )
