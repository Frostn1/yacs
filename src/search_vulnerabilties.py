from typing import Iterable
from loguru import logger
from orjson import dumps as orjson_dumps
from pymongo.collection import Collection
from packaging.version import Version
from src.mdb_client import MongoDBClient
from src.utils import (
    Confidence,
    extract_cpe_from_cve,
    is_application_name_in_cpe,
    normalize_app_name,
)


def get_cves_by_app_name(cves_collection: Collection, app_name: str) -> Iterable[dict]:
    query = {
        "cve.description.description_data": {
            "$elemMatch": {
                "value": {
                    "$regex": f"(\s|^){normalize_app_name(app_name)}(\s|$)",
                    "$options": "si",
                }
            }
        }
    }
    logger.debug(f"Query - {orjson_dumps(query)}")
    count = cves_collection.count_documents(query)
    logger.debug(f"Query - {count} documents")
    return (doc for doc in cves_collection.find(query))


def _validate_cpe_version(cve: dict, _: str, version: Version) -> bool:
    """
    Validate version is in vulnerable cpe version range

    Args:
        cve (dict): CVE to use for CPE
        version (Version): Version to check against

    Returns:
        bool: Is version in CPE vulnerable version range
    """
    return any(cpe.is_inrange(version) for cpe in extract_cpe_from_cve(cve))


def _validate_app_name_in_cpe(cve: dict, application_name: str, _: Version) -> bool:
    return any(
        map(
            lambda cpe: is_application_name_in_cpe(application_name, cpe.cpe23Uri),
            extract_cpe_from_cve(cve),
        )
    )


def is_legitimate_cve(cve: dict, application_name: str, version: Version) -> bool:
    """
    Checks if CVE is legitimate for version,

    Args:
        cve (dict): CVE to check
        version (Version): Version to check against

    Returns:
        bool: is CVE legitimate
    """
    confidence: list[Confidence] = [
        Confidence(
            "Application name contained in summary",
            lambda _, __, ____: True,
        ),
        Confidence(
            "Application name contained in CPE URI",
            _validate_app_name_in_cpe,
        ),
        Confidence("Version is in CPE Version Range", _validate_cpe_version),
    ]
    return sum(
        confidence.is_confident(cve, application_name, version)
        for confidence in confidence
    ) > 0.5


def search_vulnerabilities(
    cves_collection: Collection, app_name: str, versions: list[str]
) -> list:
    cves = get_cves_by_app_name(cves_collection, app_name)

    return (
        (
            version,
            filter(
                lambda cve: is_legitimate_cve(cve, app_name, Version(version)), cves
            ),
        )
        for version in versions
    )


def main() -> None:
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client["my_nvd_mirror"]["cves"]
        for version, cves in search_vulnerabilities(
            cve_collection, "nginx", ["1.18.0"]
        ):
            for cve in cves:
                logger.info(f"Found CVE - {version} {cve}")


if __name__ == "__main__":
    main()
