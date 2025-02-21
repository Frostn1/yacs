from typing import Iterable
import cpe_utils
from loguru import logger
from orjson import dumps as orjson_dumps
from pymongo.collection import Collection
from packaging.version import Version
from src.mdb_client import MongoDBClient
from src.utils import (
    Confidence,
    extract_cpe_uri_from_cve,
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


def _validate_cpe_version(cpe: dict, version: Version) -> bool:
    """
    Validates cpe version

    Args:
        cpe (dict): CPE to validate
        version (Version): Version to check against

    Returns:
        bool: Is cpe vulnerable for said version
    """
    if "vulnerable" not in cpe:
        return False
    uri = cpe_utils.CPE(cpe["cpe23Uri"])
    # if uri.product


def _validate_app_name_in_cpe_uri(
    cve: dict, application_name: str, version: Version
) -> bool:
    cpe = extract_cpe_uri_from_cve(cve)
    return is_application_name_in_cpe(application_name, cpe)


def is_legitimate_cve(cve: dict, application_name: str, version: Version) -> float:
    """
    Checks if CVE is legitimate for version, returns confidence from 0 to 1

    Args:
        cve (dict): CVE to check
        version (Version): Version to check against

    Returns:
        float: Confidence from 0 to 1
    """
    confidence: list[Confidence] = [
        Confidence(
            "Application name contained in summary",
            False,
            lambda _, __, ____: True,
        ),
        Confidence(
            "Application name contained in CPE URI",
            False,
            _validate_app_name_in_cpe_uri,
        ),
    ]
    print(
        [
            confidence.is_confident(cve, application_name, version)
            for confidence in confidence
        ]
    )
    return sum(
        confidence.is_confident(cve, application_name, version)
        for confidence in confidence
    )


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
