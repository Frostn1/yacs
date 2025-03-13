from typing import Iterable, Optional
from packaging.version import Version
from cpe_utils import CPE

from src.cpematch import CPEMatch

APPNAME_ESCAPES_MAP: dict[str, str] = {
    r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~": ".?{char}.?",
    " ": ".{0,3}",
    "*": ".",
}


CPE_WILDCARD = "*"
CPE_VERSION_FILLER = "-"


def greater_version(*versions: Version) -> str:
    """
    Compare list of version and return the greatest one

    Args:
        *versions (str): List of versions to compare

    Returns:
        str: Greatest version
    """
    return max(versions)


def normalize_product(product: str) -> str:
    """
    Normalize app name for search, using APPNAME_ESCAPES_MAP

    Args:
        app_productname (str): Product name to normalize

    Returns:
        str: Normalized app name
    """

    out: str = ""

    for char in product:
        for key in APPNAME_ESCAPES_MAP:
            if char in key:
                char = APPNAME_ESCAPES_MAP[key].format(char=char)
                break
        out += char

    return out


def extract_cpe_from_cve(cve: dict) -> Iterable[CPEMatch]:
    """
    Extracts CPE URI from CVE

    Args:
        cve (dict): CVE to extract CPE URI from

    Yields:
        CPE: CPE URI
    """
    for node in cve["configurations"]["nodes"]:
        for cpe_match in node.get("cpe_match", []):
            yield CPEMatch(**cpe_match)
    return None


def extract_cpe_from_cve_per_product(cve: dict, product: str) -> Iterable[CPEMatch]:
    """
    Extracts CPE URI from CVE by product name

    Args:
        cve (dict): CVE to extract CPE URI from
        product (str): Product name to filter

    Yields:
        CPE: CPE URI
    """
    yield from filter(
        lambda cpematch: product in cpematch.cpe23Uri.product, extract_cpe_from_cve(cve)
    )


def is_application_name_in_cpe(application_name: str, cpe: Optional[CPE]) -> bool:
    return bool(cpe) and application_name == cpe.product


def is_vendor_name_in_cpe(vendor_name: str, cpe: Optional[CPE]) -> bool:
    return (bool(cpe) and vendor_name == cpe.vendor) or not bool(vendor_name)
