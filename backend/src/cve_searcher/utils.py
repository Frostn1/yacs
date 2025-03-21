from typing import Iterable, Optional
from packaging.version import Version
from cpe_utils import CPE
from re import sub
from src.cve_searcher.cpematch import CPEMatch, is_version

APPNAME_ESCAPES_MAP: dict[str, str] = {
    r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~": r"\{char}",
    " ": r".{{0,3}}",
    "*": r".",
}


def greater_version(*versions: Version) -> str:
    """
    Compare list of version and return the greatest one

    Args:
        *versions (str): List of versions to compare

    Returns:
        str: Greatest version
    """
    return max(versions)


def normalize_product(product: str, vendor: str = '') -> str:
    """
    Normalize app name for search, using APPNAME_ESCAPES_MAP

    Args:
        app_productname (str): Product name to normalize

    Returns:
        str: Normalized app name
    """
    if vendor in product:
        product = product.replace(vendor, '')
        
    removed_versions = " ".join(
        filter(lambda part: not is_version(part), product.strip().split())
    )  # Remove any version

    removed_non_ascii = " ".join(
        filter(lambda part: all(ord(c) < 128 for c in part), removed_versions.split())
    )  # Remove any non english

    removed_parenthesis = sub(r'\([^)]*\)', '', removed_non_ascii).strip() # Remove any string inside parenthesis
    
    removed_after_minus, _, _ = removed_parenthesis.partition(
        "-"
    )  # Remove anything after -, usually extra info

    out: str = ""
    for char in removed_after_minus.strip():
        for key in APPNAME_ESCAPES_MAP:
            if char in key:
                out += APPNAME_ESCAPES_MAP[key].format(char=char)
                break
        else:
            out += char
    
    return out.strip()


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
    yield from filter(lambda cpematch: product.lower() == cpematch.cpe23Uri.product, extract_cpe_from_cve(cve))


def is_application_name_in_cpe(application_name: str, cpe: Optional[CPE]) -> bool:
    return bool(cpe) and application_name.lower() == cpe.product


def is_vendor_name_in_cpe(vendor_name: str, cpe: Optional[CPE]) -> bool:
    return (bool(cpe) and vendor_name.lower() == cpe.vendor) or not bool(vendor_name)
