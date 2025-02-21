from dataclasses import dataclass
from typing import Callable, Optional
from packaging.version import Version
from cpe_utils import CPE

APPNAME_ESCAPES_MAP: dict[str, str] = {
    "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~": ".?{char}.?",
    " ": ".{0,3}",
    "*": ".",
}


@dataclass
class Confidence:
    description: str
    is_legitimate: bool
    _validation_function: Callable[[dict, str, Version], bool]

    def is_confident(self, cve: dict, app_name: str, version: Version) -> bool:
        self.is_legitimate = self._validation_function(cve, app_name, version)
        return self.is_legitimate


def greater_version(*versions: str) -> str:
    """
    Compare list of version and return the greatest one

    Args:
        *versions (str): List of versions to compare

    Returns:
        str: Greatest version
    """
    return max(versions, key=Version)


def normalize_app_name(app_name: str) -> str:
    """
    Normalize app name for search, using APPNAME_ESCAPES_MAP

    Args:
        app_name (str): App name to normalize

    Returns:
        str: Normalized app name
    """

    out: str = ""

    for char in app_name:
        for key in APPNAME_ESCAPES_MAP:
            if char in key:
                char = APPNAME_ESCAPES_MAP[key].format(char=char)
                break
        out += char

    return out


def extract_cpe_uri_from_cve(cve: dict) -> Optional[CPE]:
    """
    Extracts CPE URI from CVE

    Args:
        cve (dict): CVE to extract CPE URI from

    Returns:
        Optional[CPE]: CPE URI
    """
    for node in cve["configurations"]["nodes"]:
        for cpe_match in node.get("cpe_match", []):
            return CPE(cpe_match["cpe23Uri"])
    return None


def is_application_name_in_cpe(application_name: str, cpe: Optional[CPE]) -> bool:
    return bool(cpe) and application_name in cpe.product
