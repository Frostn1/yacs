from dataclasses import dataclass
from statistics import fmean
from typing import Callable, Iterable, Optional
from packaging.version import Version, InvalidVersion
from cpe_utils import CPE
from loguru import logger

APPNAME_ESCAPES_MAP: dict[str, str] = {
    "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~": ".?{char}.?",
    " ": ".{0,3}",
    "*": ".",
}

MIN_VERSION_RAW = "0"
MAX_VERSION_RAW = "1000000000"

MIN_VERSION = Version(MIN_VERSION_RAW)
MAX_VERSION = Version(MAX_VERSION_RAW)
CPE_WILDCARD = "*"
CPE_VERSION_FILLER = "-"


@dataclass
class Confidence:
    description: str = ""
    _validation_function: Callable[[dict, str, Version], bool] = (
        lambda _, __, ___: False
    )
    is_legitimate: bool = False

    def is_confident(self, cve: dict, app_name: str, version: Version) -> bool:
        logger.debug(
            f"Validating {self.description} - {cve['cve']['CVE_data_meta']['ID']}"
        )
        self.is_legitimate = self._validation_function(cve, app_name, version)
        return self.is_legitimate


def is_version(value: str) -> bool:
    try:
        Version(value)
        return True
    except InvalidVersion:
        return False


class CPEMatch:
    def __init__(
        self,
        vulnerable: bool = False,
        cpe23Uri: str = "",
        versionStartIncluding: str = MIN_VERSION_RAW,
        versionStartExcluding: str = MIN_VERSION_RAW,
        versionEndIncluding: str = MAX_VERSION_RAW,
        versionEndExcluding: str = MAX_VERSION_RAW,
        cpe_name: list = None,
    ) -> None:
        self.vulnerable: bool = vulnerable
        self.cpe23Uri: CPE = CPE(cpe23Uri)
        self.versionStartIncluding: Version = (
            Version(versionStartIncluding)
            if is_version(self.cpe23Uri.version)
            else MIN_VERSION
        )
        self.versionStartExcluding: Version = (
            Version(versionStartExcluding)
            if is_version(self.cpe23Uri.version)
            else MIN_VERSION
        )
        self.versionEndIncluding: Version = (
            Version(versionEndIncluding)
            if is_version(self.cpe23Uri.version)
            else MAX_VERSION
        )
        self.versionEndExcluding: Version = (
            Version(versionEndExcluding)
            if is_version(self.cpe23Uri.version)
            else MAX_VERSION
        )
        self.cpe_name: list = cpe_name if cpe_name else []

        self.min_version = (
            Version(self.cpe23Uri.version)
            if is_version(self.cpe23Uri.version)
            else MIN_VERSION
        )
        self.max_version = (
            Version(self.cpe23Uri.version)
            if is_version(self.cpe23Uri.version)
            else MAX_VERSION
        )

        self.min_version = max(
            self.min_version, self.versionStartIncluding, self.versionStartExcluding
        )
        self.max_version = min(
            self.max_version, self.versionEndExcluding, self.versionEndIncluding
        )

    # TODO Fix to support including and excluding range
    def is_inrange(self, version: Version) -> bool:
       return (
            self.min_version != MIN_VERSION
            and self.max_version != MAX_VERSION
            and self.min_version <= version <= self.max_version
        )


@dataclass
class CVEMatch:
    cve: dict
    version: Version
    application_name: str
    confidences: list[Confidence]
    score: Optional[float] = None

    @property
    def confidence_score(self) -> float:
        if self.score is None:
            self.score = fmean(
                confidence.is_confident(self.cve, self.application_name, self.version)
                for confidence in self.confidences
            )
        return self.score


def greater_version(*versions: Version) -> str:
    """
    Compare list of version and return the greatest one

    Args:
        *versions (str): List of versions to compare

    Returns:
        str: Greatest version
    """
    return max(versions)


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


def is_application_name_in_cpe(application_name: str, cpe: Optional[CPE]) -> bool:
    return bool(cpe) and application_name == cpe.product
