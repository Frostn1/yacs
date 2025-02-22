from packaging.version import Version, InvalidVersion
from cpe_utils import CPE


MIN_VERSION_RAW = "0"
MAX_VERSION_RAW = "1000000000"

MIN_VERSION = Version(MIN_VERSION_RAW)
MAX_VERSION = Version(MAX_VERSION_RAW)


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
