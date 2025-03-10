from dataclasses import dataclass
import re
import sys
import time
from typing import Iterable
from loguru import logger
from packaging.version import Version
from src import catchtime
from src.cvematch import CVEMatch
from src.cvequery import CVEQuery
from src.mdb_client import MongoDBClient
from src.search_vulnerabilties import get_cves_by_query, search_vulnerabilities

APPLICATION_NAME_CLEANER = re.compile("\s\d+(\.\d+)*")


class Telemetry:
    def __init__(self) -> None:
        self.cves: list[CVEMatch] = []

    @property
    def query(self) -> CVEQuery:
        raise NotImplementedError


@dataclass
class OsVersion(Telemetry):
    os: str
    version: str
    build: str

    @property
    def query(self) -> CVEQuery:
        vendor = "microsoft"
        product = "_".join([*self.os.split()[:2], self.version]).lower()
        return CVEQuery(vendor, product, Version(self.build), normalize_product=False)


@dataclass
class InstalledApplication(Telemetry):
    name: str
    version: str

    def __post_init__(self) -> None:
        self.name = APPLICATION_NAME_CLEANER.sub("", self.name)

    @property
    def query(self) -> CVEQuery:
        return CVEQuery("", self.name, Version(self.version))


@dataclass
class CollectedData:
    os_version: OsVersion
    installed_apps: list[InstalledApplication]

    @property
    def telemetries(self) -> list[Telemetry]:
        return [self.os_version, self.installed_apps]


def print_cves(name: str, cves: Iterable[CVEMatch]) -> None:
    count: int = 0
    for count, cvematch in enumerate(cves):
        logger.info(
            f"Found CVE [Confidence {cvematch.get_raw_confidences}] - {cvematch.cve['cve']['CVE_data_meta']['ID']}"
        )
    print(f"{name} : Found {count} cves")


def main() -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    with MongoDBClient() as mdb_client:
        cve_collection = mdb_client["nvd_mirror"]["cves"]
        # cve_collection.create_index({ "cve.description.description_data.value_text": "text" })
        # cve_collection.create_index({ "configurations.nodes.cpe_match.cpe23Uri": 1 })
        # cve_collection.create_index([("cve.CVE_data_meta.ID", 1)])

        cd = CollectedData(
            # OsVersion("Windows 11 Pro", "23H2", "10.0.22631.4751"),
            OsVersion("Windows 11 Pro", "24H2", "10.0.26100.3194"),
            [InstalledApplication("CrystalDiskMark 8.0.6", "8.0.6")],
        )
        query = CVEQuery("f5", "nginx", Version("1.18.0"))
        query = OsVersion("Windows 11 Pro", "24H2", "10.0.26100.3194").query
        query = CVEQuery("", "git", Version("1.23"))
        start = time.time()
        cves = list(get_cves_by_query(cve_collection, query))
        print(type(cves), len(cves))
        end = time.time()
        print(f'Time: {end - start} seconds')

        return

        _, cd.os_version.cves = search_vulnerabilities(
            cve_collection, cd.os_version.query
        )
        # for app in cd.installed_apps:
        #     _, app.cves = search_vulnerabilities(cve_collection, app.query)
        print_cves("OS Version", cd.os_version.cves)


if __name__ == "__main__":
    main()
