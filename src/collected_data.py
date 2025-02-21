from dataclasses import dataclass

import pymongo


class Telemetry:
    def find_vulns(client: pymongo.MongoClient) -> list[dict]:
        raise NotImplementedError


@dataclass
class OsVersion(Telemetry):
    OS: str
    version: str
    build: str

    def find_vulns(self, client: pymongo.MongoClient) -> list[dict]:
        vendor = "microsoft"
        product = "_".join(self.version.split()[:2]).lower()
        vendor_query = {"cve.CVE_data_meta.ASSIGNER": {"$regex": vendor}}


@dataclass
class CollectedData:
    os_version: OsVersion
