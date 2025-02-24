from dataclasses import dataclass

from packaging import Version
from src.cvequery import CVEQuery


class Telemetry:
    
    @property
    def query(self) -> CVEQuery:
        raise NotImplementedError


@dataclass
class OsVersion(Telemetry):
    OS: str
    version: str
    build: str

    @property
    def query(self) -> CVEQuery:
        vendor = "microsoft"
        product = "_".join([*self.os.split()[:2], self.version]).lower()
        return CVEQuery(vendor, product, Version(self.build))


@dataclass
class CollectedData:
    os_version: OsVersion
