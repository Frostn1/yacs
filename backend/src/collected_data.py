from pydantic.dataclasses import dataclass
from dataclasses import field
import re
from packaging.version import Version
from src.cve_searcher.cpematch import is_version
from src.cve_searcher.cvematch import CVEMatch
from src.cve_searcher.cvequery import CVEQuery

APPLICATION_NAME_CLEANER = re.compile("\s\d+(\.\d+)*")


class Telemetry:
    def __init__(self) -> None:
        self.cves: list[CVEMatch] = []

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
        product = "_".join([*self.OS.split()[:2], self.version]).lower()
        return CVEQuery(vendor, product, Version(self.build), normalize_product=False)


@dataclass
class InstalledApplication(Telemetry):
    name: str
    vendor: str
    version: str

    def __post_init__(self) -> None:
        self.name = APPLICATION_NAME_CLEANER.sub("", self.name)
        self.version = " ".join(filter(is_version, self.version.split()))

    @property
    def query(self) -> CVEQuery:
        return CVEQuery(
            self.vendor,
            self.name,
            Version(self.version) if is_version(self.version) else None,
        )


@dataclass
class SystemStats:
    cpu_usage: str
    memory: dict[str, str]
    disk: dict[str, str]
    running_processes: list[dict[str, str | int]]


@dataclass
class OpenPorts:
    Tcp: list[dict[str, str | int]]
    Udp: list[dict[str, str | int]]


@dataclass
class FireWallState:
    Domain: bool
    Private: bool
    Public: bool


@dataclass
class AntivirusStatus:
    EngineVersion: str
    ProductVersion: str
    RealTimeProtection: str
    Antispyware: str
    AntispywareSignatureLastUpdated: str
    AntispywareSignatureVersion: str
    Antivirus: str
    AntivirusSignatureLastUpdated: str
    AntivirusSignatureVersion: str


@dataclass
class SmbStatus:
    SMB1_installed: bool
    SMB1_status: str
    SMB2_enabled: bool


@dataclass
class RDPSettings:
    rdp_enabled: bool
    rdp_port: int
    status: str


@dataclass
class LocalUser:
    name: str
    enabled: bool


@dataclass
class SharedFolder:
    name: str
    path: str
    description: str


@dataclass
class CollectedData:
    os_version: OsVersion
    system_stats: SystemStats
    open_ports: OpenPorts
    installed_apps: list[InstalledApplication]
    firewall_state: FireWallState
    antivirus_status: AntivirusStatus
    smb_status: SmbStatus
    rdp_settings: RDPSettings
    local_users: list[LocalUser]
    shared_folders: list[SharedFolder]
    vulnerabilities: dict = field(default_factory=dict)
