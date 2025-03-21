from dataclasses import dataclass
from datetime import datetime

LAST_MODIFIED_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


@dataclass
class MetaFile:
    lastModifiedDate: datetime
    size: int
    zipSize: int
    gzSize: int
    sha256: str

    def __post_init__(self):
        self.lastModifiedDate = datetime.strptime(
            self.lastModifiedDate, LAST_MODIFIED_DATE_FORMAT
        )

