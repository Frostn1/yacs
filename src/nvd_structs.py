from dataclasses import dataclass
from datetime import datetime

LAST_MODIFIED_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


class MetaFile:
    def __init__(
        self,
        lastModifiedDate: str,
        size: int,
        zipSize: int,
        gzSize: int,
        sha256: str,
        **_,
    ):
        self.lastModifiedDate = datetime.strptime(
            lastModifiedDate, LAST_MODIFIED_DATE_FORMAT
        )
        self.size = size
        self.zipSize = zipSize
        self.gzSize = gzSize
        self.sha256 = sha256

    def __repr__(self):
        return f"MetaFile(lastModifiedDate={self.lastModifiedDate}, size={self.size}, zipSize={self.zipSize}, gzSize={self.gzSize}, sha256={self.sha256})"