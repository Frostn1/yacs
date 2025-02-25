from pydantic.dataclasses import dataclass
from packaging.version import Version

from src.utils import normalize_product


@dataclass(config={"arbitrary_types_allowed": True})
class CVEQuery:
    vendor: str = ""
    _product: str = ""
    version: Version = Version("0")
    normalize_product: bool = True

    @property
    def product(self) -> str:
        return normalize_product(self._product) if self.normalize_product else self._product
