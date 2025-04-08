from typing import Optional
from pydantic.dataclasses import dataclass
from packaging.version import Version

from src.cve_searcher.utils import normalize_product


@dataclass(config={"arbitrary_types_allowed": True})
class CVEQuery:
    vendor: str = ""
    _product: str = ""
    version: Optional[Version] = None
    normalize_product: bool = True
    
    @property
    def product(self) -> str:
        return (
            normalize_product(self._product, self.vendor)
            if self.normalize_product
            else self._product
        )
