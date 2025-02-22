from pydantic.dataclasses import dataclass
from packaging.version import Version



@dataclass(config={'arbitrary_types_allowed':True})
class CVEQuery:
    vendor: str
    product: str
    version: Version
    
