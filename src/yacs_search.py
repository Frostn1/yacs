from dataclasses import dataclass
from typing import Iterable

from cve_searcher.cvematch import CVEMatch

from src.cve_searcher.cvequery import CVEQuery


@dataclass
class YACSSearch:
    query: CVEQuery
    matches: Iterable[CVEMatch]