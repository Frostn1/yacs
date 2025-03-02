from dataclasses import dataclass
from statistics import fmean
from typing import Optional

from src.confidence import Confidence
from src.cvequery import CVEQuery


@dataclass
class CVEMatch:
    cve: dict
    query: CVEQuery
    confidences: list[Confidence]
    score: Optional[float] = None
    raw_confidences: Optional[list[float]] = None

    @property
    def confidence_score(self) -> float:
        if self.score is None:
            self.score = min(max(fmean(self.get_raw_confidences), sum(self.get_raw_confidences)), 1)
        return self.score

    @property
    def get_raw_confidences(self) -> list[float]:
        if self.raw_confidences is None:
            self.raw_confidences = [
                confidence.confidence_value(self.cve, self.query)
                for confidence in self.confidences
            ]
            if self.cve['cve']['CVE_data_meta']['ID'] == "CVE-2025-21420":
                breakpoint()
        return self.raw_confidences
