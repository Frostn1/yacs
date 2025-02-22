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

    @property
    def confidence_score(self) -> float:
        if self.score is None:
            self.score = fmean(
                confidence.is_confident(self.cve, self.query)
                for confidence in self.confidences
            )
        return self.score
