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
    raw_confidences: Optional[list[bool]] = None

    @property
    async def confidence_score(self) -> float:
        if self.score is None:
            c = await self.get_raw_confidences
            print(f"{c = }")
            print(f"{[await i for i in c ] = }")
            self.score = fmean(await self.get_raw_confidences)
        return self.score

    @property
    async def get_raw_confidences(self) -> list[bool]:
        if self.raw_confidences is None:
            self.raw_confidences = [
                await confidence.is_confident(self.cve, self.query)
                for confidence in self.confidences
            ]
        return self.raw_confidences
