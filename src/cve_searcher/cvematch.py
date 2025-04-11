from dataclasses import dataclass
from statistics import fmean
from typing import Optional

from src.cve_searcher.confidence import Confidence
from src.cve_searcher.cvequery import CVEQuery


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
            self.score = min(
                max(fmean(self.get_raw_confidences), sum(self.get_raw_confidences)), 1
            )
        return self.score

    @property
    def get_raw_confidences(self) -> list[float]:
        if self.raw_confidences is None:
            self.raw_confidences = [
                confidence.confidence_value(self.cve, self.query)
                for confidence in self.confidences
            ]
        return self.raw_confidences

    def pretty_print(self) -> None:
        """Pretty print the CVE match."""
        print(
            f"[Description] {self.cve['cve']['description']['description_data'][0]['value']}"
        )
        impact = self.cve.get("impact", {})
        basemetric = impact.get("baseMetricV3", {}) or impact.get("baseMetricV2", {})
        cvss = basemetric.get("cvssV3", {}) or basemetric.get("cvssV2", {})
        if cvss.get("baseScore"):
            print(f"[CVSS] {cvss.get('baseScore')}")
        else:
            print("[CVSS] Not available")

        if basemetric.get("severity"):
            print(f"[CVSS Severity] {basemetric.get('severity')}")
        else:
            print("[CVSS Severity] Not available")

        print(f"[Published Date] {self.cve['publishedDate']}")
        print(f"[Last Modified Date] {self.cve['lastModifiedDate']}")
