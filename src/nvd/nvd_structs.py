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


@dataclass
class CVE:
    def __post_init__(raw: dict) -> None:
        print(f"{raw = }")

    def getvars(self) -> dict:
        try:
            self.cpe = self.configurations[0].nodes[0].cpeMatch
        except AttributeError:
            pass

        try:
            self.cwe = [x for w in self.weaknesses for x in w.description]
        except AttributeError:
            pass

        try:
            self.url = "https://nvd.nist.gov/vuln/detail/" + self.id
        except:
            pass

        if hasattr(self.metrics, "cvssMetricV40"):
            self.v40score = self.metrics.cvssMetricV40[0].cvssData.baseScore
            self.v40vector = self.metrics.cvssMetricV40[0].cvssData.vectorString
            self.v40severity = self.metrics.cvssMetricV40[0].cvssData.baseSeverity

        if hasattr(self.metrics, "cvssMetricV31"):
            self.v31score = self.metrics.cvssMetricV31[0].cvssData.baseScore
            self.v31vector = self.metrics.cvssMetricV31[0].cvssData.vectorString
            self.v31severity = self.metrics.cvssMetricV31[0].cvssData.baseSeverity
            self.v31attackVector = self.metrics.cvssMetricV31[0].cvssData.attackVector
            self.v31attackComplexity = self.metrics.cvssMetricV31[
                0
            ].cvssData.attackComplexity
            self.v31privilegesRequired = self.metrics.cvssMetricV31[
                0
            ].cvssData.privilegesRequired
            self.v31userInteraction = self.metrics.cvssMetricV31[
                0
            ].cvssData.userInteraction
            self.v31scope = self.metrics.cvssMetricV31[0].cvssData.scope
            self.v31confidentialityImpact = self.metrics.cvssMetricV31[
                0
            ].cvssData.confidentialityImpact
            self.v31integrityImpact = self.metrics.cvssMetricV31[
                0
            ].cvssData.integrityImpact
            self.v31availabilityImpact = self.metrics.cvssMetricV31[
                0
            ].cvssData.availabilityImpact

            self.v31exploitability = self.metrics.cvssMetricV31[0].exploitabilityScore
            self.v31impactScore = self.metrics.cvssMetricV31[0].impactScore

        if hasattr(self.metrics, "cvssMetricV30"):
            self.v30score = self.metrics.cvssMetricV30[0].cvssData.baseScore
            self.v30vector = self.metrics.cvssMetricV30[0].cvssData.vectorString
            self.v30severity = self.metrics.cvssMetricV30[0].cvssData.baseSeverity
            self.v30attackVector = self.metrics.cvssMetricV30[0].cvssData.attackVector
            self.v30attackComplexity = self.metrics.cvssMetricV30[
                0
            ].cvssData.attackComplexity
            self.v30privilegesRequired = self.metrics.cvssMetricV30[
                0
            ].cvssData.privilegesRequired
            self.v30userInteraction = self.metrics.cvssMetricV30[
                0
            ].cvssData.userInteraction
            self.v30scope = self.metrics.cvssMetricV30[0].cvssData.scope
            self.v30confidentialityImpact = self.metrics.cvssMetricV30[
                0
            ].cvssData.confidentialityImpact
            self.v30integrityImpact = self.metrics.cvssMetricV30[
                0
            ].cvssData.integrityImpact
            self.v30availabilityImpact = self.metrics.cvssMetricV30[
                0
            ].cvssData.availabilityImpact

            self.v30exploitability = self.metrics.cvssMetricV30[0].exploitabilityScore
            self.v30impactScore = self.metrics.cvssMetricV30[0].impactScore

        if hasattr(self.metrics, "cvssMetricV2"):
            self.v2score = self.metrics.cvssMetricV2[0].cvssData.baseScore
            self.v2vector = self.metrics.cvssMetricV2[0].cvssData.vectorString
            self.v2severity = self.metrics.cvssMetricV2[0].baseSeverity
            self.v2accessVector = self.metrics.cvssMetricV2[0].cvssData.accessVector
            self.v2accessComplexity = self.metrics.cvssMetricV2[
                0
            ].cvssData.accessComplexity
            self.v2authentication = self.metrics.cvssMetricV2[0].cvssData.authentication
            self.v2confidentialityImpact = self.metrics.cvssMetricV2[
                0
            ].cvssData.confidentialityImpact
            self.v2integrityImpact = self.metrics.cvssMetricV2[
                0
            ].cvssData.integrityImpact
            self.v2availabilityImpact = self.metrics.cvssMetricV2[
                0
            ].cvssData.availabilityImpact
            self.v2exploitability = self.metrics.cvssMetricV2[0].exploitabilityScore
            self.v2impactScore = self.metrics.cvssMetricV2[0].impactScore

        # Prefer the base score version to V3, if it isn't available use V2.
        # If no score is present, then set it to None.
        if hasattr(self.metrics, "cvssMetricV40"):
            self.score = ["V40", self.v40score, self.v40severity]
        elif hasattr(self.metrics, "cvssMetricV31"):
            self.score = ["V31", self.v31score, self.v31severity]
        elif hasattr(self.metrics, "cvssMetricV30"):
            self.score = ["V30", self.v30score, self.v30severity]
        elif hasattr(self.metrics, "cvssMetricV2"):
            self.score = ["V2", self.v2score, self.v2severity]
        else:
            self.score = [None, None, None]
