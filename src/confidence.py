from __future__ import annotations
from dataclasses import dataclass, field
from itertools import chain
from typing import Callable
from loguru import logger

from src.cvequery import CVEQuery


@dataclass
class Confidence:
    description: str = ""
    _validation_function: Callable[[dict, CVEQuery], bool] = lambda _, __, ___: False
    weight: float = 0.1
    sub_confidences: list[Confidence] = field(default_factory=list)

    def confidence_value(self, cve: dict, query: CVEQuery) -> float:
        logger.debug(
            f"Validating {self.description} - {cve['cve']['CVE_data_meta']['ID']}"
        )
        self.is_legitimate = self._validation_function(cve, query)
        return self.is_legitimate * sum(
            chain(
                [self.weight], (sub.confidence_value(cve, query) for sub in self.sub_confidences)
            )
        )
