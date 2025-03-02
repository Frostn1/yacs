from dataclasses import dataclass
from typing import Callable
from loguru import logger

from src.cvequery import CVEQuery


@dataclass
class Confidence:
    description: str = ""
    _validation_function: Callable[[dict, CVEQuery], bool] = lambda _, __, ___: False
    weight: float = .1

    def confidence_value(self, cve: dict, query: CVEQuery) -> float:
        logger.debug(
            f"Validating {self.description} - {cve['cve']['CVE_data_meta']['ID']}"
        )
        self.is_legitimate = self._validation_function(cve, query)
        return self.is_legitimate * self.weight
