from dataclasses import dataclass
from typing import Awaitable, Callable, Optional
from loguru import logger

from src.cvequery import CVEQuery


@dataclass
class Confidence:
    description: str = ""
    _validation_function: Callable[[dict, CVEQuery], Awaitable[bool]] = (
        lambda _, __, ___: False
    )
    is_legitimate: Optional[bool] = None

    async def is_confident(self, cve: dict, query: CVEQuery) -> bool:
        logger.debug(
            f"Validating {self.description} - {cve['cve']['CVE_data_meta']['ID']}"
        )
        if self.is_legitimate is None:
            self.is_legitimate = await self._validation_function(cve, query)
        return self.is_legitimate
