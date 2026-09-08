from abc import ABC, abstractmethod
from typing import Any

class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, url: str) -> Any:
        pass