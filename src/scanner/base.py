from abc import ABC, abstractmethod
from typing import Any
from httpx import Response

class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, url: str) -> Any:
        pass

class BaseResponseScanner(ABC):
    @abstractmethod
    async def scan(self, response: Response) -> Any:
        pass