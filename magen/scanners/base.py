"""Base scanner interface."""

from abc import ABC, abstractmethod
from magen.models import MCPToolDefinition, ScanResult


class BaseScanner(ABC):
    """All scanners implement this interface."""

    @property
    @abstractmethod
    def layer_name(self) -> str:
        ...

    @abstractmethod
    def scan(self, tool: MCPToolDefinition) -> ScanResult:
        ...
