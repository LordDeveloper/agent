from abc import ABC, abstractmethod
from typing import Any

from agent.models import UsageSnapshotModel


class CoreDriver(ABC):
    key: str
    label: str

    @abstractmethod
    def capabilities(self) -> list[str]:
        ...

    @abstractmethod
    def installed(self) -> bool:
        ...

    @abstractmethod
    def running(self) -> bool:
        ...

    @abstractmethod
    def version(self) -> str | None:
        ...

    def install(self) -> dict[str, Any]:
        raise NotImplementedError

    def enable(self) -> dict[str, Any]:
        return {"enabled": True}

    def disable(self) -> dict[str, Any]:
        return {"enabled": False}

    def restart(self) -> dict[str, Any]:
        return {"restarted": True}

    @abstractmethod
    def usage_snapshot(self) -> UsageSnapshotModel:
        ...

    @abstractmethod
    def online_users(self) -> list[str]:
        ...
