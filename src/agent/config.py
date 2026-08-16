from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class XraySettings(BaseModel):
    """Runtime connection to customized Xray-core HTTP API."""

    api_base: str = "http://127.0.0.1:8080"
    username: str = ""
    password: str = ""
    binary: str = "/usr/local/bin/xray"
    timeout: float = 15.0
    connect_timeout: float = 3.0


class WireGuardSettings(BaseModel):
    config_dir: str = "/etc/wireguard"


class AmneziaSettings(BaseModel):
    config_dir: str = "/etc/amneziawg"


class AgentSettings(BaseSettings):
    """
    Flat .env keys (no nested prefixes):

      LISTEN=0.0.0.0:8443
      AUTH_TOKEN=...
      ENABLED_CORES=xray,wireguard
      XRAY_API_BASE=http://127.0.0.1:8080
      XRAY_BINARY=/usr/local/bin/xray
    """

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    listen: str = "127.0.0.1:8443"
    auth_token: str = ""
    auth_username: str = ""
    auth_password: str = ""
    data_dir: str = "/var/lib/agent"
    db_path: str = ""
    enabled_cores: str = "xray"

    xray_api_base: str = "http://127.0.0.1:8080"
    xray_username: str = ""
    xray_password: str = ""
    xray_binary: str = "/usr/local/bin/xray"

    wireguard_config_dir: str = "/etc/wireguard"
    amnezia_config_dir: str = "/etc/amneziawg"

    @property
    def xray(self) -> XraySettings:
        return XraySettings(
            api_base=self.xray_api_base,
            username=self.xray_username,
            password=self.xray_password,
            binary=self.xray_binary,
        )

    @property
    def wireguard(self) -> WireGuardSettings:
        return WireGuardSettings(config_dir=self.wireguard_config_dir)

    @property
    def amnezia(self) -> AmneziaSettings:
        return AmneziaSettings(config_dir=self.amnezia_config_dir)

    def cores(self) -> list[str]:
        return [part.strip() for part in self.enabled_cores.split(",") if part.strip()]

    def resolve_db_path(self) -> Path:
        if self.db_path:
            return Path(self.db_path)
        return Path(self.data_dir) / "agent.db"

    def listen_host_port(self) -> tuple[str, int]:
        if ":" in self.listen:
            host, port = self.listen.rsplit(":", 1)
            return host, int(port)
        return self.listen, 8443


def default_env_paths() -> list[Path]:
    paths: list[Path] = []
    explicit = os.environ.get("ENV_FILE")
    if explicit:
        paths.append(Path(explicit))
    paths.extend(
        [
            Path("/etc/agent/.env"),
            Path.cwd() / ".env",
        ]
    )
    return paths


def load_settings(env_file: str | Path | None = None) -> AgentSettings:
    """Load flat env vars from process env and optional .env file (`ENV_FILE`)."""
    file_path: Path | None = None
    if env_file is not None:
        candidate = Path(env_file)
        if candidate.is_file():
            file_path = candidate
    else:
        for candidate in default_env_paths():
            if candidate.is_file():
                file_path = candidate
                break

    if file_path is None:
        return AgentSettings()
    return AgentSettings(_env_file=file_path)
