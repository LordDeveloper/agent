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
    config: str = "/usr/local/etc/xray/config.json"
    # Per-step timeout (format / batch / rules replace). Keep under proxy 60s budgets.
    timeout: float = 45.0
    connect_timeout: float = 3.0


class WireGuardSettings(BaseModel):
    config_dir: str = "/etc/wireguard"


class AmneziaSettings(BaseModel):
    config_dir: str = "/etc/amneziawg"


class L2tpSettings(BaseModel):
    config_dir: str = "/etc/agent/bin/l2tp"


class OpenVpnSettings(BaseModel):
    config_dir: str = "/etc/agent/bin/openvpn"


class AgentSettings(BaseSettings):
    """
    Flat .env keys (no nested prefixes):

      LISTEN=0.0.0.0:8443
      AUTH_TOKEN=...
      ENABLED_CORES=xray,wireguard
      LOG_FILE=/var/lib/agent/agent.log
      LOG_LEVEL=INFO
      XRAY_API_BASE=http://127.0.0.1:8080
      XRAY_BINARY=/usr/local/bin/xray
      XRAY_CONFIG=/usr/local/etc/xray/config.json
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
    # Laravel-style database env (defaults keep the historical sqlite file in data_dir).
    db_connection: str = "sqlite"
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_database: str = "agent.db"
    db_username: str = ""
    db_password: str = ""
    # Legacy absolute sqlite path; when set, overrides db_database for sqlite only.
    db_path: str = ""
    enabled_cores: str = "xray"
    log_file: str = ""
    log_level: str = "INFO"
    log_max_bytes: int = 5_000_000
    log_backup_count: int = 5

    xray_api_base: str = "http://127.0.0.1:8080"
    xray_username: str = ""
    xray_password: str = ""
    xray_binary: str = "/usr/local/bin/xray"
    xray_config: str = "/usr/local/etc/xray/config.json"
    xray_timeout: float = 45.0
    xray_connect_timeout: float = 3.0

    wireguard_config_dir: str = "/etc/wireguard"
    amnezia_config_dir: str = "/etc/amneziawg"
    l2tp_config_dir: str = "/etc/agent/bin/l2tp"
    openvpn_config_dir: str = "/etc/agent/bin/openvpn"
    # Seconds between local volume-quota checks (0 disables the enforcer loop entirely).
    # The loop still removes clients the panel already marked disabled. It does not
    # decide volume cutoff unless ENFORCE_LOCAL_VOLUME_QUOTA=true.
    quota_enforce_interval: float = 10.0
    # Volume cutoff belongs to Laravel UpdateSubscribeStats. Positive `volume` is still
    # stored for sync and diagnose. Set true only to restore the old local cut.
    enforce_local_volume_quota: bool = False
    # Seconds between volume samples for panel billing (0 disables the background worker).
    # The worker attempts a sample on this cadence and never runs two at once.
    traffic_sample_interval: float = 15.0
    # A sample still running after this many seconds is cancelled so the next
    # cycle can start. Same idea as withoutOverlapping: one sample at a time,
    # and a stuck sample cannot block volume calculation longer than this.
    traffic_sample_lock_seconds: float = 120.0
    # Max seconds for panel GET/HEAD on stats and /cores/*/diagnose before core I/O is capped.
    # Keep below typical Laravel Guzzle timeouts so the agent fails fast with 503 instead of idle sockets.
    read_budget_seconds: float = 12.0
    # HTTP budget for health, stats, and Mullvad locations. The handler is cancelled and
    # the last JSON body is returned with stale=true so the panel never waits on 0 bytes.
    read_response_seconds: float = 3.0
    # HTTP budget for writes and every other route. A timeout still writes a JSON body.
    write_response_seconds: float = 180.0
    # Log SQLite operations slower than this (ms); 0 disables.
    slow_query_log_ms: float = 500.0
    # Log one line with X-RUNTIME breakdown when total duration exceeds this (ms); 0 disables.
    slow_request_log_ms: float = 500.0
    # Sidecar TCP forwarder injecting PROXY protocol v1 for Xray acceptProxyProtocol inbounds.
    proxy_protocol_forwarder_enabled: bool = True
    proxy_protocol_forwarder_binary: str = ""
    # Seconds between Mullvad exit fallback checks (0 disables).
    mullvad_fallback_interval: float = 90.0
    # How many interface start/stop/restart operations may run at once.
    interface_lifecycle_concurrency: int = 4
    # Per-interface budget for one start, stop, or restart. A timeout is local
    # to that interface and does not cancel the others.
    interface_lifecycle_timeout: float = 180.0

    @property
    def xray(self) -> XraySettings:
        return XraySettings(
            api_base=self.xray_api_base,
            username=self.xray_username,
            password=self.xray_password,
            binary=self.xray_binary,
            config=self.xray_config,
            timeout=float(self.xray_timeout),
            connect_timeout=float(self.xray_connect_timeout),
        )

    @property
    def wireguard(self) -> WireGuardSettings:
        return WireGuardSettings(config_dir=self.wireguard_config_dir)

    @property
    def amnezia(self) -> AmneziaSettings:
        return AmneziaSettings(config_dir=self.amnezia_config_dir)

    @property
    def l2tp(self) -> L2tpSettings:
        return L2tpSettings(config_dir=self.l2tp_config_dir)

    @property
    def openvpn(self) -> OpenVpnSettings:
        return OpenVpnSettings(config_dir=self.openvpn_config_dir)

    def cores(self) -> list[str]:
        return [part.strip() for part in self.enabled_cores.split(",") if part.strip()]

    def resolve_db_path(self) -> Path:
        """Sqlite database file path (ignored when DB_CONNECTION is not sqlite)."""
        if self.db_path:
            return Path(self.db_path)
        name = (self.db_database or "agent.db").strip()
        path = Path(name)
        if path.is_absolute():
            return path
        return Path(self.data_dir) / name

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
