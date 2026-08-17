from typing import Any, Optional

from pydantic import BaseModel, Field


class ClientUsageModel(BaseModel):
    id: str
    email: Optional[str] = None
    incoming: int = 0
    outgoing: int = 0
    inbound_id: Optional[int | str] = Field(None, alias="inboundId")

    model_config = {"populate_by_name": True}


class InboundUsageModel(BaseModel):
    id: int | str
    tag: str
    incoming: int = 0
    outgoing: int = 0
    clients: list[ClientUsageModel] = Field(default_factory=list)


class UsageSnapshotModel(BaseModel):
    inbounds: list[InboundUsageModel] = Field(default_factory=list)


class CoreInfo(BaseModel):
    key: str
    label: str
    installed: bool = False
    running: bool = False
    version: Optional[str] = None
    capabilities: list[str] = Field(default_factory=list)


class InboundPayload(BaseModel):
    id: Optional[int | str] = None
    tag: Optional[str] = None
    listen: str = "0.0.0.0"
    port: int = 0
    protocol: str = "vless"
    settings: dict[str, Any] = Field(default_factory=dict)
    streamSettings: dict[str, Any] = Field(default_factory=dict)
    sniffing: dict[str, Any] = Field(default_factory=dict)
    # Deprecated: formats live on the API client; ignored if sent.
    format: Optional[str] = None


class ClientPayload(BaseModel):
    model_config = {"extra": "allow"}

    id: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    flow: Optional[str] = None
    alterId: Optional[int] = None
    enable: Optional[bool] = True
    is_enabled: Optional[bool] = None
    expiryTime: Optional[int] = None
    expires_at: Optional[Any] = None
    totalGB: Optional[float] = None
    volume: Optional[float] = None
    up: Optional[int] = None
    down: Optional[int] = None
    outgoing: Optional[int] = None
    incoming: Optional[int] = None
    limitIp: Optional[int] = None
    max_connection: Optional[int] = None
    subId: Optional[str] = None
    tgId: Optional[str] = None
    public_key: Optional[str] = None
    allowed_ips: Optional[str] = None
    obfuscation: Optional[dict[str, Any]] = None


class WgInterfacePayload(BaseModel):
    model_config = {"extra": "allow"}

    id: Optional[int | str] = None
    name: Optional[str] = None
    listen_port: int = 51820
    subnet: str = "10.8.0.0/24"
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    obfuscation: Optional[dict[str, Any]] = None


class WgPeerPayload(BaseModel):
    model_config = {"extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    public_key: Optional[str] = None
    allowed_ips: Optional[str] = None
    persistent_keepalive: int = 25
    is_enabled: Optional[bool] = None
    enable: Optional[bool] = True
    volume: Optional[float] = None
    max_connection: Optional[int] = None
    incoming: Optional[int] = None
    outgoing: Optional[int] = None
    _incoming: Optional[int] = None
    _outgoing: Optional[int] = None


class AmneziaObfuscation(BaseModel):
    Jc: Optional[int] = None
    Jmin: Optional[int] = None
    Jmax: Optional[int] = None
    S1: Optional[int] = None
    S2: Optional[int] = None
    H1: Optional[int] = None
    H2: Optional[int] = None
    H3: Optional[int] = None
    H4: Optional[int] = None


class AmneziaInterfacePayload(WgInterfacePayload):
    obfuscation: AmneziaObfuscation = Field(default_factory=AmneziaObfuscation)


class AmneziaPeerPayload(WgPeerPayload):
    obfuscation: Optional[AmneziaObfuscation] = None
