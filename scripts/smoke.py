"""Smoke test against local temp .env with fake Xray HTTP API."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from agent.main import create_app
from tests.fake_xray import FakeXrayHttpClient
import agent.drivers.xray as xray_mod

xray_mod.XrayHttpClient = lambda settings, transport=None: FakeXrayHttpClient()  # type: ignore


def _sample_inbound(inbound_id: int = 1, port: int = 443) -> dict:
    return {
        "id": inbound_id,
        "port": port,
        "protocol": "vless",
        "streamSettings": {"network": "tcp", "security": "none"},
        "settings": {"decryption": "none", "clients": []},
    }


with tempfile.TemporaryDirectory() as tmp:
    data_dir = Path(tmp) / "data"
    env = Path(tmp) / ".env"
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data_dir.as_posix()}",
                "ENABLED_CORES=xray,wireguard,amnezia",
                "XRAY_API_BASE=http://127.0.0.1:8080",
                "XRAY_BINARY=/usr/local/bin/xray",
                "",
            ]
        ),
        encoding="utf-8",
    )
    os.environ["ENV_FILE"] = str(env)
    with TestClient(create_app(str(env))) as client:
        headers = {"Authorization": "Bearer dev-token"}

        r = client.get("/health")
        assert r.status_code == 200, r.text
        print("health ok")

        r = client.get("/api/v1/cores", headers=headers)
        assert r.status_code == 200, r.text
        print("cores ok")

        r = client.post(
            "/api/v1/cores/xray/inbounds",
            headers=headers,
            json=_sample_inbound(1, 443),
        )
        assert r.status_code == 200, r.text
        print("xray inbound ok")

        r = client.post(
            "/api/v1/cores/wireguard/interfaces",
            headers=headers,
            json={"id": 1, "listen_port": 51820},
        )
        assert r.status_code == 200, r.text
        print("wireguard interface ok")

        r = client.get("/api/v1/stats/snapshot", headers=headers)
        assert r.status_code == 200, r.text
        print("snapshot ok")

        print("smoke passed")
