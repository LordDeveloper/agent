from __future__ import annotations

import json
from types import SimpleNamespace

from agent.config import AgentSettings
from agent.db import Store
from agent.factory_reset import confirmation_accepted, factory_reset
from agent.ops import relax_agent_start_post


class _Result(SimpleNamespace):
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


def test_confirmation_requires_exact_word():
    assert confirmation_accepted("CONFIRM")
    assert confirmation_accepted("  CONFIRM  ")
    assert not confirmation_accepted("confirm")
    assert not confirmation_accepted("YES")
    assert not confirmation_accepted("")


def test_factory_reset_wipes_database_and_managed_state(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    wg_dir = tmp_path / "wireguard"
    wg_dir.mkdir()
    awg_dir = tmp_path / "amnezia"
    awg_dir.mkdir()
    xray_config = tmp_path / "config.json"
    xray_config.write_text(
        json.dumps({"inbounds": [{"tag": "transferred", "port": 443}]}),
        encoding="utf-8",
    )
    (wg_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")
    script = data / "peer-egress-apply.sh"
    script.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    (data / "certs").mkdir()
    (data / "certs" / "fullchain.pem").write_text("cert", encoding="utf-8")

    settings = AgentSettings(
        data_dir=str(data),
        db_path=str(data / "agent.db"),
        wireguard_config_dir=str(wg_dir),
        amnezia_config_dir=str(awg_dir),
        xray_config=str(xray_config),
    )
    store = Store(settings.resolve_db_path())
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {"id": 1, "name": "wg0", "peers": [{"address": "10.90.68.2", "exit_interface": "nl"}]},
    )
    store.put_doc("wireguard", "interface", "evil", {"id": "evil", "name": "../outside"})
    store.close()

    calls: list[list[str]] = []

    def runner(args, check=False, timeout=30):
        calls.append(list(args))
        if args[:4] == ["ip", "-4", "rule", "show"]:
            return _Result(
                stdout="0:\tfrom all lookup local\n15010:\tfrom 10.90.68.2 lookup 21141\n32766:\tfrom all lookup main\n"
            )
        return _Result()

    result = factory_reset(settings, runner=runner, stop_service=False)

    assert result["ok"] is True
    assert not (data / "agent.db").exists()
    assert not script.exists()
    assert not (wg_dir / "wg0.conf").exists()
    assert not (data / "certs").exists()
    assert ["ip", "rule", "del", "pref", "15010"] in calls
    assert ["ip", "rule", "del", "pref", "0"] not in calls
    assert ["ip", "rule", "del", "pref", "32766"] not in calls
    assert not any(args[:2] == ["systemctl", "kill"] for args in calls)
    reset = json.loads(xray_config.read_text(encoding="utf-8"))
    assert [row["tag"] for row in reset["inbounds"]] == ["api"]
    assert ["systemctl", "restart", "xray"] in calls
    assert not (wg_dir / "../outside.conf").exists()


def test_relax_agent_start_post_stops_waiting_on_the_script(tmp_path):
    unit = tmp_path / "agent.service"
    unit.write_text(
        "\n".join(
            [
                "[Service]",
                "ExecStart=/opt/agent/bin/agent serve",
                "ExecStartPost=-/bin/sh -c 'test -x /var/lib/agent/peer-egress-apply.sh && /var/lib/agent/peer-egress-apply.sh || true'",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def runner(args, check=False, timeout=30):
        calls.append(list(args))
        return _Result()

    assert relax_agent_start_post(unit, runner=runner) is True
    text = unit.read_text(encoding="utf-8")
    assert "peer-egress-apply.sh" not in text
    assert "systemctl start --no-block agent-peer-egress.service" in text
    assert calls == [["systemctl", "daemon-reload"]]
    assert relax_agent_start_post(unit, runner=runner) is False
