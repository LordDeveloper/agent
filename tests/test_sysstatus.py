from collections import namedtuple
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agent.api.status import router
from agent.auth import verify_auth
from agent.config import AgentSettings
from agent.support.sysstatus import (
    HostSample,
    NetCounters,
    RateTracker,
    read_linux,
    reset_tracker,
)

Usage = namedtuple("Usage", "total used free")


def _net(rx_bytes: int, tx_bytes: int, rx_packets: int = 0, tx_packets: int = 0) -> NetCounters:
    return NetCounters(
        rx_bytes=rx_bytes,
        tx_bytes=tx_bytes,
        rx_packets=rx_packets,
        tx_packets=tx_packets,
    )


def _sample(**overrides) -> HostSample:
    sample = HostSample(
        cpu_idle=800,
        cpu_total=1000,
        net={"eth0": _net(1000, 2000, 10, 20), "lo": _net(9, 9)},
    )
    for key, value in overrides.items():
        setattr(sample, key, value)
    return sample


def test_first_sample_has_counters_and_null_rates():
    tracker = RateTracker()
    payload = tracker.consume(_sample(), now=10.0)

    assert payload["rates_ready"] is False
    assert payload["cpu"]["utilization_percent"] is None
    assert payload["network"]["rx_mbps"] is None
    assert payload["network"]["rx_bytes"] == 1009
    assert payload["traffic"]["rx_packets_per_sec"] is None
    assert [row["name"] for row in payload["network"]["interfaces"]] == ["eth0", "lo"]


def test_second_sample_computes_bandwidth_and_packet_rates():
    tracker = RateTracker()
    tracker.consume(_sample(), now=10.0)
    payload = tracker.consume(
        _sample(
            cpu_idle=800 + 800,
            cpu_total=1000 + 1000,
            net={
                "eth0": _net(1000 + 125_000, 2000 + 250_000, 10 + 50, 20 + 25),
                "lo": _net(9, 9),
            },
        ),
        now=11.0,
    )

    assert payload["rates_ready"] is True
    assert payload["interval_seconds"] == 1.0
    assert payload["cpu"]["utilization_percent"] == 20.0
    eth0 = next(row for row in payload["network"]["interfaces"] if row["name"] == "eth0")
    assert eth0["rx_mbps"] == 1.0
    assert eth0["tx_mbps"] == 2.0
    assert eth0["rx_packets_per_sec"] == 50.0
    assert payload["network"]["rx_mbps"] == 1.0
    assert payload["traffic"]["tx_packets_per_sec"] == 25.0


def test_counter_reset_and_missing_interface_do_not_invent_rates():
    tracker = RateTracker()
    tracker.consume(_sample(), now=1.0)
    reset = tracker.consume(
        _sample(net={"eth0": _net(10, 2000, 10, 20)}),
        now=2.0,
    )
    eth0 = next(row for row in reset["network"]["interfaces"] if row["name"] == "eth0")
    assert eth0["rx_mbps"] is None
    assert reset["network"]["rx_mbps"] is None
    assert eth0["tx_mbps"] == 0.0

    recovered = tracker.consume(
        _sample(net={"eth0": _net(10 + 125_000, 2000, 10, 20)}),
        now=3.0,
    )
    eth0 = next(row for row in recovered["network"]["interfaces"] if row["name"] == "eth0")
    assert eth0["rx_mbps"] == 1.0

    missing = tracker.consume(_sample(net={}), now=4.0)
    assert missing["network"]["interfaces"] == []
    assert missing["network"]["rx_mbps"] is None
    assert missing["traffic"]["rx_bytes_per_sec"] is None


def test_short_interval_keeps_the_previous_baseline():
    tracker = RateTracker()
    tracker.consume(_sample(), now=0.0)
    tracker.consume(
        _sample(net={"eth0": _net(1000 + 1_000, 2000, 10, 20), "lo": _net(9, 9)}),
        now=0.05,
    )
    payload = tracker.consume(
        _sample(net={"eth0": _net(1000 + 125_000, 2000, 10, 20), "lo": _net(9, 9)}),
        now=1.0,
    )
    eth0 = next(row for row in payload["network"]["interfaces"] if row["name"] == "eth0")
    assert eth0["rx_mbps"] == 1.0


def test_read_linux_parses_proc_and_skips_pseudo_filesystems(tmp_path: Path):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "self" / "fd").mkdir(parents=True)
    (proc / "self" / "fd" / "0").write_text("", encoding="utf-8")
    (proc / "stat").write_text("cpu  100 0 50 800 50 0 0 0 0 0\n", encoding="utf-8")
    (proc / "loadavg").write_text("0.40 0.20 0.10 1/100 10\n", encoding="utf-8")
    (proc / "meminfo").write_text(
        "MemTotal: 2048 kB\nMemAvailable: 1024 kB\n",
        encoding="utf-8",
    )
    (proc / "mounts").write_text(
        "\n".join(
            [
                "proc /proc proc rw 0 0",
                "tmpfs /run tmpfs rw 0 0",
                "/dev/vda1 / ext4 rw 0 0",
                "/dev/vda1 /home ext4 rw 0 0",
            ]
        ),
        encoding="utf-8",
    )
    (proc / "net" / "dev").write_text(
        "\n".join(
            [
                "Inter-|   Receive                                                |  Transmit",
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
                "    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0",
                "  eth0: 100 4 1 2 0 0 0 0 50 3 0 1 0 0 0 0",
            ]
        ),
        encoding="utf-8",
    )
    (proc / "net" / "sockstat").write_text(
        "sockets: used 12\nTCP: inuse 4 orphan 0 tw 1 alloc 5 mem 1\nUDP: inuse 2 mem 0\n",
        encoding="utf-8",
    )
    (proc / "net" / "snmp").write_text(
        "Tcp: RtoAlgorithm MaxConn CurrEstab\nTcp: 1 -1 3\n",
        encoding="utf-8",
    )
    (proc / "uptime").write_text("1000.5 10\n", encoding="utf-8")
    # Fields 3..24: state through rss. utime/stime are 14/15, threads 20, starttime 22, rss 24.
    fields = ["0"] * 22
    fields[0] = "S"
    fields[11] = "10"
    fields[12] = "20"
    fields[17] = "4"
    fields[19] = "5000"
    fields[21] = "12"
    (proc / "self" / "stat").write_text(f"42 (agent) {' '.join(fields)}\n", encoding="utf-8")

    def disk_usage(path: str):
        assert path == "/"
        return Usage(total=1000, used=250, free=750)

    sample = read_linux(proc, disk_usage=disk_usage)

    assert sample.cpu_idle == 850
    assert sample.cpu_total == 1000
    assert sample.load == (0.4, 0.2, 0.1)
    assert sample.memory is not None
    assert sample.memory.total_bytes == 2048 * 1024
    assert sample.memory.available_bytes == 1024 * 1024
    assert [disk.mount for disk in sample.disks] == ["/"]
    assert "lo" not in sample.net
    assert sample.net["eth0"].rx_bytes == 100
    assert sample.net["eth0"].rx_errors == 1
    assert sample.net["eth0"].rx_dropped == 2
    assert sample.tcp_inuse == 4
    assert sample.udp_inuse == 2
    assert sample.sockets_used == 12
    assert sample.tcp_established == 3
    assert sample.uptime_seconds == 1000.5
    assert sample.agent is not None
    assert sample.agent.pid == 42
    assert sample.agent.state == "sleeping"
    assert sample.agent.threads == 4
    assert sample.agent.fd_count == 1
    assert sample.agent.cpu_seconds == pytest.approx(30 / 100)


def test_status_route_requires_auth_and_returns_host_metrics(tmp_path: Path):
    reset_tracker()
    app = FastAPI()
    app.state.settings = AgentSettings(auth_token="dev-token", data_dir=str(tmp_path))
    app.include_router(router, prefix="/api/v1", dependencies=[Depends(verify_auth)])

    with TestClient(app) as client:
        denied = client.get("/api/v1/status/sys")
        assert denied.status_code == 401
        assert client.get("/status/sys").status_code == 404

        first = client.get("/api/v1/status/sys", headers={"Authorization": "Bearer dev-token"})
        assert first.status_code == 200
        body = first.json()
        assert body["success"] is True
        assert body["rates_ready"] is False
        assert set(body) >= {
            "cpu",
            "memory",
            "disks",
            "network",
            "traffic",
            "connections",
            "uptime_seconds",
            "agent",
        }
        assert body["memory"]["total_bytes"] > 0
        assert body["uptime_seconds"] > 0
        assert body["agent"]["pid"] > 0
        assert body["network"]["rx_mbps"] is None

        import time

        time.sleep(0.35)
        second = client.get("/api/v1/status/sys", headers={"Authorization": "Bearer dev-token"})

    assert second.status_code == 200
    live = second.json()
    assert live["rates_ready"] is True
    assert live["cpu"]["utilization_percent"] is not None
    assert live["interval_seconds"] >= 0.25
