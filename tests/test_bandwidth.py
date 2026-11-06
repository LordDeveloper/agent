import asyncio
import time

import pytest

from agent.support.bandwidth import (
    IFB_DOWN,
    IFB_UP,
    BandwidthManager,
    BandwidthValueError,
    collect_l2tp_plans,
    collect_openvpn_plans,
    collect_tunnel_plans,
    diagnose_bandwidth,
    limit_from_peer,
    core_supports_bandwidth,
    filter_show_has,
    ifb_commands,
    repair_ifb_commands,
    repair_tunnel_commands,
    mbps_to_kbit,
    normalize_bandwidth,
    ppp_commands,
    reset_runtime_for_tests,
    resolve_enforcement_status,
    schedule_bandwidth,
    tunnel_commands,
    with_provisioning,
)
def test_mbps_uses_decimal_kilobits():
    assert mbps_to_kbit(1) == 1000
    assert mbps_to_kbit(5) == 5000


def test_null_bandwidth_is_unlimited():
    assert normalize_bandwidth(None) is None
    assert normalize_bandwidth({}) is None
    assert normalize_bandwidth({"download_mbps": None, "upload_mbps": None}) is None


def test_shared_and_directional_values():
    assert normalize_bandwidth(5) == {"download_mbps": 5, "upload_mbps": 5}
    assert normalize_bandwidth({"download_mbps": 10, "upload_mbps": 2}) == {
        "download_mbps": 10,
        "upload_mbps": 2,
    }
    assert normalize_bandwidth({"mbps": 8, "upload_mbps": None}) == {
        "download_mbps": 8,
        "upload_mbps": 8,
    }
    assert normalize_bandwidth({"download_mbps": 4}) == {
        "download_mbps": 4,
        "upload_mbps": None,
    }


@pytest.mark.parametrize("value", [0, -1, 100001, "0", True, 1.5])
def test_invalid_bandwidth_is_rejected(value):
    with pytest.raises(BandwidthValueError):
        normalize_bandwidth(value)


def test_two_tunnel_addresses_share_one_class():
    plans = collect_tunnel_plans([
        {
            "name": "wg0",
            "peers": [
                {
                    "id": "sub-1",
                    "is_enabled": True,
                    "address": "10.8.0.2",
                    "allowed_ips": "10.8.0.2/32,10.8.0.3/32",
                    "bandwidth": {"download_mbps": 5, "upload_mbps": 5},
                },
                {
                    "id": "sub-2",
                    "is_enabled": True,
                    "address": "10.8.0.4",
                    "bandwidth": {"download_mbps": 20, "upload_mbps": 1},
                },
            ],
        }
    ])
    assert len(plans) == 1
    assert len(plans[0].limits) == 2
    first = plans[0].limits[0]
    commands = "\n".join(tunnel_commands("wg0", plans[0].limits))
    assert commands.count(f"classid 1:{first.minor} ") == 1
    assert "match ip dst 10.8.0.2/32" in commands
    assert "match ip dst 10.8.0.3/32" in commands
    assert f"flowid 1:{first.minor}" in commands
    assert "match ip dst 10.8.0.4/32" in commands
    assert "dev wg0 root" in commands
    assert IFB_UP in commands


def test_disabled_and_unlimited_peers_are_omitted():
    plans = collect_tunnel_plans([
        {
            "name": "awg1",
            "peers": [
                {"id": "off", "is_enabled": False, "address": "10.1.0.2", "bandwidth": 5},
                {"id": "free", "is_enabled": True, "address": "10.1.0.3", "bandwidth": None},
            ],
        }
    ])
    assert plans == []


def test_openvpn_sessions_share_the_subscription_class():
    plans = collect_openvpn_plans(
        [
            {
                "id": 4,
                "users": [
                    {
                        "id": "user-1",
                        "username": "alice",
                        "is_enabled": True,
                        "address": "10.9.0.2",
                        "bandwidth": {"download_mbps": 3, "upload_mbps": 3},
                    }
                ],
            }
        ],
        {"alice": ["10.9.0.2", "10.9.0.9"]},
    )
    assert plans[0].name == "ovpn4"
    assert plans[0].limits[0].addresses == ["10.9.0.2", "10.9.0.9"]
    commands = "\n".join(tunnel_commands(plans[0].name, plans[0].limits))
    minor = plans[0].limits[0].minor
    assert commands.count(f"classid 1:{minor} ") == 1
    assert "match ip dst 10.9.0.9/32" in commands


def test_l2tp_sessions_share_one_ifb_class():
    limits, devices = collect_l2tp_plans(
        [
            {
                "users": [
                    {
                        "id": "same",
                        "is_enabled": True,
                        "address": "10.7.0.2",
                        "bandwidth": {"download_mbps": 4, "upload_mbps": 4},
                    }
                ]
            }
        ],
        {
            "10.7.0.2": {"interface": "ppp0"},
            "10.7.0.8": {"interface": "ppp1"},
        },
    )
    assert len(limits) == 1
    assert "ppp0" in devices
    assert "ppp1" not in devices
    limits[0].addresses.append("10.7.0.8")
    commands = "\n".join(ifb_commands(IFB_DOWN, limits, direction="download"))
    minor = limits[0].minor
    assert commands.count(f"classid 1:{minor} ") == 1
    assert "match ip dst 10.7.0.2/32" in commands
    assert "match ip dst 10.7.0.8/32" in commands
    assert "dev ppp0" not in commands


def _limited_peer(peer_id: str = "sub-1") -> dict:
    return {
        "id": peer_id,
        "is_enabled": True,
        "address": "10.8.0.2",
        "allowed_ips": "10.8.0.2/32,10.8.0.3/32",
        "bandwidth": {"download_mbps": 5, "upload_mbps": 5},
    }


def test_filters_are_installed_without_an_explicit_u32_handle():
    plans = collect_tunnel_plans([{
        "name": "wg9a440050",
        "peers": [{
            "id": "sub-1",
            "is_enabled": True,
            "address": "10.90.68.108",
            "bandwidth": {"download_mbps": 1, "upload_mbps": 1},
        }],
    }])
    limit = plans[0].limits[0]
    commands = "\n".join(tunnel_commands("wg9a440050", plans[0].limits))
    assert "qdisc add dev wg9a440050 root handle 1: htb default 9999" in commands
    assert "qdisc replace dev wg9a440050 clsact" in commands
    assert (
        "filter add dev wg9a440050 parent 1:0 protocol ip prio 10 "
        "u32 match ip dst 10.90.68.108/32 "
        f"flowid 1:{limit.minor}"
    ) in commands
    assert (
        "filter add dev wg9a440050 parent ffff: protocol ip prio 10 "
        "u32 match ip src 10.90.68.108/32 "
        f"action mirred egress redirect dev {IFB_UP}"
    ) in commands
    # An explicit 800:: node is rejected unless that hash table already exists.
    assert "handle 800::" not in commands
    assert "filter del " not in commands


_HTB = "qdisc htb 1: root refcnt 2 r2q 10 default 0x270f"
_CLSACT = "qdisc clsact ffff: parent ffff:fff1"


def test_repair_adds_missing_filters_without_replacing_qdiscs():
    plans = collect_tunnel_plans([{
        "name": "wg9a440050",
        "peers": [{
            "id": "sub-1",
            "is_enabled": True,
            "address": "10.90.68.108",
            "bandwidth": {"download_mbps": 1, "upload_mbps": 1},
        }],
    }])
    limit = plans[0].limits[0]
    qdisc = "\n".join([_HTB, _CLSACT])
    commands = "\n".join(repair_tunnel_commands(
        "wg9a440050",
        plans[0].limits,
        qdisc_text=qdisc,
        filter_text="",
        previous={"classes": [limit.minor]},
    ))
    assert "qdisc replace" not in commands
    assert "qdisc add" not in commands
    assert f"class replace dev wg9a440050 parent 1:1 classid 1:{limit.minor} " in commands
    assert "match ip dst 10.90.68.108/32" in commands
    assert f"flowid 1:{limit.minor}" in commands
    assert "match ip src 10.90.68.108/32" in commands
    assert f"action mirred egress redirect dev {IFB_UP}" in commands
    assert "handle 800::" not in commands

    ifb = "\n".join(repair_ifb_commands(
        IFB_UP,
        plans[0].limits,
        direction="upload",
        qdisc_text=_HTB,
        filter_text="",
    ))
    assert "qdisc replace" not in ifb
    assert "match ip src 10.90.68.108/32" in ifb
    assert f"flowid 1:{limit.minor}" in ifb


def test_repair_keeps_another_clients_filter_and_drops_only_the_removed_one():
    plans = collect_tunnel_plans([{
        "name": "wg9a440050",
        "peers": [
            {
                "id": "keep",
                "is_enabled": True,
                "address": "10.90.68.108",
                "bandwidth": {"download_mbps": 1, "upload_mbps": 1},
            },
            {
                "id": "other",
                "is_enabled": True,
                "address": "10.90.68.109",
                "bandwidth": {"download_mbps": 5, "upload_mbps": 5},
            },
        ],
    }])
    kept, other = plans[0].limits
    show = f"""
filter parent 1: protocol ip pref 10 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:{kept.minor}
  match 0a5a446c/ffffffff at 16
filter parent 1: protocol ip pref 10 u32 chain 0 fh 800::801 order 2049 key ht 800 bkt 0 flowid 1:{other.minor}
  match 0a5a446d/ffffffff at 16
filter parent ffff: protocol ip pref 10 u32 chain 0 fh 800::802 order 2050 key ht 800 bkt 0
  match 0a5a446c/ffffffff at 12
  action order 1: mirred (Egress Redirect to device ifb-nj-up)
filter parent ffff: protocol ip pref 10 u32 chain 0 fh 800::803 order 2051 key ht 800 bkt 0
  match 0a5a446d/ffffffff at 12
  action order 1: mirred (Egress Redirect to device ifb-nj-up)
"""
    both = "\n".join(repair_tunnel_commands(
        "wg9a440050",
        plans[0].limits,
        qdisc_text="\n".join([_HTB, _CLSACT]),
        filter_text=show,
    ))
    assert "filter add " not in both
    assert "filter del " not in both
    assert "qdisc replace" not in both

    only_kept = "\n".join(repair_tunnel_commands(
        "wg9a440050",
        [kept],
        qdisc_text="\n".join([_HTB, _CLSACT]),
        filter_text=show,
        previous={"classes": [kept.minor, other.minor]},
    ))
    assert "fh 800::800" not in only_kept
    assert "handle 800::801" in only_kept
    assert "handle 800::803" in only_kept
    assert "handle 800::802" not in only_kept
    assert f"class del dev wg9a440050 classid 1:{other.minor}" in only_kept
    assert f"classid 1:{kept.minor}" in only_kept


def test_ifb_htb_root_deletes_pfifo_before_add():
    from agent.support.bandwidth import _htb_root_lines

    pfifo = "qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"
    lines = _htb_root_lines("ifb-nj-up", pfifo)
    assert "qdisc del dev ifb-nj-up root" in lines
    assert "qdisc add dev ifb-nj-up root handle 1: htb default 9999" in lines
    assert "qdisc replace" not in "\n".join(lines)


def test_u32_fallback_uses_separate_mask_tokens():
    from agent.support.bandwidth import _filter_add_fallbacks, _ipv4_u32_match

    line = (
        "filter add dev wg0 parent 1:0 protocol ip prio 10 "
        "u32 match ip dst 10.90.68.108/32 flowid 1:1419"
    )
    alts = _filter_add_fallbacks(line)
    assert len(alts) == 2
    assert "match ip dst" in alts[0]
    assert _ipv4_u32_match("10.90.68.108", "dst") in alts[1]
    assert "/ffffffff" not in alts[1]


def test_run_tc_lines_applies_deletes_before_adds():
    from agent.support import bandwidth as bw

    calls: list[str] = []

    async def fake_run(args, **kwargs):
        calls.append(" ".join(args))
        return 0, ""

    bw._run = fake_run
    asyncio.run(bw._run_tc_lines([
        "filter add dev wg0 parent 1:0 protocol ip prio 10 u32 match u32 aa/ffffffff at 16 flowid 1:2",
        "filter del dev wg0 parent 1:0 protocol ip prio 10 handle 800::800 u32",
    ]))
    assert calls[0].startswith("tc filter del")
    assert calls[1].startswith("tc filter add")


def test_filter_show_parser_requires_the_same_block():
    show = """
filter parent 1: protocol ip pref 10 u32 chain 0 fh 800::e46 order 3654 key ht 800 bkt 0 flowid 1:1419
  match 0a5a446c/ffffffff at 16
filter parent ffff: protocol ip pref 10 u32 chain 0 fh 800::10 order 16 key ht 800 bkt 0
  match 0a5a446c/ffffffff at 12
  action order 1: mirred (Egress Redirect to device ifb-nj-up)
"""
    assert filter_show_has(show, "10.90.68.108", minor=0x1419, kind="dst")
    assert filter_show_has(show, "10.90.68.108", kind="redirect")
    assert filter_show_has(show, "10.90.68.108", minor=0x1419, kind="src") is False


def test_status_is_not_active_without_kernel_verification():
    assert resolve_enforcement_status(configured=False, verified=False) == "unlimited"
    assert resolve_enforcement_status(configured=True, verified=True) == "active"
    assert resolve_enforcement_status(configured=True, verified=False) == "error"
    assert resolve_enforcement_status(configured=True, verified=True, task="queued") == "pending"
    assert resolve_enforcement_status(configured=True, verified=False, task="running") == "installing"
    assert resolve_enforcement_status(configured=True, verified=False, dependency_state="unsupported") == "unsupported"
    assert resolve_enforcement_status(configured=True, verified=False, waiting=True) == "pending"


def test_diagnostics_do_not_report_active_from_configuration_alone():
    report = asyncio.run(diagnose_bandwidth(_limited_peer(), interface="wg1660", kind="tunnel"))
    assert report["configured"] is True
    assert report["download_mbps"] == 5
    assert report["upload_mbps"] == 5
    assert report["status"] != "active"
    assert report["verified"] is False
    unlimited = asyncio.run(diagnose_bandwidth({"id": "free", "is_enabled": True, "address": "10.8.0.4"}))
    assert unlimited == {
        "configured": False,
        "status": "unlimited",
        "download_mbps": None,
        "upload_mbps": None,
        "verified": False,
        "method": None,
        "interface": None,
        "class_id": None,
        "last_error": None,
    }


def test_provisioning_response_does_not_wait_and_keeps_success_on_bandwidth_failure(tmp_path):
    reset_runtime_for_tests()
    manager = BandwidthManager(object(), tmp_path, retry_delay=0)

    async def fail():
        await asyncio.sleep(0.2)
        return {"state": "error", "last_error": "tc failed"}

    manager._run = fail
    started = time.perf_counter()
    queued = manager.apply({"id": "example"}, core="wireguard", interface="wg1660")
    elapsed = time.perf_counter() - started
    assert elapsed < 0.1
    assert queued["status"] == "queued"
    payload = with_provisioning({"success": True, "client_id": "example"}, "example")
    # The helper reads the process manager. Bind it for this assertion.
    from agent.support import bandwidth as bandwidth_module

    bandwidth_module._manager = manager
    try:
        payload = with_provisioning({"success": True, "client_id": "example"}, "example")
    finally:
        reset_runtime_for_tests()
    assert payload["success"] is True
    assert payload["provisioning_status"] == "completed"
    assert payload["background_tasks"]["bandwidth"] == "pending"


def test_background_tasks_coalesce_retry_and_ignore_stale_state(tmp_path):
    manager = BandwidthManager(object(), tmp_path, retry_delay=0)
    state = {"rate": 5, "enabled": True, "present": True, "calls": []}

    async def apply_desired():
        observed = (state["rate"], state["enabled"], state["present"])
        await asyncio.sleep(0.02)
        state["calls"].append(observed)
        if state.get("boom"):
            state["boom"] = False
            raise RuntimeError("transient tc failure")
        return {"state": "idle"}

    manager._run = apply_desired

    async def scenario():
        for index in range(20):
            manager.update({"id": f"client-{index}"}, core="wireguard")
        manager.update({"id": "client-0"}, core="wireguard")
        drain = asyncio.create_task(manager._drain(asyncio.Event()))
        await asyncio.sleep(0.01)
        state["rate"] = 20
        state["enabled"] = False
        state["present"] = False
        manager.remove("client-0")
        await drain
        state["boom"] = True
        manager.update({"id": "client-0"})
        await manager._drain(asyncio.Event())

    asyncio.run(scenario())
    assert state["calls"]
    assert state["calls"][-1] == (20, False, False)
    assert len(state["calls"]) < 20
    failed = [row for row in manager._tasks.values() if row.get("status") == "failed"]
    assert failed == []
    assert any(int(row.get("retries") or 0) >= 1 for row in manager._tasks.values())


def test_restart_requeues_unfinished_tasks(tmp_path):
    manager = BandwidthManager(object(), tmp_path)
    manager.apply({"id": "example"})
    manager._tasks["example"]["status"] = "running"
    manager._save_tasks()
    restored = BandwidthManager(object(), tmp_path)
    assert restored.requeue_unfinished() == 1
    assert restored._tasks["example"]["status"] == "queued"
    assert restored._wake.is_set()


def test_slow_bandwidth_task_does_not_block_another_client(tmp_path):
    manager = BandwidthManager(object(), tmp_path, retry_delay=0)
    release = asyncio.Event()
    entered = asyncio.Event()

    async def slow():
        entered.set()
        await release.wait()
        return {"state": "idle"}

    manager._run = slow

    async def scenario():
        manager.apply({"id": "slow"}, core="wireguard", interface="wg1")
        worker = asyncio.create_task(manager._drain(asyncio.Event()))
        await entered.wait()
        started = time.perf_counter()
        manager.update({"id": "other"}, core="openvpn", interface="ovpn1")
        elapsed = time.perf_counter() - started
        release.set()
        await worker
        return elapsed

    elapsed = asyncio.run(scenario())
    assert elapsed < 0.1
    assert manager._tasks["other"]["status"] in {"completed", "running", "queued"}


def test_disabled_bandwidth_does_not_install_limit():
    peer = {
        "id": "limited",
        "is_enabled": True,
        "address": "10.8.0.5",
        "bandwidth": {"download_mbps": 5, "upload_mbps": 5},
        "bandwidth_enabled": False,
    }
    assert limit_from_peer(peer) is None
    report = asyncio.run(diagnose_bandwidth(peer, interface="wg1", kind="tunnel"))
    assert report["configured"] is True
    assert report["enabled"] is False
    assert report["status"] == "disabled"


def test_each_shaped_core_can_enqueue_and_xray_cannot(tmp_path):
    reset_runtime_for_tests()
    manager = BandwidthManager(object(), tmp_path, retry_delay=0)
    from agent.support import bandwidth as bandwidth_module

    bandwidth_module._manager = manager
    try:
        for core in ("wireguard", "amnezia", "openvpn", "l2tp"):
            assert core_supports_bandwidth(core) is True
            queued = schedule_bandwidth(f"client-{core}", core=core, action="update")
            assert queued["status"] == "queued"
        assert core_supports_bandwidth("xray") is False
        refused = schedule_bandwidth("xray-client", core="xray", action="update")
        assert refused == {"status": "unsupported", "enqueued": False}
        assert "xray-client" not in manager._tasks
        direct = manager.apply({"id": "xray-direct"}, core="xray")
        assert direct["status"] == "unsupported"
        assert "xray-direct" not in manager._tasks
    finally:
        reset_runtime_for_tests()
