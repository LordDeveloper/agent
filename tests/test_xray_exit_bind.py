import asyncio
import os
from types import SimpleNamespace

from agent.errors import AgentError
from agent.support.peer_egress import table_id_for_interface
from agent.support.xray_exit_bind import (
    bind_pref,
    choose_bind_pref,
    ensure_interface_bind_route,
    parse_ip_rule_line,
    script_lines,
)


def test_script_lines_install_the_interface_table_not_main():
    lines = script_lines(["wg-fi"])
    rendered = "\n".join(lines)
    assert 'dev "wg-fi"' in rendered
    assert "table main" not in rendered
    route_lines = [line for line in lines if "ip route replace" in line]
    assert route_lines
    for line in route_lines:
        assert " table " in line
        table = line.rsplit(" table ", 1)[1].split()[0]
        assert int(table) >= 10000
    assert "ip rule del pref " in rendered


def test_parse_ip_rule_line_reads_oif_and_lookup():
    row = parse_ip_rule_line("11042:\tfrom all oif uk lookup 15234")
    assert row == {"pref": 11042, "oif": "uk", "table": "15234"}
    assert parse_ip_rule_line("0:\tfrom all lookup local")["oif"] == ""
    assert parse_ip_rule_line("not a rule") is None


def test_choose_bind_pref_skips_a_taken_slot():
    base = bind_pref("uk")
    chosen = choose_bind_pref("uk", {base})
    assert chosen != base
    assert 11000 <= chosen <= 13999


def _completed(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class _Host:
    def __init__(self, rules: str):
        self.rules = rules
        self.calls: list[list[str]] = []
        self.add_code = 0
        self.add_err = ""
        self.rules_after_add: str | None = None

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[:4] == ["ip", "link", "show", "dev"]:
            return _completed(stdout="2: uk: <BROADCAST,UP>")
        if args[:5] == ["ip", "-4", "addr", "show", "dev"]:
            return _completed(stdout="    inet 10.7.0.2/32 scope global uk")
        if args[0] == "sysctl":
            return _completed()
        if args[:3] == ["ip", "route", "replace"]:
            return _completed()
        if args[:3] == ["ip", "rule", "show"]:
            return _completed(stdout=self.rules)
        if args[:3] == ["ip", "rule", "del"]:
            return _completed()
        if args[:3] == ["ip", "rule", "add"]:
            if self.rules_after_add is not None:
                self.rules = self.rules_after_add
            return _completed(self.add_code, stderr=self.add_err)
        return _completed(1, stderr="unexpected")


def _bind(host: _Host, tmp_path):
    previous = os.environ.get("NETINJA_XRAY_EXIT_BINDS")
    os.environ["NETINJA_XRAY_EXIT_BINDS"] = str(tmp_path / "binds.json")
    try:
        return asyncio.run(ensure_interface_bind_route("uk", runner=host))
    finally:
        if previous is None:
            os.environ.pop("NETINJA_XRAY_EXIT_BINDS", None)
        else:
            os.environ["NETINJA_XRAY_EXIT_BINDS"] = previous


def _adds(host: _Host) -> list[list[str]]:
    return [call for call in host.calls if call[:3] == ["ip", "rule", "add"]]


def _dels(host: _Host) -> list[list[str]]:
    return [call for call in host.calls if call[:3] == ["ip", "rule", "del"]]


def test_existing_oif_rule_is_not_added_again(tmp_path):
    table = table_id_for_interface("uk")
    pref = bind_pref("uk")
    host = _Host(f"{pref}:\tfrom all oif uk lookup {table}\n32766:\tfrom all lookup main\n")
    result = _bind(host, tmp_path)
    assert result["ok"] is True
    assert result["pref"] == pref
    assert _adds(host) == []
    assert _dels(host) == []


def test_dead_ifindex_at_the_same_pref_is_replaced(tmp_path):
    table = table_id_for_interface("uk")
    pref = bind_pref("uk")
    host = _Host(f"{pref}:\tfrom all oif 15 lookup {table}\n")
    result = _bind(host, tmp_path)
    assert result["pref"] == pref
    assert _dels(host) == [["ip", "rule", "del", "pref", str(pref)]]
    assert _adds(host) == [["ip", "rule", "add", "oif", "uk", "lookup", str(table), "pref", str(pref)]]


def test_another_exit_keeps_a_colliding_pref(tmp_path):
    pref = bind_pref("uk")
    host = _Host(f"{pref}:\tfrom all oif pl lookup 10001\n")
    result = _bind(host, tmp_path)
    assert result["pref"] != pref
    assert _dels(host) == []
    assert _adds(host)[0][-1] == str(result["pref"])


def test_file_exists_is_success_when_the_rule_is_already_present(tmp_path):
    table = table_id_for_interface("uk")
    pref = bind_pref("uk")
    host = _Host("32766:\tfrom all lookup main\n")
    host.add_code = 2
    host.add_err = "RTNETLINK answers: File exists"
    host.rules_after_add = f"{pref}:\tfrom all oif uk lookup {table}\n"
    result = _bind(host, tmp_path)
    assert result["ok"] is True
    assert result["pref"] == pref


def test_file_exists_without_the_rule_still_fails(tmp_path):
    pref = bind_pref("uk")
    host = _Host(f"{pref}:\tfrom all iif eth0 lookup main\n")
    host.add_code = 2
    host.add_err = "RTNETLINK answers: File exists"
    try:
        _bind(host, tmp_path)
    except AgentError as exc:
        assert exc.code == "EXEC_ERROR"
        assert "File exists" in exc.message
    else:
        raise AssertionError("missing rule should still fail")
