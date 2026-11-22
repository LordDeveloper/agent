"""Real Xray process: VLESS TCP with and without PROXY protocol v2.

The inbound JSON is the object ``XrayDriver._wire_inbound`` would hand the
core. Ports come from the kernel. The test skips when no xray binary is on
PATH or in XRAY_BIN. It does not print the client id.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest

from agent.drivers.xray import XrayDriver

pytestmark = pytest.mark.skipif(
    not (os.environ.get("XRAY_BIN") or shutil.which("xray")),
    reason="xray binary not available",
)


def _binary() -> str:
    return os.environ.get("XRAY_BIN") or shutil.which("xray") or ""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _proxy_v2(src: str, sport: int, dst: str, dport: int) -> bytes:
    body = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!HH", sport, dport)
    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes((0x21, 0x11)) + struct.pack("!H", len(body)) + body


def _vless(user_id: str, host: str, port: int, payload: bytes) -> bytes:
    host_b = host.encode("ascii")
    return (
        b"\x00"
        + uuid.UUID(user_id).bytes
        + b"\x00"
        + b"\x01"
        + struct.pack("!H", port)
        + b"\x02"
        + bytes((len(host_b),))
        + host_b
        + payload
    )


def _read_response(sock: socket.socket) -> bytes:
    header = b""
    while len(header) < 2:
        chunk = sock.recv(2 - len(header))
        if not chunk:
            return b""
        header += chunk
    addon = header[1]
    pending = addon
    while pending:
        chunk = sock.recv(pending)
        if not chunk:
            break
        pending -= len(chunk)
    body = b""
    sock.settimeout(0.4)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        pass
    return body


def _serve(port: int, stop: list[bool], seen: list[tuple[str, int]]) -> None:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    server.settimeout(0.2)
    while not stop[0]:
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        seen.append((str(addr[0]), int(addr[1])))
        conn.settimeout(1)
        data = b""
        try:
            while len(data) < 2:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        try:
            if data:
                conn.sendall(data)
        except OSError:
            pass
        conn.close()
    server.close()


def _wired_inbound(*, listen_port: int, user_id: str, accept_proxy: bool) -> dict:
    inbound = {
        "listen": "127.0.0.1",
        "port": listen_port,
        "protocol": "vless",
        "tag": "inbound-probe",
        "acceptProxyProtocol": True,
        "settings": {
            "clients": [{"id": user_id, "email": "probe"}],
        },
        "streamSettings": {
            "network": "tcp",
            "security": "none",
            "domainSettings": {"share": {"host": "ignored.example"}},
        },
    }
    if accept_proxy:
        inbound["streamSettings"]["tcpSettings"] = {"acceptProxyProtocol": True}
    driver = object.__new__(XrayDriver)
    wired = XrayDriver._wire_inbound(driver, inbound)
    assert "acceptProxyProtocol" not in wired
    assert "domainSettings" not in wired["streamSettings"]
    stream = wired["streamSettings"]
    if accept_proxy:
        assert stream["tcpSettings"]["acceptProxyProtocol"] is True
    else:
        assert "tcpSettings" not in stream or not stream["tcpSettings"].get("acceptProxyProtocol")
    freedom = {"protocol": "freedom", "tag": "direct"}
    assert "streamSettings" not in freedom
    return wired


def _config(inbound: dict) -> dict:
    return {
        "inbounds": [inbound],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def _start(binary: str, config_path: Path) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [binary, "run", "-c", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 5
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"xray exited {proc.returncode}")
        try:
            port = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]["port"]
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.05)
    proc.kill()
    pytest.fail("xray did not accept connections")
    raise AssertionError("unreachable")


def _exchange(
    *,
    listen_port: int,
    echo_port: int,
    user_id: str,
    payload: bytes,
    proxy: bool,
) -> bytes:
    sock = socket.create_connection(("127.0.0.1", listen_port), timeout=2)
    sock.settimeout(2)
    blob = _vless(user_id, "127.0.0.1", echo_port, payload)
    if proxy:
        blob = _proxy_v2("203.0.113.10", 40000, "127.0.0.1", listen_port) + blob
    try:
        sock.sendall(blob)
        return _read_response(sock)
    except OSError:
        return b""
    finally:
        sock.close()


def test_vless_tcp_proxy_v2_and_plain_round_trip(tmp_path: Path):
    user_id = str(uuid.uuid4())
    payload = b"ok"
    echo_port = _free_port()
    stop = [False]
    seen: list[tuple[str, int]] = []
    thread = threading.Thread(target=_serve, args=(echo_port, stop, seen), daemon=True)
    thread.start()
    binary = _binary()
    directory = Path(tempfile.mkdtemp(dir=tmp_path))
    try:
        proxy_port = _free_port()
        proxy_inbound = _wired_inbound(listen_port=proxy_port, user_id=user_id, accept_proxy=True)
        proxy_path = directory / "proxy.json"
        proxy_path.write_text(json.dumps(_config(proxy_inbound)), encoding="utf-8")
        proc = _start(binary, proxy_path)
        try:
            before = len(seen)
            body = _exchange(
                listen_port=proxy_port,
                echo_port=echo_port,
                user_id=user_id,
                payload=payload,
                proxy=True,
            )
            assert len(seen) == before + 1
            assert body == payload
            proc.kill()
            proc.wait(timeout=5)
            proc = _start(binary, proxy_path)
            before = len(seen)
            body = _exchange(
                listen_port=proxy_port,
                echo_port=echo_port,
                user_id=user_id,
                payload=payload,
                proxy=True,
            )
            assert len(seen) == before + 1
            assert body == payload
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

        plain_port = _free_port()
        plain_inbound = _wired_inbound(listen_port=plain_port, user_id=user_id, accept_proxy=False)
        plain_path = directory / "plain.json"
        plain_path.write_text(json.dumps(_config(plain_inbound)), encoding="utf-8")
        proc = _start(binary, plain_path)
        try:
            before = len(seen)
            body = _exchange(
                listen_port=plain_port,
                echo_port=echo_port,
                user_id=user_id,
                payload=payload,
                proxy=False,
            )
            assert len(seen) == before + 1
            assert body == payload
            before = len(seen)
            rejected = _exchange(
                listen_port=plain_port,
                echo_port=echo_port,
                user_id=user_id,
                payload=payload,
                proxy=True,
            )
            assert rejected == b""
            assert len(seen) == before
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        stop[0] = True
        thread.join(timeout=2)
