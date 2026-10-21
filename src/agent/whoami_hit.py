"""Localhost receiver for the Xray whoami routing webhook.

Xray posts here from the same machine. The socket never binds a public address.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

HOST = "127.0.0.1"
PORT = 39217
PATH = "/hit"
DOMAIN = "whoami.nerobot.click"
MAX_BODY = 4096
HEADER_LIMIT = 8192
RATE_SECONDS = 30
QUEUE_LIMIT = 200

_SCHEMES = ("tcp:", "udp:", "http:", "https:", "tls:", "quic:")


def authorization_ok(provided: str, secret: str) -> bool:
    if not secret:
        return False
    return hmac.compare_digest(
        hashlib.sha256(b"Bearer " + secret.encode()).digest(),
        hashlib.sha256(provided.encode()).digest(),
    )


def destination_is_check_host(destination: Any) -> bool:
    if not isinstance(destination, str):
        return False
    value = destination.strip().lower()
    if not value:
        return False
    if "://" in value:
        value = value.split("://", 1)[1]
    for scheme in _SCHEMES:
        if value.startswith(scheme) and "." in value[len(scheme) :]:
            value = value[len(scheme) :]
            break
    value = value.split("/", 1)[0]
    if value.startswith("["):
        return False
    host = value
    if value.count(":") == 1:
        host = value.split(":", 1)[0]
    return host.rstrip(".") == DOMAIN


def content_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None or not raw.strip().isdigit():
        return None
    return int(raw.strip())


def decide(
    method: str,
    target: str,
    headers: dict[str, str],
    body: bytes | None,
    body_was_read: bool,
    secret: str,
    now: int,
    recent: dict[str, int],
) -> dict[str, Any]:
    path = target.split("?", 1)[0]
    if method != "POST" or path != PATH:
        return {"status": 404, "read_body": False, "store": False}

    length = content_length(headers)
    if length is None or length > MAX_BODY:
        return {"status": 401, "read_body": False, "store": False}

    if not authorization_ok(headers.get("authorization", ""), secret):
        return {"status": 401, "read_body": False, "store": False}

    if not body_was_read:
        return {"status": 204, "read_body": True, "store": False}

    try:
        payload = json.loads(body or b"")
    except (json.JSONDecodeError, UnicodeError):
        return {"status": 204, "read_body": False, "store": False}
    if not isinstance(payload, dict):
        return {"status": 204, "read_body": False, "store": False}

    email = str(payload.get("email") or "").strip()
    if not email or len(email) > 190 or any(ch.isspace() for ch in email):
        return {"status": 204, "read_body": False, "store": False}
    if not destination_is_check_host(payload.get("destination")):
        return {"status": 204, "read_body": False, "store": False}

    last = recent.get(email)
    if last is not None and (now - last) < RATE_SECONDS:
        return {"status": 204, "read_body": False, "store": False}

    return {
        "status": 204,
        "read_body": False,
        "store": True,
        "email": email,
        "inbound_tag": _short(payload.get("inboundTag")),
        "source": _short(payload.get("source")),
    }


def http_response(status: int) -> bytes:
    if status not in {204, 401, 404}:
        status = 404
    text = {204: "No Content", 401: "Unauthorized", 404: "Not Found"}[status]
    return (
        f"HTTP/1.1 {status} {text}\r\nContent-Length: 0\r\n"
        "Connection: close\r\nCache-Control: no-store\r\n\r\n"
    ).encode()


def _short(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = "".join(ch for ch in value.strip() if ord(ch) >= 32)[:128]
    return text or None


class WhoamiHitService:
    def __init__(self, secret_path: Path) -> None:
        self.secret_path = secret_path
        self._secret = ""
        self._recent: dict[str, int] = {}
        self._hits: deque[dict[str, Any]] = deque(maxlen=QUEUE_LIMIT)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._server = None
        self._stop = threading.Event()

    def start_if_configured(self) -> None:
        token = self._read_secret()
        if token:
            self.set_token(token)

    def set_token(self, token: str) -> None:
        token = token.strip()
        if len(token) < 32 or any(ch.isspace() for ch in token):
            raise ValueError("token rejected")
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)
        self.secret_path.write_text(token, encoding="utf-8")
        os.chmod(self.secret_path, 0o600)
        with self._lock:
            self._secret = token
        self._ensure_started()

    def drain(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self._hits)
            self._hits.clear()
            return rows

    def stop(self) -> None:
        self._stop.set()
        server = self._server
        if server is not None:
            try:
                server.close()
            except OSError:
                pass

    def _read_secret(self) -> str:
        try:
            return self.secret_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def _ensure_started(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="whoami-hit", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        import socket

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        bound = server.getsockname()
        if bound[0] != HOST:
            server.close()
            return
        server.listen(16)
        server.settimeout(1.0)
        self._server = server
        try:
            while not self._stop.is_set():
                try:
                    client, _addr = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                try:
                    self._handle(client)
                finally:
                    client.close()
        finally:
            server.close()

    def _handle(self, client: Any) -> None:
        client.settimeout(5)
        raw = self._read_head(client)
        if raw is None:
            client.sendall(http_response(404))
            return
        head, _, prefetched = raw.partition(b"\r\n\r\n")
        parsed = _parse_head(head)
        if parsed is None:
            client.sendall(http_response(404))
            return
        method, target, headers = parsed
        with self._lock:
            secret = self._secret
            recent = dict(self._recent)
        decision = decide(method, target, headers, None, False, secret, int(time.time()), recent)
        body = b""
        if decision["read_body"]:
            length = content_length(headers) or 0
            body = _read_body(client, prefetched, length)
            with self._lock:
                secret = self._secret
                recent = dict(self._recent)
            decision = decide(method, target, headers, body, True, secret, int(time.time()), recent)
        client.sendall(http_response(int(decision["status"])))
        if decision.get("store") and decision.get("email"):
            hit = {
                "email": decision["email"],
                "inbound_tag": decision.get("inbound_tag"),
                "source": decision.get("source"),
                "seen_at": int(time.time()),
            }
            with self._lock:
                self._recent[str(decision["email"])] = hit["seen_at"]
                self._hits.append(hit)


def _read_head(client: Any) -> bytes | None:
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > HEADER_LIMIT:
            return None
        chunk = client.recv(1024)
        if not chunk:
            break
        data += chunk
    return data if b"\r\n\r\n" in data else None


def _read_body(client: Any, prefetched: bytes, length: int) -> bytes:
    body = prefetched[:length]
    while len(body) < length:
        chunk = client.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return body


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]] | None:
    try:
        text = head.decode("iso-8859-1")
    except UnicodeError:
        return None
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3 or not parts[2].startswith("HTTP/1."):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return parts[0], parts[1], headers
