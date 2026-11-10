from __future__ import annotations

import os
import socket


def systemd_notify(state: str) -> bool:
    """Send a state string to systemd (READY=1, etc.) when NOTIFY_SOCKET is set."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    path = addr
    if path.startswith("@"):
        path = "\0" + path[1:]
    payload = state.encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(path)
        sock.sendall(payload)
        return True
    except OSError:
        return False
    finally:
        sock.close()
