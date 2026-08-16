from __future__ import annotations

import json

import httpx
import pytest

from agent.update import (
    check_for_update,
    fetch_latest_release,
    normalize_version,
    parse_version_tuple,
    version_is_newer,
)


def test_version_compare():
    assert normalize_version("v1.2.3") == "1.2.3"
    assert parse_version_tuple("1.2.3") == (1, 2, 3)
    assert version_is_newer("0.2.0", "0.1.0")
    assert not version_is_newer("0.1.0", "0.1.0")
    assert not version_is_newer("0.1.0", "0.2.0")


def test_fetch_latest_release(monkeypatch):
    payload = {
        "tag_name": "v0.2.0",
        "html_url": "https://github.com/LordDeveloper/agent/releases/tag/v0.2.0",
        "assets": [
            {
                "id": 42,
                "name": "agent-linux-amd64",
                "browser_download_url": "https://example.invalid/agent",
            }
        ],
    }

    class FakeResponse:
        status_code = 200

        def json(self):
            return payload

        @property
        def text(self):
            return json.dumps(payload)

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, headers=None):
            assert "releases/latest" in url
            assert headers["Authorization"] == "Bearer secret-token"
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    release = fetch_latest_release(repo="LordDeveloper/agent", token="secret-token")
    assert release.version == "0.2.0"
    assert release.asset_id == 42


def test_check_for_update(monkeypatch):
    monkeypatch.setattr(
        "agent.update.fetch_latest_release",
        lambda **kwargs: type(
            "R",
            (),
            {
                "tag": "v0.2.0",
                "version": "0.2.0",
                "asset_name": "agent-linux-amd64",
                "asset_id": 1,
                "asset_url": "https://api.github.com/x",
                "html_url": "https://github.com/x",
            },
        )(),
    )
    result = check_for_update(current="0.1.0")
    assert result["update_available"] is True
    assert result["latest_version"] == "0.2.0"


def test_cli_update_check(monkeypatch, capsys):
    from agent.cli import main

    monkeypatch.setattr(
        "agent.cli.check_for_update",
        lambda **kwargs: {
            "current_version": "0.1.0",
            "latest_version": "0.2.0",
            "update_available": True,
            "latest_tag": "v0.2.0",
            "asset": "agent-linux-amd64",
            "release_url": "https://example",
            "repo": "LordDeveloper/agent",
        },
    )
    assert main(["update", "--check"]) == 0
    out = capsys.readouterr().out
    assert '"update_available": true' in out.lower() or '"update_available": true' in out
