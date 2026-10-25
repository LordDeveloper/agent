# Agent PROJECT_CONTEXT

Future changes to this node agent follow this file. The process is an async service (FastAPI + asyncio). **No synchronous I/O in `src/agent`** — use native async drivers (`aiosqlite`, `aiofiles`, `httpx.AsyncClient`, `process.run`).

## Execution model

- I/O methods are `async def`: store, driver commands, subprocess, HTTP to Xray, DNS, systemd.
- Async callers `await` the result. A coroutine is not a dict. Never call `.get()`, iterate, or subscript it.
- CLI / menu entry points call `asyncio.run(...)` (or `run_sync(...)` for one coroutine) and use the same async stack as the server — no sync `Store`, no `subprocess.run`, no `asyncio.to_thread` for I/O.
- `maybe_await()` is for a value that might already be a dict or might be a coroutine. It is not a substitute for `await` on a known async call.

```python
report = await driver.diagnose_address(address)          # async route / driver
report = run_sync(driver.diagnose_address(address))      # CLI / menu (top-level only)
```

`await obj.method()[key]` is wrong. Subscript binds first and crashes on the coroutine. Use `(await obj.method())[key]`.

## Bulk work

Independent I/O that does not need to run in order uses `gather_independent` or `bounded_gather` (`agent/asyncutil.py`). One 15ms call for 100 peers is one wave, not 1500ms.

Use that for:

- key generation, DNS lookups, per-client stats when a grouped query is missing
- per-core snapshots, per-interface `wg show`, per-tunnel start/stop
- Xray user add/remove requests that do not share one lock

Do **not** fan out work that mutates one shared resource. Stage every row, then apply once:

| Path | Stage | One commit |
|---|---|---|
| WireGuard / Amnezia `batch_peers` | mutate the interface document; mint missing keypairs with `bounded_gather` | one `wg syncconf` / `wg-quick` |
| L2TP `batch_users` | `add_user` / `update_user` with `apply=False` | one `_commit_user_runtime()` |
| OpenVPN `batch_users` | same | one passwd/CCD write + egress sync |
| Xray `batch_clients` | classify rows in memory | one grouped traffic read, then bulk `add_users` / `edit_users` |

A per-row response (succeeded / failed / errors) is still returned. The expensive side effect is not repeated per row.

When a single grouped call exists, use it. Xray renewal baselines come from `stats_query_grouped` (`_user_traffic_index`). Per-user `stats_query` runs only as a parallel fallback when that index is empty.

`XrayDriver._api_call` uses the async HTTP client (`maybe_await` only). Do not call blocking functions inside `bounded_gather` tasks.

## What stays serial

- IP allocation inside one subnet (shared `used_ips`)
- ordered bring-up of a single interface (`wg-quick down` then `up`)
- writing one shared systemd unit file (`daemon-reload`) before per-instance enables
- anything that holds `self._inbound_lock` for the same Xray tag

## When you add a feature

1. If it talks to a process, socket, or disk that can block, it is `async def`.
2. Call it with `await` from async code, or `run_sync` from CLI/menu.
3. If the new work is a loop over peers, users, or clients, decide first: independent I/O (`bounded_gather`) or one shared config (stage, then one commit).
4. Extend `tests/test_async_boundaries.py` or the driver batch test when the new path is a sync entry point or a bulk commit.
