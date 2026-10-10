"""Latency benchmark: token issuance at the gateway and local verification in a bank system.

Usage: python tools/benchmark.py [N]   (in-process, single thread; numbers are per request)
Note: the development JSON-file store rewrites the state file on every audit event, so issuance
latency grows with state size; a database-backed store removes that cost.
"""
from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import gateway.app as gw  # noqa: E402
from helpers import World  # noqa: E402


def pct(values: list[float], p: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, int(p * len(values)))]


def main(n: int) -> None:
    gw.AGENT_RATE_LIMIT = 10**9
    w = World(Path(tempfile.mkdtemp()))
    v = w.verifier()
    issue_ms, verify_ms, tokens = [], [], []
    for i in range(n):
        t0 = time.perf_counter()
        r = w.agent_post("/v1/authorize", {"action": "users.select", "params": {"limit": i % 50}})
        issue_ms.append((time.perf_counter() - t0) * 1000)
        tokens.append((r.json()["action_token"], i % 50))
    v.policy()  # warm JWKS + policy cache, as in steady state
    for token, limit in tokens:
        proof = w.agent.proof("GET", "http://bank/users", token)
        t0 = time.perf_counter()
        v.verify_action(token, proof, method="GET", url="http://bank/users", action="users.select", params={"limit": limit})
        verify_ms.append((time.perf_counter() - t0) * 1000)
    for name, data in (("gateway issuance (HTTP, signed agent request, policy, audit)", issue_ms),
                       ("bank-side local verification (signature, PoP, single use, policy)", verify_ms)):
        print(f"{name}\n  n={len(data)}  p50={statistics.median(data):.2f} ms  p95={pct(data, .95):.2f} ms  p99={pct(data, .99):.2f} ms")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 300)
