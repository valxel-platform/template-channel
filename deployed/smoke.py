"""Checks a deployed channel service from outside, and writes JUnit for the post-deploy report.

What the outside can reach is the point: each channel refuses a message without its provider's
signature (401), confirming a link needs a person's token (401), and /healthz, /readyz and /metrics
aren't routed outside the cluster. Sends no valid message, so it is safe in production.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx

from channel.config import load


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--config", default="channel.yaml")
    ap.add_argument("--junit", default="reports/deployed-smoke.xml")
    args = ap.parse_args(argv)
    base = args.base_url.rstrip("/")
    cfg = load(args.config)
    checks: dict[str, Callable[[], bool]] = {}
    for kind, channel in cfg.channels.items():
        checks[f"{kind}: unsigned messages are refused"] = lambda p=channel.path: (  # type: ignore[misc]
            httpx.post(f"{base}{p}", content=b"{}", timeout=10).status_code == 401
        )
    checks["links need a person's token"] = lambda: (
        httpx.post(f"{base}/links/smoke/confirm", timeout=10).status_code == 401
    )
    for path in ("/healthz", "/readyz", "/metrics"):
        checks[f"{path} isn't reachable from outside"] = lambda p=path: (  # type: ignore[misc]
            httpx.get(f"{base}{p}", timeout=10).status_code in (403, 404)
        )
    suite = ET.Element("testsuite", name="smoke")
    failed = 0
    for name, check in checks.items():
        t0 = time.monotonic()
        try:
            ok = check()
        except Exception:  # noqa: BLE001  (an unreachable service is a failed check)
            ok = False
        tc = ET.SubElement(
            suite, "testcase", classname="smoke", name=name, time=f"{time.monotonic() - t0:.3f}"
        )
        if not ok:
            failed += 1
            ET.SubElement(tc, "failure", message=f"{name} failed at {base}")
        print(f"{'pass' if ok else 'FAIL'}  {name}")
    suite.set("tests", str(len(checks)))
    suite.set("failures", str(failed))
    Path(args.junit).parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(args.junit, encoding="utf-8", xml_declaration=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
