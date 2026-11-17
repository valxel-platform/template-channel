from __future__ import annotations

from xml.etree import ElementTree as ET

import httpx

from deployed import smoke

from .conftest import ROOT


def run(tmp_path, monkeypatch, post, get):
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Response(post(url)))
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Response(get(url)))
    out = tmp_path / "s.xml"
    code = smoke.main(
        ["--base-url", "https://chat.test/", "--config", str(ROOT / "channel.yaml"), "--junit", str(out)]
    )
    return code, ET.fromstring(out.read_text())  # noqa: S314 - our own file


def test_a_locked_down_service_passes(tmp_path, monkeypatch):
    code, suite = run(tmp_path, monkeypatch, lambda u: 401, lambda u: 404)
    assert code == 0 and suite.get("tests") == "7"


def test_an_open_channel_or_exposed_metrics_fail(tmp_path, monkeypatch):
    code, _ = run(tmp_path, monkeypatch, lambda u: 200 if u.endswith("/sms") else 401, lambda u: 404)
    assert code == 1
    code, _ = run(tmp_path, monkeypatch, lambda u: 401, lambda u: 200 if u.endswith("/metrics") else 404)
    assert code == 1
