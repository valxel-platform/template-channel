"""Messages in: provider signatures, dedupe, linking, consent and what reaches the product."""

from __future__ import annotations

import json
import time

import pytest

from .conftest import PHONE, SECRETS


def test_an_unlinked_person_gets_a_sign_in_link_and_reaches_nothing(env):
    r = env.slack("what's my next appointment?")
    assert r.status_code == 200 and env.store.claim() == []
    [(address, text)] = env.senders["slack"].sent
    assert address == "T1:U1" and "https://app.example-clinic.test/link?nonce=" in text
    nonce = text.split("nonce=", 1)[1]
    assert nonce not in json.dumps(list(env.store.links))  # only its hash is kept


def test_linking_then_messages_reach_the_product_once(env):
    env.slack("hello")
    nonce = env.senders["slack"].sent[-1][1].split("nonce=", 1)[1]
    r = env.link()
    assert r.status_code == 200 and r.json() == {"linked": True, "channel": "slack"}
    assert "signed in" in env.senders["slack"].sent[-1][1]
    again = env.client.post(f"/links/{nonce}/confirm", headers={"Authorization": "Bearer nurse"})
    assert again.status_code == 404  # single use
    env.slack("my knee still hurts", event_id="Ev2")
    env.slack("my knee still hurts", event_id="Ev2")  # Slack's retry
    [q] = env.store.claim()
    data = q.value["data"]
    assert (data["user_id"], data["tenant"], data["channel"], data["text"]) == (
        "nurse-7",
        "north-clinic",
        "slack",
        "my knee still hurts",
    )
    assert q.topic == "emr.conversation-message-received.v1" and q.key == "nurse-7"
    linked = [e for e in env.sink.events if e["data"]["action"] == "channel.linked"]
    assert linked and linked[0]["data"]["actor"]["id"] == "nurse-7"
    assert "U1" not in json.dumps(env.sink.events) and "T1:U1" not in json.dumps(q.value)


@pytest.mark.parametrize("change", [{"secret": "wrong"}, {"stamp": int(time.time()) - 301}])
def test_bad_slack_signatures_and_replays_are_401(env, caplog, change):
    r = env.slack("hi", **change)
    assert (r.status_code, r.json()) == (401, {"error": "unauthorized"})
    assert env.senders["slack"].sent == [] and "channel.signature_rejected kind=slack" in caplog.text


def test_slack_url_verification_answers_only_when_signed(env):
    import hashlib
    import hmac

    body = json.dumps({"type": "url_verification", "challenge": "c-123"}).encode()
    ts = str(int(time.time()))
    sig = (
        "v0="
        + hmac.new(
            SECRETS["slack-signing"].encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    ok = env.client.post(
        "/channels/slack", content=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}
    )
    assert ok.json() == {"challenge": "c-123"}
    assert env.client.post("/channels/slack", content=body).status_code == 401


def test_sms_stop_start_and_help_are_always_answered(env):
    assert env.sms("hi", sid="SM0", token="wrong").status_code == 401
    env.sms("STOP", sid="SM1")
    [ident] = env.store.identities.values()
    assert ident.consent == "out" and "won't get more messages" in env.senders["sms"].sent[-1][1]
    env.sms("help", sid="SM2")
    assert "Reply STOP" in env.senders["sms"].sent[-1][1]
    env.sms("Start", sid="SM3")
    assert next(iter(env.store.identities.values())).consent == "in"
    assert [e["data"]["reason"] for e in env.sink.events if e["data"]["action"] == "channel.consent"] == [
        "out",
        "in",
    ]
    assert PHONE not in json.dumps(env.sink.events)  # never the number


def test_addresses_are_hashed_and_sealed(env):
    env.sms("hi")
    [ident] = env.store.identities.values()
    assert PHONE not in ident.lookup and PHONE not in ident.sealed
    assert env.rt.receiver.addresses.open(ident.sealed) == PHONE


def test_email_tokens_are_single_use(env):
    assert env.email("hello", token="t-1").status_code == 200
    assert env.email("hello", token="t-1").status_code == 401  # a replayed signature
    assert env.email("hello", token="t-2", stamp=int(time.time()) - 1000).status_code == 401


def test_rate_limit_per_person(env):
    env.sms("hi", sid="S0")
    env.link("sms")
    for i in range(12):
        env.sms(f"msg {i}", sid=f"S{i + 1}")
    assert len(env.store.claim()) == 10  # rate_per_minute: 10 for sms


def test_large_or_unreadable_bodies(env):
    assert env.client.post("/channels/slack", content=b"x" * (300 * 1024)).status_code == 413
    import hashlib
    import hmac

    body, ts = b"not json", str(int(time.time()))
    sig = (
        "v0="
        + hmac.new(
            SECRETS["slack-signing"].encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    r = env.client.post(
        "/channels/slack", content=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}
    )
    assert r.status_code == 400


def test_link_confirmation_needs_one_organization_and_a_token(env):
    env.slack("hello")
    assert env.link(who="two-orgs").status_code == 422
    nonce = env.senders["slack"].sent[-1][1].split("nonce=", 1)[1]
    assert env.client.post(f"/links/{nonce}/confirm").status_code == 401
    assert (
        env.client.post("/links/nope/confirm", headers={"Authorization": "Bearer nurse"}).status_code == 404
    )


def test_no_audit_record_means_no_link(env):
    env.slack("hello")
    env.sink.fail = True
    assert env.link().status_code == 503
    assert next(iter(env.store.identities.values())).user_id == ""


def test_health_and_routes(env):
    assert env.client.get("/healthz").json() == {"status": "ok"}
    assert env.client.get("/readyz").status_code == 200
    assert env.client.post("/channels/teams").status_code == 404  # not configured
    assert env.client.get("/docs").status_code == 404 and "valxel_events" in env.client.get("/metrics").text


def test_an_unmounted_signing_secret_refuses_everything(env, caplog):
    (env.secrets_dir / "slack-signing").unlink()
    assert env.slack("hi").status_code == 401 and "secrets aren't mounted" in caplog.text


def test_readyz_names_a_stopped_worker(env):
    class Dead:
        name = "replies"

        def is_alive(self):
            return False

    env.rt.threads.append(Dead())
    assert env.client.get("/readyz").json() == {"status": "not ready", "stopped": ["replies"]}


def test_teams_messages_are_verified_by_token_and_replies_go_where_it_says(env):
    from dataclasses import replace

    from channel.config import Channel

    from .conftest import FakeSender

    r = env.rt.receiver
    r.cfg = replace(r.cfg, channels={**r.cfg.channels, "teams": Channel("teams", "full", True, {})})
    r.senders["teams"] = FakeSender()
    r.teams = lambda headers: headers.get("authorization") == "Bearer good"
    activity = json.dumps(
        {
            "type": "message",
            "id": "a-1",
            "text": "hi",
            "from": {"id": "29:x", "aadObjectId": "aad-1"},
            "conversation": {"id": "c-1"},
            "serviceUrl": "https://smba.trafficmanager.net/amer/",
        }
    ).encode()
    assert r.receive("teams", {"Authorization": "Bearer bad"}, activity).status == 401
    assert r.receive("teams", {"Authorization": "Bearer good"}, activity).status == 200
    [(where, text)] = r.senders["teams"].sent
    assert json.loads(where)["conversation"] == "c-1" and "nonce=" in text
    assert r.receive("teams", {"Authorization": "Bearer good"}, b"{}").status == 200  # no message: answered


def test_link_offers_cant_be_used_to_run_up_a_texting_bill(env, caplog):
    env.sms("hi", sid="A1")
    env.sms("hi again", sid="A2")
    assert len(env.senders["sms"].sent) == 1  # their open link still works: no second text
    env.rt.receiver.link_offers_per_minute = 3
    for i in range(10):  # a flood from spoofed numbers
        env.sms("hi", sid=f"B{i}", sender=f"+1555000{i:04d}")
    assert len(env.senders["sms"].sent) == 3 and "channel.link_offers_limited kind=sms" in caplog.text


def test_the_example_feature_is_behind_its_flag(env):
    """The pattern every feature follows: its new behaviour reads its flag, and off is today's."""
    from openfeature.provider.in_memory_provider import InMemoryFlag, InMemoryProvider

    from channel import flags
    from channel.service import example_flag

    assert (
        example_flag("emr") == "emr.example.help-start-hint"
        and example_flag("") == "example.example.help-start-hint"
    )
    env.sms("help", sid="SM10")
    assert "Reply START" not in env.senders["sms"].sent[-1][1]
    on = InMemoryFlag("on", {"on": True, "off": False})
    flags.use_provider(InMemoryProvider({example_flag(env.settings.product): on}))
    try:
        env.sms("help", sid="SM11")
        assert env.senders["sms"].sent[-1][1].endswith("Reply START to get them again.")
    finally:
        flags.use_provider(InMemoryProvider({}))
