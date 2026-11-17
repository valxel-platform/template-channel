"""Senders, Teams tokens, the policy file, address keys and start-up."""

from __future__ import annotations

import json
import os
import time

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa

from channel.app import build
from channel.config import Channel, ConfigError, load, parse
from channel.crypto import KEY, Addresses
from channel.providers import Disallowed, Refused, Sender, Skip
from channel.providers import parse as parse_message
from channel.secrets import Secrets
from channel.verify import TeamsVerifier

from .conftest import ROOT


def sender(env, kind, handler, **over):
    base = env.rt.cfg.channels.get(kind) or Channel(
        "teams", "full", True, {"app_id": "slack-signing", "app_password": "slack-bot-token"}
    )
    channel = Channel(**{**base.__dict__, **over}) if over else base
    return Sender(channel, Secrets(str(env.secrets_dir)), transport=httpx.MockTransport(handler))


def test_each_provider_is_called_where_and_how_it_expects(env):
    seen = []

    def ok(request):
        seen.append(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "bot-token"})
        return httpx.Response(200, json={"ok": True})

    sender(env, "slack", ok).send("T1:U1", "hi")
    sender(env, "sms", ok).send("+15555550123", "hi")
    sender(env, "email", ok).send("pat@example.test", "hi", subject="Clinic")
    where = json.dumps({"serviceUrl": "https://smba.trafficmanager.net/amer/", "conversation": "a:1"})
    sender(env, "teams", ok).send(where, "hi")
    urls = [str(r.url) for r in seen]
    assert urls == [
        "https://slack.com/api/chat.postMessage",
        "https://api.twilio.com/2010-04-01/Accounts/AC0000/Messages.json",
        "https://api.mailgun.net/v3/mail.example-clinic.test/messages",
        "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token",
        "https://smba.trafficmanager.net/amer/v3/conversations/a:1/activities",
    ]
    assert seen[0].headers["authorization"] == "Bearer xoxb-synthetic"
    assert seen[1].headers["authorization"].startswith("Basic ") and b"To=%2B15555550123" in seen[1].content
    assert seen[4].headers["authorization"] == "Bearer bot-token"


def test_senders_refuse_other_hosts_and_report_provider_answers(env):
    where = json.dumps({"serviceUrl": "https://evil.test/", "conversation": "a"})
    with pytest.raises(Disallowed):
        sender(env, "teams", lambda r: httpx.Response(200, json={"access_token": "t"})).send(where, "hi")
    with pytest.raises(Refused, match="not_in_channel"):
        sender(
            env, "slack", lambda r: httpx.Response(200, json={"ok": False, "error": "not_in_channel"})
        ).send("T:U", "x")
    with pytest.raises(Refused, match="400"):
        sender(env, "sms", lambda r: httpx.Response(400)).send("+1", "x")
    with pytest.raises(httpx.HTTPStatusError):
        sender(env, "email", lambda r: httpx.Response(503)).send("a@b.test", "x")


def test_inbound_parsing_keeps_only_whats_needed():
    with pytest.raises(Skip):
        parse_message(
            "slack",
            json.dumps({"type": "event_callback", "event": {"type": "message", "bot_id": "B"}}).encode(),
        )
    with pytest.raises(ValueError, match="Bot Framework"):
        parse_message(
            "teams",
            json.dumps(
                {"type": "message", "from": {"id": "u"}, "id": "1", "serviceUrl": "https://evil.test/"}
            ).encode(),
        )
    m = parse_message(
        "teams",
        json.dumps(
            {
                "type": "message",
                "from": {"id": "29:x", "aadObjectId": "aad-1"},
                "id": "act-1",
                "text": "hi",
                "conversation": {"id": "c-1"},
                "serviceUrl": "https://smba.trafficmanager.net/emea/",
            }
        ).encode(),
    )
    assert (m.address, m.external_id, json.loads(m.reply_to)["conversation"]) == ("aad-1", "act-1", "c-1")
    with pytest.raises(Skip):
        parse_message("teams", json.dumps({"type": "conversationUpdate"}).encode())


def test_teams_tokens_are_checked_for_issuer_audience_and_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = type(
        "J", (), {"get_signing_key_from_jwt": lambda self, t: type("K", (), {"key": key.public_key()})()}
    )()
    v = TeamsVerifier(lambda: "app-1", jwks=jwks)
    claims = {"iss": TeamsVerifier.ISSUER, "aud": "app-1", "exp": int(time.time()) + 600}
    assert v({"authorization": "Bearer " + jwt.encode(claims, key, algorithm="RS256")})
    assert not v(
        {"authorization": "Bearer " + jwt.encode({**claims, "aud": "other"}, key, algorithm="RS256")}
    )
    assert not v(
        {"authorization": "Bearer " + jwt.encode({**claims, "iss": "https://x"}, key, algorithm="RS256")}
    )
    assert not v({})


def test_the_policy_file_refuses_phi_in_full_without_a_baa():
    raw = {
        "name": "c",
        "data_class": "phi",
        "link_url": "https://app.test/link",
        "received": "a",
        "replies": "b",
        "channels": [
            {
                "kind": "sms",
                "content": "full",
                "baa": False,
                "from": "+1",
                "secrets": {"auth_token": "t", "account_sid": "s"},
            }
        ],
    }
    with pytest.raises(ConfigError, match="BAA"):
        parse(raw)
    bad = {
        "name": "c",
        "data_class": "x",
        "link_url": "http://app.test",
        "received": "A",
        "channels": [
            {"kind": "fax"},
            {"kind": "email", "content": "loud", "secrets": {}, "rate_per_minute": 0},
        ],
    }
    with pytest.raises(ConfigError) as err:
        parse(bad)
    text = str(err.value)
    for says in (
        "data_class",
        "link_url",
        "received",
        "replies",
        "kind must be",
        "content is",
        "mounted secrets",
        "from is",
        "rate_per_minute",
    ):
        assert says in text, says
    assert set(load(str(ROOT / "channel.yaml")).channels) == {"slack", "sms", "email"}


def test_the_address_key_rotates_without_losing_addresses(env):
    a = Addresses(Secrets(str(env.secrets_dir)))
    sealed = a.seal("+15555550123")
    path = env.secrets_dir / KEY
    path.write_text(Fernet.generate_key().decode() + "\n" + path.read_text())
    os.utime(path, (1, 1))
    assert a.open(sealed) == "+15555550123"
    path.write_text(Fernet.generate_key().decode() + "\n")
    os.utime(path, (2, 2))
    with pytest.raises(ValueError, match="rotated"):
        a.open(sealed)
    assert a.lookup("sms", " +1555 ") == a.lookup("sms", "+1555")


def test_start_up_refuses_missing_secrets_contracts_and_deployed_shortcuts(env):
    (env.secrets_dir / "address-pepper").unlink()
    with pytest.raises(RuntimeError, match="address-pepper isn't mounted"):
        build(env.settings)
    (env.secrets_dir / "address-pepper").write_text("p\n")
    for update, says in (
        ({"contracts_dir": "/none"}, "no contract"),
        ({"environment": "production"}, "DATABASE_URL"),
        ({"kafka_bootstrap": "k:9092"}, "TLS"),
    ):
        with pytest.raises(RuntimeError, match=says):
            build(env.settings.model_copy(update=update), verifier=object())  # type: ignore[arg-type]
