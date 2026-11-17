from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from channel.app import start_workers
from channel.auth import JwtVerifier, tenants
from channel.contracts import summary_line
from channel.relay import Relay

from .fakes import Producer


def test_the_relay_publishes_received_messages(env):
    env.slack("hi")
    env.link()
    env.slack("a question", event_id="Ev9")
    summary_line()
    with pytest.raises(RuntimeError, match="acknowledged"):
        Relay(env.store, env.rt.receiver.contracts, Producer(fail=True)).step()
    producer = Producer()
    assert Relay(env.store, env.rt.receiver.contracts, producer).step() == 1
    assert producer.sent[0]["key"] == b"nurse-7"
    assert summary_line() == 'valxel.datasets {"conversation-message-received":{"published":1}}'


def test_link_tokens_are_checked_for_signature_issuer_and_audience(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Jwks:
        def __init__(self, url, cache_keys):
            pass

        def get_signing_key_from_jwt(self, token):
            return type("K", (), {"key": key.public_key()})()

    monkeypatch.setattr(jwt, "PyJWKClient", Jwks)
    v = JwtVerifier(issuer="https://idp.test", jwks_url="https://idp.test/certs", audience="channel")
    claims = {"iss": "https://idp.test", "aud": "channel", "sub": "nurse-7", "exp": int(time.time()) + 60}
    assert v.verify(jwt.encode(claims, key, algorithm="RS256"))["sub"] == "nurse-7"
    assert v.verify(jwt.encode({**claims, "aud": "other"}, key, algorithm="RS256")) is None
    with pytest.raises(RuntimeError, match="CHANNEL_OIDC"):
        JwtVerifier(issuer="", jwks_url="", audience="x")
    assert tenants({"organization": "a"}, "organization") == frozenset({"a"})


def test_without_kafka_no_workers_start(env, caplog):
    start_workers(env.rt)
    assert env.rt.threads == [] and "outbox" in caplog.text
