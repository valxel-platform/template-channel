from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from channel.app import build, create_app
from channel.audit import Auditor, MemorySink
from channel.settings import Settings
from channel.store import MemoryStore
from channel.verify import mailgun_signature, twilio_signature

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = "https://chat.example-clinic.test"
SECRETS = {
    "slack-signing": "slack-secret",
    "slack-bot-token": "xoxb-synthetic",
    "twilio-auth-token": "tw-token",
    "twilio-account-sid": "AC0000",
    "mailgun-signing": "mg-signing",
    "mailgun-api-key": "mg-key",
    "address-pepper": "pepper-synthetic",
    "address-key": Fernet.generate_key().decode(),
}
PEOPLE = {
    "nurse": {"sub": "nurse-7", "azp": "emr-bff", "organization": {"north-clinic": {}}},
    "two-orgs": {"sub": "y", "azp": "emr-bff", "organization": ["a", "b"]},
}
PHONE = "+15555550123"


class FakeVerifier:
    def verify(self, token: str) -> dict[str, Any] | None:
        return PEOPLE.get(token)


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail: Exception | None = None

    def send(self, address: str, text: str, subject: str = "") -> None:
        if self.fail:
            raise self.fail
        self.sent.append((address, text))


class Env:
    def __init__(self, tmp: Path) -> None:
        d = tmp / "secrets"
        d.mkdir()
        for k, v in SECRETS.items():
            (d / k).write_text(v + "\n")
        self.secrets_dir = d
        self.settings = Settings(
            config_path=str(ROOT / "channel.yaml"),
            contracts_dir=str(ROOT / "contracts"),
            secrets_dir=str(d),
            public_url=PUBLIC,
            product="Example Clinic",
        )
        self.sink = MemorySink()
        self.auditor = Auditor(
            self.sink, service="channel", product="emr", environment="test", data_class="phi"
        )
        self.store = MemoryStore()
        self.senders = {k: FakeSender() for k in ("slack", "sms", "email")}
        self.rt = build(
            self.settings,
            store=self.store,
            auditor=self.auditor,
            verifier=FakeVerifier(),
            senders=self.senders,
        )  # type: ignore[arg-type]
        self.client = TestClient(create_app(self.settings, runtime=self.rt, workers=False))

    # Providers, signing as they do.
    def slack(
        self,
        text: str,
        event_id: str = "Ev1",
        user: str = "U1",
        stamp: int | None = None,
        secret: str = SECRETS["slack-signing"],
    ) -> Any:
        import hashlib
        import hmac

        body = json.dumps(
            {
                "type": "event_callback",
                "team_id": "T1",
                "event_id": event_id,
                "event": {"type": "message", "user": user, "text": text},
            }
        ).encode()
        ts = str(stamp or int(time.time()))
        sig = (
            "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
        )
        return self.client.post(
            "/channels/slack",
            content=body,
            headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig},
        )

    def sms(
        self, text: str, sid: str = "SM1", sender: str = PHONE, token: str = SECRETS["twilio-auth-token"]
    ) -> Any:
        params = {"From": sender, "To": "+15555550100", "Body": text, "MessageSid": sid}
        sig = twilio_signature(token, f"{PUBLIC}/channels/sms", params)
        return self.client.post("/channels/sms", data=params, headers={"X-Twilio-Signature": sig})

    def email(self, text: str, token: str = "tok1", stamp: int | None = None) -> Any:  # noqa: S107
        ts = str(stamp or int(time.time()))
        params = {
            "sender": "pat@example.test",
            "stripped-text": text,
            "Message-Id": f"<{token}@x>",
            "timestamp": ts,
            "token": token,
            "signature": mailgun_signature(SECRETS["mailgun-signing"], ts, token),
        }
        return self.client.post("/channels/email", data=params)

    def link(self, kind: str = "slack", who: str = "nurse") -> Any:
        sent = self.senders[kind].sent[-1][1]
        nonce = sent.split("nonce=", 1)[1]
        return self.client.post(f"/links/{nonce}/confirm", headers={"Authorization": f"Bearer {who}"})


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)
