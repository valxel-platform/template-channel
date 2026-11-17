"""Each provider's message format in, and its API out.

Inbound parsing only runs after verify.py has accepted the request. It keeps what the product needs:
who sent it (the address, which is hashed and sealed straight away), the text, the provider's
message id (for dedupe) and, for Teams, where to reply.

Outbound calls go through `Egress`: https, to the kind's provider hosts only (config.HOSTS), no
redirects, a timeout. Credentials come from mounted secrets and are never logged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx

from .config import HOSTS, Channel
from .secrets import Secrets


@dataclass(frozen=True)
class Message:
    kind: str
    address: str  # what identifies the sender at the provider
    text: str
    external_id: str
    reply_to: str = ""  # Teams: where replies go (JSON), sealed with the address


class Skip(Exception):
    def __init__(self, answer: dict[str, Any] | None = None) -> None:
        super().__init__("no message")
        self.answer = answer or {}


class Refused(Exception):
    """A reply the provider won't take; the message never contains the text or address."""


class Disallowed(RuntimeError):
    pass


def form(body: bytes) -> dict[str, str]:
    return dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))


def parse(kind: str, body: bytes) -> Message:
    if kind == "slack":
        raw = json.loads(body)
        if raw.get("type") == "url_verification":
            raise Skip({"challenge": str(raw.get("challenge", ""))[:100]})
        ev = raw.get("event") or {}
        if (
            raw.get("type") != "event_callback"
            or ev.get("type") != "message"
            or ev.get("bot_id")
            or ev.get("subtype")
        ):
            raise Skip()
        return Message(
            "slack", f"{raw['team_id']}:{ev['user']}", str(ev.get("text", "")), str(raw["event_id"])
        )
    if kind == "sms":
        f = form(body)
        return Message("sms", f["From"], f.get("Body", ""), f["MessageSid"])
    if kind == "email":
        f = form(body)
        text = f.get("stripped-text") or f.get("body-plain") or ""
        return Message("email", f["sender"], text, f.get("Message-Id") or f["token"])
    if kind == "teams":
        a = json.loads(body)
        if a.get("type") != "message":
            raise Skip()
        sender = a.get("from") or {}
        service = str(a.get("serviceUrl") or "")
        if (urlparse(service).hostname or "") not in HOSTS["teams"]:
            raise ValueError("serviceUrl isn't a Bot Framework host")
        where = json.dumps(
            {"serviceUrl": service, "conversation": (a.get("conversation") or {}).get("id", "")}
        )
        return Message(
            "teams",
            str(sender.get("aadObjectId") or sender["id"]),
            str(a.get("text", "")),
            str(a["id"]),
            where,
        )
    raise ValueError(f"unknown kind {kind}")


class Egress:
    def __init__(
        self, kind: str, *, transport: httpx.BaseTransport | None = None, timeout_s: float = 10.0
    ) -> None:
        self.hosts = HOSTS[kind]
        kw: dict[str, Any] = {"timeout": timeout_s, "follow_redirects": False, "trust_env": False}
        if transport is not None:
            kw["transport"] = transport
        self.http = httpx.Client(**kw)

    def post(self, url: str, **kw: Any) -> httpx.Response:
        parsed = urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "") not in self.hosts:
            raise Disallowed(f"{parsed.hostname}: not a provider host for this channel")
        resp = self.http.post(url, **kw)
        if resp.status_code == 429 or resp.status_code >= 500:
            raise httpx.HTTPStatusError("provider unavailable", request=resp.request, response=resp)
        if resp.status_code >= 300:
            raise Refused(f"the provider answered {resp.status_code}")
        return resp


class Sender:
    """Sends one reply on one channel."""

    def __init__(
        self, channel: Channel, secrets: Secrets, *, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.channel, self.secrets = channel, secrets
        self.out = Egress(channel.kind, transport=transport)

    def _secret(self, name: str) -> str:
        return self.secrets.current(self.channel.secrets[name])

    def send(self, address: str, text: str, subject: str = "") -> None:
        kind = self.channel.kind
        if kind == "slack":
            user = address.split(":", 1)[-1]
            resp = self.out.post(
                "https://slack.com/api/chat.postMessage",
                json={"channel": user, "text": text},
                headers={"Authorization": f"Bearer {self._secret('token')}"},
            )
            if not resp.json().get("ok"):
                raise Refused(f"slack refused the message ({resp.json().get('error', 'unknown')})")
        elif kind == "sms":
            sid = self._secret("account_sid")
            self.out.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                data={"From": self.channel.sender, "To": address, "Body": text},
                auth=(sid, self._secret("auth_token")),
            )
        elif kind == "email":
            domain = self.channel.sender.rsplit("@", 1)[-1]
            self.out.post(
                f"https://api.mailgun.net/v3/{domain}/messages",
                auth=("api", self._secret("api_key")),
                data={
                    "from": self.channel.sender,
                    "to": address,
                    "subject": subject or "A new message",
                    "text": text,
                },
            )
        elif kind == "teams":
            where = json.loads(address)
            token = self.out.post(
                "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._secret("app_id"),
                    "client_secret": self._secret("app_password"),
                    "scope": "https://api.botframework.com/.default",
                },
            ).json()["access_token"]
            base = where["serviceUrl"].rstrip("/")
            self.out.post(
                f"{base}/v3/conversations/{where['conversation']}/activities",
                json={"type": "message", "text": text},
                headers={"Authorization": f"Bearer {token}"},
            )
