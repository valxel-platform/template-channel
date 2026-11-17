"""channel.yaml: which channels the product talks on, how each proves who's calling, and what may
be said on it. People approve it at G4 with the design's Channels section.

    name: template-channel
    data_class: phi
    link_url: https://app.example-clinic.test/link     # where people sign in to link a channel
    received: conversation-message-received            # the dataset messages are published under
    replies: conversation-reply                         # the dataset of replies to send
    channels:
      - kind: slack                  # slack | teams | sms | email
        content: full                # full | notice ("you have a new message; sign in to read it")
        baa: true                    # PHI in full needs a BAA with the provider
        secrets: { signing: slack-signing, token: slack-bot-token }
        rate_per_minute: 30          # messages one person may send
      - kind: sms
        content: notice
        baa: false
        from: "+15555550100"         # the product's number (synthetic)
        secrets: { auth_token: twilio-auth-token, account_sid: twilio-account-sid }

Each kind's provider hosts are fixed here (HOSTS); outbound calls go nowhere else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

KINDS = ("slack", "teams", "sms", "email")
# The secrets each kind needs (mounted files, by name).
NEEDS = {
    "slack": ("signing", "token"),
    "teams": ("app_id", "app_password"),
    "sms": ("auth_token", "account_sid"),
    "email": ("signing", "api_key"),
}
HOSTS = {
    "slack": ("slack.com",),
    "teams": ("login.microsoftonline.com", "smba.trafficmanager.net"),
    "sms": ("api.twilio.com",),
    "email": ("api.mailgun.net",),
}
DATA_CLASSES = ("general", "payments", "phi")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_SECRET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Channel:
    kind: str
    content: str
    baa: bool
    secrets: dict[str, str]
    rate_per_minute: int = 30
    sender: str = ""  # the product's number or address (sms, email)
    path: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", f"/channels/{self.kind}")


@dataclass(frozen=True)
class Config:
    name: str
    data_class: str
    link_url: str
    received: str
    replies: str
    channels: dict[str, Channel] = field(default_factory=dict)

    @property
    def secret_names(self) -> list[str]:
        return sorted({v for c in self.channels.values() for v in c.secrets.values()})


def parse(raw: dict[str, Any]) -> Config:
    problems: list[str] = []
    name, data_class = str(raw.get("name") or ""), str(raw.get("data_class") or "")
    if not _NAME.match(name):
        problems.append("name must be the component's name")
    if data_class not in DATA_CLASSES:
        problems.append(f"data_class must be one of {', '.join(DATA_CLASSES)}")
    link = urlparse(str(raw.get("link_url") or ""))
    if link.scheme != "https" or not link.hostname:
        problems.append("link_url must be the product's https page where people sign in to link a channel")
    received, replies = str(raw.get("received") or ""), str(raw.get("replies") or "")
    for key, value in (("received", received), ("replies", replies)):
        if not _NAME.match(value):
            problems.append(f"{key} names a dataset (its contract is in contracts/)")
    channels: dict[str, Channel] = {}
    for i, c in enumerate(raw.get("channels") or []):
        where = f"channels[{i}]"
        kind = str(c.get("kind") or "")
        if kind not in KINDS or kind in channels:
            problems.append(f"{where}: kind must be one of {', '.join(KINDS)}, once each")
            continue
        content, baa = str(c.get("content") or ""), bool(c.get("baa", False))
        if content not in ("full", "notice"):
            problems.append(f"{where}: content is full or notice")
        if data_class == "phi" and content == "full" and not baa:
            problems.append(
                f"{where}: {kind} carries PHI in full only with a BAA with the provider (baa: true), "
                "or use content: notice"
            )
        secrets = {str(k): str(v) for k, v in (c.get("secrets") or {}).items()}
        missing = [n for n in NEEDS[kind] if not _SECRET.match(secrets.get(n, ""))]
        if missing:
            problems.append(f"{where}: name the mounted secrets {', '.join(missing)} (never their values)")
        sender = str(c.get("from") or "")
        if kind in ("sms", "email") and not sender:
            problems.append(f"{where}: from is the product's {'number' if kind == 'sms' else 'address'}")
        rate = int(c.get("rate_per_minute", 30))
        if not 1 <= rate <= 600:
            problems.append(f"{where}: rate_per_minute must be 1-600")
        channels[kind] = Channel(kind, content, baa, secrets, rate, sender)
    if not channels:
        problems.append("name at least one channel")
    if problems:
        raise ConfigError("channel.yaml: " + "; ".join(problems))
    return Config(name, data_class, str(raw["link_url"]), received, replies, channels)


def load(path: str) -> Config:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"channel.yaml isn't YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("channel.yaml must be a mapping")
    return parse(raw)
