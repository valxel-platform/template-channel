"""Messages in, replies out: who may talk to the product, and who it may write to.

In, for each request on /channels/<kind>, in order:
  verify    the provider's signature or token (verify.py); anything else is a bare 401.
  dedupe    the provider's message id: each message is handled at most once; a retry is answered.
  identity  the sender's address, hashed to find their identity and sealed to reply to them.
  keywords  STOP, UNSUBSCRIBE, CANCEL, END, QUIT: consent out (nothing more is sent, but one
            confirmation). START, UNSTOP: consent in. HELP: what this is and how to stop. On every
            channel, always answered, linked or not.
  linked?   no: one reply with a sign-in link carrying a single-use nonce (10 minutes; only its hash
            is stored). The message itself goes nowhere: unlinked people reach nothing in the product.
  rate      per identity (rate_per_minute): over it, the message is dropped and counted.
  publish   linked: the message as the `received` dataset's event (user, tenant, channel, text),
            through the outbox with its dedupe record.

Out (Replies): each `replies` event (user, channel, text) is sent only if that user has a linked
identity on the channel whose consent isn't out (SMS also needs consent in), with content: notice
replacing the text by a sign-in notice. Sent replies are recorded by id so a redelivery isn't sent
twice. Audit: channel.linked, channel.consent, channel.sent, channel.withheld, by identity id only.
"""

from __future__ import annotations

import hashlib
import logging
import secrets as pysecrets
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any

from . import cohorts, events, verify
from .audit import Actor, Auditor
from .config import Config
from .contracts import ContractError, Contracts, count
from .crypto import Addresses
from .providers import Message, Refused, Sender, Skip, form, parse
from .relay_types import Outgoing
from .secrets import SecretMissing, Secrets
from .store import Identity, Store, new_identity, now

log = logging.getLogger("channel.service")
STOP = {"stop", "stopall", "unsubscribe", "cancel", "end", "quit"}
START = {"start", "unstop", "yes"}
HELP = {"help", "info"}
LINK_TTL_S = 600


@dataclass(frozen=True)
class Answer:
    status: int
    body: dict[str, Any]


OK = Answer(200, {"ok": True})
UNAUTHORIZED = Answer(401, {"error": "unauthorized"})


class Window:
    """Messages per identity per minute (per replica)."""

    def __init__(self) -> None:
        self.hits: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str, per_minute: int, at: float) -> bool:
        with self.lock:
            recent = [t for t in self.hits.get(key, []) if at - t < 60]
            ok = len(recent) < per_minute
            self.hits[key] = [*recent, at] if ok else recent
            if len(self.hits) > 50_000:
                self.hits.clear()
            return ok


class Receiver:
    def __init__(
        self,
        cfg: Config,
        secrets: Secrets,
        store: Store,
        contracts: Contracts,
        auditor: Auditor,
        senders: dict[str, Sender],
        *,
        public_url: str,
        source: str,
        product: str,
        teams: Any = None,
        clock: Any = time.time,
    ) -> None:
        self.cfg, self.secrets, self.store, self.contracts, self.auditor = (
            cfg,
            secrets,
            store,
            contracts,
            auditor,
        )
        self.senders, self.public_url, self.source, self.product = (
            senders,
            public_url.rstrip("/"),
            source,
            product,
        )
        self.addresses, self.window, self.clock, self.teams = Addresses(secrets), Window(), clock, teams
        self.service = Actor(id=source.rsplit("/", 1)[-1], type="service")

    # ------------------------------------------------------------------ verification
    def verified(self, kind: str, headers: dict[str, str], body: bytes) -> bool:
        channel = self.cfg.channels[kind]
        try:
            if kind == "slack":
                return verify.slack(
                    self.secrets.values(channel.secrets["signing"]), headers, body, self.clock()
                )
            if kind == "sms":
                return verify.sms(
                    self.secrets.values(channel.secrets["auth_token"]),
                    headers,
                    f"{self.public_url}{channel.path}",
                    form(body),
                )
            if kind == "email":
                return verify.email(
                    self.secrets.values(channel.secrets["signing"]), form(body), self.clock(), self.store.seen
                )
            if kind == "teams":
                return bool(self.teams and self.teams(headers))
        except SecretMissing:
            log.error("channel %s: its secrets aren't mounted; refusing messages", kind)
        return False

    # ------------------------------------------------------------------ in
    def receive(self, kind: str, headers: dict[str, str], body: bytes) -> Answer:
        h = {k.lower(): v for k, v in headers.items()}
        if not self.verified(kind, h, body):
            log.warning("channel.signature_rejected kind=%s", kind)
            events.record("channel.rejected", kind=kind)
            return UNAUTHORIZED
        try:
            msg = parse(kind, body)
        except Skip as skip:
            return Answer(200, skip.answer or {"ok": True})
        except (ValueError, KeyError, TypeError) as exc:
            log.error("channel %s: a verified message couldn't be read (%s)", kind, type(exc).__name__)
            return Answer(400, {"error": "unreadable"})
        with cohorts.item():
            return self._handle(kind, msg)

    def _identity(self, msg: Message) -> Identity:
        lookup = self.addresses.lookup(msg.kind, msg.address)
        found = self.store.identity(msg.kind, lookup)
        sealed = self.addresses.seal(msg.reply_to or msg.address)
        if found is None:
            return self.store.save(new_identity(msg.kind, lookup, sealed))
        if msg.reply_to:  # Teams: where to reply can move
            return self.store.save(replace(found, sealed=sealed))
        return found

    def _audit(
        self,
        action: str,
        ident: Identity,
        outcome: str = "success",
        reason: str = "",
        actor: Actor | None = None,
        **details: Any,
    ) -> None:
        self.auditor.record(
            action,
            actor=actor or self.service,
            resource=("channel-identity", [ident.id]),
            outcome=outcome,  # type: ignore[arg-type]
            reason=reason,
            details={"kind": ident.kind, "user": ident.user_id, **details},
        )

    def _say(self, ident: Identity, text: str) -> None:
        try:
            self.senders[ident.kind].send(self.addresses.open(ident.sealed), text, subject=self.product)
        except Exception as exc:  # noqa: BLE001 - a confirmation that can't go isn't worth failing the request
            log.warning(
                "channel.reply_failed kind=%s identity=%s (%s)", ident.kind, ident.id, type(exc).__name__
            )

    def _handle(self, kind: str, msg: Message) -> Answer:
        channel = self.cfg.channels[kind]
        key = f"{kind}:{msg.external_id}"
        if self.store.seen(key + ":in"):
            return OK
        ident = self._identity(msg)
        word = msg.text.strip().lower()
        if word in STOP | START:
            consent = "out" if word in STOP else "in"
            self.store.save(replace(ident, consent=consent))
            self._audit("channel.consent", ident, reason=consent)
            events.record("channel.consent", kind=kind, consent=consent)
            self._say(
                ident,
                f"You won't get more messages from {self.product} here. Reply START to undo."
                if consent == "out"
                else f"You'll get messages from {self.product} here. Reply STOP to stop.",
            )
            return OK
        if word in HELP:
            self._say(ident, f"This is {self.product}. Reply STOP to stop messages here.")
            return OK
        if not ident.user_id:
            nonce = pysecrets.token_urlsafe(24)
            self.store.add_link(hashlib.sha256(nonce.encode()).hexdigest(), ident.id, LINK_TTL_S)
            events.record("channel.link_offered", kind=kind)
            self._say(
                ident,
                f"To talk to {self.product} here, sign in within 10 minutes: "
                f"{self.cfg.link_url}?nonce={nonce}",
            )
            return OK
        if not self.window.allow(ident.id, channel.rate_per_minute, self.clock()):
            log.warning("channel.rate_limited kind=%s identity=%s", kind, ident.id)
            events.record("channel.rate_limited", kind=kind)
            return OK  # providers retry errors; a dropped message is answered
        try:
            event = self._event(ident, msg)
        except ContractError as exc:
            count(exc.dataset, "refused")
            log.error("channel.message_refused kind=%s dataset=%s field=%s", kind, exc.dataset, exc.field)
            return OK
        self.store.accept(key, [event])
        events.record("channel.received", kind=kind)
        return OK

    def _event(self, ident: Identity, msg: Message) -> Outgoing:
        contract = self.contracts.for_dataset(self.cfg.received)
        if contract is None:
            raise ContractError(self.cfg.received, "", "no contract")
        data = contract.check_whole(
            {
                "message_id": f"msg_{uuid.uuid4().hex}",
                "user_id": ident.user_id,
                "tenant": ident.tenant,
                "channel": msg.kind,
                "text": msg.text[:4000],
                "received_at": now().isoformat(),
            }
        )
        value = {
            "specversion": "1.0",
            "id": data["message_id"],
            "source": self.source,
            "type": self.cfg.received,
            "time": data["received_at"],
            "datacontenttype": "application/json",
            "dataschema": f"{contract.dataset}@{contract.version}",
            "data": data,
        }
        return Outgoing(contract.topic, ident.user_id, value, {"valxel-dataset": contract.dataset})

    # ------------------------------------------------------------------ linking
    def confirm(self, nonce: str, user_id: str, tenant: str, actor: Actor) -> Identity | None:
        ident = self.store.use_link(hashlib.sha256(nonce.encode()).hexdigest())
        if ident is None:
            return None
        linked = replace(ident, user_id=user_id, tenant=tenant, linked_at=now())
        self._audit("channel.linked", linked, actor=actor)
        saved = self.store.save(linked)
        events.record("channel.linked", kind=ident.kind)
        self._say(saved, f"You're signed in to {self.product} here. Reply STOP to stop messages.")
        return saved


class Replies:
    """The product's replies, from the `replies` dataset, to people on their channels."""

    def __init__(self, receiver: Receiver) -> None:
        self.r = receiver

    def notice(self) -> str:
        return f"You have a new message from {self.r.product}. Sign in to read it: {self.r.cfg.link_url}"

    def handle(self, event: dict[str, Any]) -> str:
        """Send one reply; returns what happened: sent, withheld or skipped."""
        r = self.r
        contract = r.contracts.for_dataset(r.cfg.replies)
        if contract is None:
            raise ContractError(r.cfg.replies, "", "no contract")
        data = contract.check(event.get("data") or {})
        reply_id, kind = str(event["id"]), str(data["channel"])
        if r.store.was_sent(reply_id):
            return "skipped"
        channel = r.cfg.channels.get(kind)
        ident = r.store.identity_for(str(data["user_id"]), kind) if channel else None
        why = (
            "no such channel"
            if channel is None
            else "not linked"
            if ident is None
            else "opted out"
            if ident.consent == "out"
            else "no consent yet"
            if kind == "sms" and ident.consent != "in"
            else ""
        )
        if why or ident is None or channel is None:
            if ident is not None:
                r._audit("channel.withheld", ident, "denied", why, reply=reply_id)
            log.info("channel.withheld kind=%s reason=%s", kind, why)
            events.record("channel.withheld", kind=kind, reason=why.replace(" ", "_"))
            r.store.mark_sent(reply_id)
            return "withheld"
        text = str(data["text"]) if channel.content == "full" else self.notice()
        # The record first: nothing goes out without it. If the send then fails, the retry records
        # again (twice, never zero times).
        r._audit("channel.sent", ident, reply=reply_id, content=channel.content)
        with cohorts.item():
            r.senders[kind].send(r.addresses.open(ident.sealed), text[:1600], subject=r.product)
        r.store.mark_sent(reply_id)
        count(contract.dataset, "sent")
        events.record("channel.sent", kind=kind)
        return "sent"


__all__ = ["Answer", "Receiver", "Refused", "Replies"]
