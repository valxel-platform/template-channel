"""Identities, link nonces, consent, what's been seen and the outbox, in the product's Postgres.

identities  one per (channel kind, address): its keyed hash, the address encrypted, and, once
            linked, the product user and tenant. consent: unknown, in or out.
links       single-use link nonces, by their SHA-256 (the nonce itself is only in the link sent).
seen        provider message ids and email tokens already handled (dedupe and replay refusal).
outbox      events to publish (messages received), written with their `seen` row.
sent        replies already sent, by reply id.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .relay_types import Outgoing, Queued


@dataclass(frozen=True)
class Identity:
    id: str
    kind: str
    lookup: str
    sealed: str
    user_id: str = ""
    tenant: str = ""
    consent: str = "unknown"  # unknown | in | out
    linked_at: datetime | None = None


def now() -> datetime:
    return datetime.now(UTC)


class Store(Protocol):
    def identity(self, kind: str, lookup: str) -> Identity | None: ...
    def identity_for(self, user_id: str, kind: str) -> Identity | None: ...
    def save(self, ident: Identity) -> Identity: ...
    def add_link(self, nonce_hash: str, identity_id: str, ttl_s: int) -> None: ...
    def use_link(self, nonce_hash: str) -> Identity | None: ...
    def seen(self, key: str) -> bool: ...
    def accept(self, key: str, events: list[Outgoing]) -> bool: ...
    def was_sent(self, reply_id: str) -> bool: ...
    def mark_sent(self, reply_id: str) -> None: ...
    def claim(self, limit: int = 100) -> list[Queued]: ...
    def published(self, ids: list[int]) -> None: ...


class MemoryStore:
    def __init__(self) -> None:
        self.identities: dict[str, Identity] = {}
        self.links: dict[str, tuple[str, datetime, bool]] = {}
        self.keys: set[str] = set()
        self.sent: set[str] = set()
        self.outbox: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def identity(self, kind: str, lookup: str) -> Identity | None:
        return next((i for i in self.identities.values() if i.kind == kind and i.lookup == lookup), None)

    def identity_for(self, user_id: str, kind: str) -> Identity | None:
        return next((i for i in self.identities.values() if i.kind == kind and i.user_id == user_id), None)

    def save(self, ident: Identity) -> Identity:
        with self.lock:
            found = self.identity(ident.kind, ident.lookup)
            if found and found.id != ident.id:
                return found
            self.identities[ident.id] = ident
            return ident

    def add_link(self, nonce_hash: str, identity_id: str, ttl_s: int) -> None:
        self.links[nonce_hash] = (identity_id, now() + timedelta(seconds=ttl_s), False)

    def use_link(self, nonce_hash: str) -> Identity | None:
        with self.lock:
            row = self.links.get(nonce_hash)
            if row is None or row[2] or row[1] < now():
                return None
            self.links[nonce_hash] = (row[0], row[1], True)
            return self.identities.get(row[0])

    def seen(self, key: str) -> bool:
        with self.lock:
            if key in self.keys:
                return True
            self.keys.add(key)
            return False

    def accept(self, key: str, events: list[Outgoing]) -> bool:
        with self.lock:
            if key in self.keys:
                return False
            self.keys.add(key)
            for e in events:
                self.outbox.append(
                    {
                        "id": len(self.outbox) + 1,
                        "topic": e.topic,
                        "key": e.key,
                        "value": e.value,
                        "headers": e.headers,
                        "sent": False,
                    }
                )
            return True

    def was_sent(self, reply_id: str) -> bool:
        return reply_id in self.sent

    def mark_sent(self, reply_id: str) -> None:
        self.sent.add(reply_id)

    def claim(self, limit: int = 100) -> list[Queued]:
        rows = [r for r in self.outbox if not r["sent"]][:limit]
        return [Queued(r["id"], r["topic"], r["key"], r["value"], r["headers"]) for r in rows]

    def published(self, ids: list[int]) -> None:
        for r in self.outbox:
            if r["id"] in ids:
                r["sent"] = True


def new_identity(kind: str, lookup: str, sealed: str) -> Identity:
    return Identity(id=f"idn_{uuid.uuid4().hex}", kind=kind, lookup=lookup, sealed=sealed)


SCHEMA = """
create table if not exists channel_identities (
  id text primary key,
  kind text not null,
  lookup text not null,
  sealed text not null,
  user_id text not null default '',
  tenant text not null default '',
  consent text not null default 'unknown' check (consent in ('unknown', 'in', 'out')),
  linked_at timestamptz,
  unique (kind, lookup)
);
create index if not exists channel_identities_user on channel_identities (user_id, kind) where user_id <> '';
create table if not exists channel_links (
  nonce_hash text primary key,
  identity_id text not null references channel_identities (id) on delete cascade,
  expires_at timestamptz not null,
  used boolean not null default false
);
create table if not exists channel_seen (key text primary key, at timestamptz not null default now());
create table if not exists channel_sent (reply_id text primary key, at timestamptz not null default now());
create table if not exists channel_outbox (
  id bigserial primary key,
  topic text not null,
  key text not null,
  value jsonb not null,
  headers jsonb not null default '{}',
  created_at timestamptz not null default now(),
  sent_at timestamptz
);
create index if not exists channel_outbox_unsent on channel_outbox (id) where sent_at is null;
"""
BY_LOOKUP = (
    "select id, kind, lookup, sealed, user_id, tenant, consent, linked_at from channel_identities"
    " where kind = %s and lookup = %s"
)
BY_USER = (
    "select id, kind, lookup, sealed, user_id, tenant, consent, linked_at from channel_identities"
    " where user_id = %s and kind = %s order by linked_at desc limit 1"
)
BY_ID = (
    "select id, kind, lookup, sealed, user_id, tenant, consent, linked_at from channel_identities"
    " where id = %s"
)
UPSERT = (
    "insert into channel_identities (id, kind, lookup, sealed, user_id, tenant, consent, linked_at)"
    " values (%s, %s, %s, %s, %s, %s, %s, %s) on conflict (kind, lookup) do update"
    " set sealed = excluded.sealed,"
    " user_id = excluded.user_id, tenant = excluded.tenant, consent = excluded.consent,"
    " linked_at = excluded.linked_at where channel_identities.id = excluded.id"
)


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        from psycopg_pool import ConnectionPool

        self.pool = ConnectionPool(dsn, min_size=1, max_size=5, open=True, kwargs={"autocommit": True})
        with self.pool.connection() as conn:
            conn.execute(SCHEMA)

    def identity(self, kind: str, lookup: str) -> Identity | None:
        with self.pool.connection() as conn:
            r = conn.execute(BY_LOOKUP, (kind, lookup)).fetchone()
        return Identity(*r) if r else None

    def identity_for(self, user_id: str, kind: str) -> Identity | None:
        with self.pool.connection() as conn:
            r = conn.execute(BY_USER, (user_id, kind)).fetchone()
        return Identity(*r) if r else None

    def save(self, ident: Identity) -> Identity:
        with self.pool.connection() as conn:
            conn.execute(
                UPSERT,
                (
                    ident.id,
                    ident.kind,
                    ident.lookup,
                    ident.sealed,
                    ident.user_id,
                    ident.tenant,
                    ident.consent,
                    ident.linked_at,
                ),
            )
        return self.identity(ident.kind, ident.lookup) or ident

    def add_link(self, nonce_hash: str, identity_id: str, ttl_s: int) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "insert into channel_links (nonce_hash, identity_id, expires_at)"
                " values (%s, %s, now() + make_interval(secs => %s))",
                (nonce_hash, identity_id, ttl_s),
            )

    def use_link(self, nonce_hash: str) -> Identity | None:
        with self.pool.connection() as conn:
            r = conn.execute(
                "update channel_links set used = true where nonce_hash = %s and not used"
                " and expires_at > now() returning identity_id",
                (nonce_hash,),
            ).fetchone()
            if r is None:
                return None
            row = conn.execute(BY_ID, (r[0],)).fetchone()
        return Identity(*row) if row else None

    def seen(self, key: str) -> bool:
        with self.pool.connection() as conn:
            r = conn.execute(
                "insert into channel_seen (key) values (%s) on conflict do nothing returning 1", (key,)
            ).fetchone()
        return r is None

    def accept(self, key: str, events: list[Outgoing]) -> bool:
        with self.pool.connection() as conn, conn.transaction():
            r = conn.execute(
                "insert into channel_seen (key) values (%s) on conflict do nothing returning 1", (key,)
            ).fetchone()
            if r is None:
                return False
            for e in events:
                conn.execute(
                    "insert into channel_outbox (topic, key, value, headers) values (%s, %s, %s, %s)",
                    (e.topic, e.key, json.dumps(e.value), json.dumps(e.headers)),
                )
            return True

    def was_sent(self, reply_id: str) -> bool:
        with self.pool.connection() as conn:
            return (
                conn.execute("select 1 from channel_sent where reply_id = %s", (reply_id,)).fetchone()
                is not None
            )

    def mark_sent(self, reply_id: str) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "insert into channel_sent (reply_id) values (%s) on conflict do nothing", (reply_id,)
            )

    def claim(self, limit: int = 100) -> list[Queued]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "select id, topic, key, value, headers from channel_outbox where sent_at is null"
                " order by id limit %s",
                (limit,),
            ).fetchall()
        return [Queued(int(r[0]), r[1], r[2], r[3], r[4]) for r in rows]

    def published(self, ids: list[int]) -> None:
        if ids:
            with self.pool.connection() as conn:
                conn.execute("update channel_outbox set sent_at = now() where id = any(%s)", (ids,))


__all__ = ["Identity", "MemoryStore", "PostgresStore", "Store", "new_identity", "now", "replace"]
