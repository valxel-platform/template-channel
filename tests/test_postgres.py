"""The Postgres store against a real database (VALXEL_TEST_DATABASE_URL); skipped without one."""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from channel.relay_types import Outgoing
from channel.store import PostgresStore, new_identity, now

URL = os.environ.get("VALXEL_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="needs VALXEL_TEST_DATABASE_URL")


@pytest.fixture
def pg():
    store = PostgresStore(URL)
    with store.pool.connection() as conn:
        conn.execute(
            "truncate channel_identities, channel_links, channel_seen, channel_sent, channel_outbox cascade"
        )
    yield store
    store.pool.close()


def test_identities_links_consent_dedupe_and_outbox(pg):
    a = pg.save(new_identity("sms", "hash-1", "sealed-1"))
    assert pg.identity("sms", "hash-1") == a and pg.identity("slack", "hash-1") is None
    racer = pg.save(new_identity("sms", "hash-1", "sealed-2"))  # someone else's insert loses
    assert racer.id == a.id
    pg.add_link("nonce-hash", a.id, 600)
    used = pg.use_link("nonce-hash")
    assert used is not None and used.id == a.id and pg.use_link("nonce-hash") is None
    pg.add_link("old", a.id, -1)
    assert pg.use_link("old") is None
    linked = pg.save(replace(a, user_id="nurse-7", tenant="north", consent="in", linked_at=now()))
    assert pg.identity_for("nurse-7", "sms") == linked and pg.identity_for("nurse-7", "slack") is None
    assert not pg.seen("k1") and pg.seen("k1")
    ev = Outgoing("t", "nurse-7", {"id": "m"}, {"valxel-dataset": "d"})
    assert pg.accept("k2", [ev]) and not pg.accept("k2", [ev])
    [q] = pg.claim()
    pg.published([q.id])
    assert pg.claim() == []
    assert not pg.was_sent("r1")
    pg.mark_sent("r1")
    pg.mark_sent("r1")
    assert pg.was_sent("r1")


def test_open_links(pg):
    a = pg.save(new_identity("sms", "hash-9", "sealed"))
    assert not pg.open_link(a.id)
    pg.add_link("n1", a.id, 600)
    assert pg.open_link(a.id)
    pg.use_link("n1")
    assert not pg.open_link(a.id)
