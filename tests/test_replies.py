"""Replies out: only to linked people who haven't opted out, notice-only where the design says so."""

from __future__ import annotations

import httpx
import pytest

from channel.consumer import ReplyConsumer
from channel.contracts import ContractError

from .fakes import Consumer, Msg, Producer


def reply(user="nurse-7", channel="slack", text="Your results are in: all normal.", rid="r-1"):
    return {
        "id": rid,
        "type": "conversation-reply",
        "data": {"user_id": user, "channel": channel, "text": text},
    }


def linked(env, kind="sms"):
    getattr(env, kind)("hi")
    env.link(kind)
    env.senders[kind].sent.clear()


def test_a_reply_goes_in_full_where_allowed_once(env):
    linked(env, "slack")
    assert env.rt.replies.handle(reply()) == "sent"
    assert env.senders["slack"].sent == [("T1:U1", "Your results are in: all normal.")]
    assert env.rt.replies.handle(reply()) == "skipped"
    sent = [e for e in env.sink.events if e["data"]["action"] == "channel.sent"]
    assert sent[0]["data"]["details"]["content"] == "full"


def test_notice_only_channels_never_carry_the_text(env):
    linked(env, "sms")
    env.sms("START", sid="SM9")
    env.senders["sms"].sent.clear()
    assert env.rt.replies.handle(reply(channel="sms")) == "sent"
    [(_, text)] = env.senders["sms"].sent
    assert "all normal" not in text and "Sign in to read it" in text


@pytest.mark.parametrize(
    "setup,why",
    [
        (lambda env: None, "not linked"),
        (lambda env: linked(env, "sms"), "no consent yet"),
        (lambda env: (linked(env, "sms"), env.sms("STOP", sid="SM8")), "opted out"),
    ],
)
def test_replies_are_withheld_without_a_link_or_consent(env, setup, why):
    setup(env)
    env.senders["sms"].sent.clear()
    assert env.rt.replies.handle(reply(channel="sms")) == "withheld"
    assert env.senders["sms"].sent == []
    if why != "not linked":
        assert env.sink.events[-1]["data"]["reason"] == why


def test_a_reply_that_breaks_its_contract_is_refused(env):
    with pytest.raises(ContractError):
        env.rt.replies.handle(reply(channel="fax"))


def test_the_consumer_sends_parks_and_retries(env):
    linked(env, "slack")
    good, bad = Msg("emr.conversation-reply.v1", reply()), Msg("emr.conversation-reply.v1", b"nope", 1)
    consumer, producer = Consumer([good, bad]), Producer()
    c = ReplyConsumer(env.rt.replies, consumer, "emr.conversation-reply.v1", lambda: producer, pause_s=0)
    c.step()
    c.step()
    assert consumer.committed == [0, 1] and producer.sent[0]["topic"] == "emr.conversation-reply.v1.dlt"
    env.senders["slack"].fail = httpx.ConnectError("down")
    later = Consumer([Msg("emr.conversation-reply.v1", reply(rid="r-2"), 7)])
    ReplyConsumer(env.rt.replies, later, "t", lambda: producer, pause_s=0).step()
    assert later.committed == [] and later.seeks == [7]


def test_no_audit_record_means_the_reply_is_tried_again(env):
    linked(env, "slack")
    env.sink.fail = True
    from channel.audit import AuditUnavailable

    with pytest.raises(AuditUnavailable):
        env.rt.replies.handle(reply())
    assert not env.store.was_sent("r-1") and env.senders["slack"].sent == []


def test_the_consumer_thread_subscribes_and_closes(env):
    consumer = Consumer([])
    c = ReplyConsumer(env.rt.replies, consumer, "emr.conversation-reply.v1", Producer, pause_s=0)
    c.stop.set()
    c.run()
    assert consumer.subscribed == ["emr.conversation-reply.v1"] and consumer.closed
