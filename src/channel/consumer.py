"""The replies dataset from Kafka, each sent by Replies (service.py), at least once and never twice."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from typing import Any

import httpx

from .audit import AuditUnavailable
from .contracts import ContractError, count
from .providers import Refused
from .secrets import SecretMissing
from .service import Replies

log = logging.getLogger("channel.consumer")


class ReplyConsumer(threading.Thread):
    def __init__(
        self,
        replies: Replies,
        consumer: Any,
        topic: str,
        producer_factory: Callable[[], Any],
        *,
        pause_s: float = 5.0,
    ) -> None:
        super().__init__(daemon=True, name="replies")
        self.replies, self.consumer, self.topic, self.producer_factory = (
            replies,
            consumer,
            topic,
            producer_factory,
        )
        self.pause_s = pause_s
        self.producer: Any = None
        self.stop = threading.Event()

    def run(self) -> None:
        self.consumer.subscribe([self.topic])
        try:
            while not self.stop.is_set():
                self.step()
        finally:
            self.consumer.close()

    def step(self) -> None:
        msg = self.consumer.poll(1.0)
        if msg is None or msg.error():
            return
        dataset = self.replies.r.cfg.replies
        try:
            self.replies.handle(json.loads(msg.value()))
        except (ContractError, Refused, ValueError, KeyError, TypeError) as exc:
            field = getattr(exc, "field", "")
            self.park(msg, dataset, field, type(exc).__name__)
        except (httpx.HTTPError, SecretMissing, AuditUnavailable) as exc:
            log.warning("channel.provider_unavailable dataset=%s (%s); retrying", dataset, type(exc).__name__)
            from confluent_kafka import TopicPartition

            self.consumer.seek(TopicPartition(msg.topic(), msg.partition(), msg.offset()))
            self.stop.wait(self.pause_s)
            return
        self.consumer.commit(message=msg, asynchronous=False)

    def park(self, msg: Any, dataset: str, field: str, rule: str) -> None:
        if self.producer is None:
            self.producer = self.producer_factory()
        self.producer.produce(
            f"{msg.topic()}.dlt",
            key=msg.key(),
            value=msg.value(),
            headers=[
                ("valxel-dataset", dataset.encode()),
                ("valxel-field", field.encode()),
                ("valxel-rule", rule.encode()),
            ],
        )
        self.producer.flush(10)
        count(dataset, "parked")
        log.error(
            "channel.reply_parked dataset=%s field=%s rule=%s offset=%s", dataset, field, rule, msg.offset()
        )
