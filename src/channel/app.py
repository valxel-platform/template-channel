"""The channel service.

Routes: POST /channels/<kind> for each channel in channel.yaml (the only ones the platform
exposes outside the cluster: each provider calls its own), POST /links/{nonce}/confirm (the BFF,
with the signed-in person's token), /healthz and /readyz (in-cluster only). /metrics is on the
management port (management.py).

Start-up refuses to run when channel.yaml is invalid, a secret it names (or the address key and
pepper) isn't mounted, a dataset has no contract, a PHI or payments product's Kafka isn't TLS, or a
deployed environment has no database or Kafka.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from . import cohorts, errors, events, flags, management, telemetry
from .audit import Actor, Auditor, AuditUnavailable, make_sink, require_encryption
from .auth import Caller, JwtVerifier, RateLimiter, Verifier, authenticate
from .component import COMPONENT
from .config import Config, load
from .contracts import Contracts, summary_line
from .crypto import KEY, PEPPER
from .providers import Sender
from .secrets import SecretMissing, Secrets
from .service import Receiver, Replies
from .settings import Settings
from .store import MemoryStore, PostgresStore, Store
from .verify import TeamsVerifier

log = logging.getLogger("channel")
MAX_BODY = 256 * 1024


@dataclass
class Runtime:
    settings: Settings
    cfg: Config
    store: Store
    receiver: Receiver
    replies: Replies
    verifier: Verifier
    threads: list[Any] = field(default_factory=list)


def build(
    settings: Settings,
    *,
    store: Store | None = None,
    auditor: Auditor | None = None,
    verifier: Verifier | None = None,
    senders: dict[str, Any] | None = None,
    teams: Any = None,
) -> Runtime:
    cfg = load(settings.config_path)
    secrets = Secrets(settings.secrets_dir)
    problems = []
    for name in [*cfg.secret_names, PEPPER, KEY]:
        try:
            secrets.values(name)
        except SecretMissing as exc:
            problems.append(str(exc))
    contracts = Contracts.load(settings.contracts_dir)
    known = {c.dataset for c in contracts.by_topic.values()}
    problems += [f"no contract for {d} in contracts/" for d in (cfg.received, cfg.replies) if d not in known]
    if settings.environment in ("staging", "production") and not (
        settings.database_url and settings.kafka_bootstrap
    ):
        problems.append("staging and production need CHANNEL_DATABASE_URL and CHANNEL_KAFKA_BOOTSTRAP")
    if problems:
        raise RuntimeError("the channel service can't start: " + "; ".join(problems))
    if settings.kafka_bootstrap:
        require_encryption(settings.kafka_config, cfg.data_class, "events")
    if auditor is None:
        required = (
            settings.audit_required if settings.audit_required is not None else cfg.data_class != "general"
        )
        auditor = Auditor(
            make_sink(
                settings.audit_sink,
                bootstrap=settings.audit_kafka_bootstrap,
                topic=settings.audit_topic,
                config=settings.audit_kafka_config,
                data_class=cfg.data_class,
            ),
            service=COMPONENT,
            product=settings.product,
            environment=settings.environment,
            data_class=cfg.data_class,
            required=required,
        )
    store = store or (PostgresStore(settings.database_url) if settings.database_url else MemoryStore())
    senders = senders or {k: Sender(c, secrets) for k, c in cfg.channels.items()}
    if teams is None and "teams" in cfg.channels:
        app_id = cfg.channels["teams"].secrets["app_id"]
        teams = TeamsVerifier(lambda: secrets.current(app_id))
    receiver = Receiver(
        cfg,
        secrets,
        store,
        contracts,
        auditor,
        senders,
        public_url=settings.public_url,
        source=f"{settings.product}/{COMPONENT}",
        product=settings.product or "the product",
        teams=teams,
        link_offers_per_minute=settings.link_offers_per_minute,
    )
    verifier = verifier or JwtVerifier(
        issuer=settings.oidc_issuer, jwks_url=settings.oidc_jwks_url, audience=settings.audience
    )
    return Runtime(settings, cfg, store, receiver, Replies(receiver), verifier)


async def _read_capped(request: Request) -> bytes | None:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY:
        return None
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(
    settings: Settings | None = None, *, runtime: Runtime | None = None, workers: bool = True
) -> Any:
    settings = settings or Settings()
    rt = runtime or build(settings)
    limiter = RateLimiter(60, 20)
    app = FastAPI(title=COMPONENT, docs_url=None, redoc_url=None, openapi_url=None)
    telemetry.setup(COMPONENT, app=app)
    errors.start_errors()
    flags.configure(settings)
    events.register(REGISTRY)

    def route(kind: str) -> Any:
        async def handle(request: Request) -> Response:
            body = await _read_capped(request)
            if body is None:
                return JSONResponse({"error": "too large"}, status_code=413)
            try:
                answer = rt.receiver.receive(kind, dict(request.headers), body)
            except AuditUnavailable:
                return JSONResponse({"error": "unavailable"}, status_code=503)
            return JSONResponse(answer.body, status_code=answer.status)

        return handle

    for kind, channel in rt.cfg.channels.items():
        app.add_api_route(channel.path, route(kind), methods=["POST"], include_in_schema=False)

    def signed_in(request: Request) -> Caller:
        return authenticate(request, rt.verifier, settings.tenant_claim, limiter)

    @app.post("/links/{nonce}/confirm")
    def confirm(nonce: str, caller: Caller = Depends(signed_in)) -> dict[str, Any]:  # noqa: B008
        if len(caller.tenants) != 1 or not caller.subject:
            raise HTTPException(422, "Sign in as a person in one organization to link a channel.")
        actor = Actor(id=caller.subject, type="user", client=caller.client)
        try:
            ident = rt.receiver.confirm(nonce[:200], caller.subject, next(iter(caller.tenants)), actor)
        except AuditUnavailable as exc:
            raise HTTPException(503, "This couldn't be recorded; try again shortly.") from exc
        if ident is None:
            raise HTTPException(
                404, "This link has expired or was used. Send a message on the channel for a new one."
            )
        return {"linked": True, "channel": ident.kind}

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> Response:
        dead = [t.name for t in rt.threads if not t.is_alive()]
        return JSONResponse(
            {"status": "not ready", "stopped": dead} if dead else {"status": "ready"},
            status_code=503 if dead else 200,
        )

    app.add_middleware(cohorts.CohortMiddleware)
    app.add_middleware(errors.TraceResponseMiddleware)
    app.state.runtime = rt
    if workers:
        start_workers(rt)
    return app


def start_workers(rt: Runtime) -> None:
    s = rt.settings
    if not s.kafka_bootstrap:
        log.warning("no Kafka configured: messages stay in the outbox and no replies are read")
        return
    from confluent_kafka import Consumer

    from .consumer import ReplyConsumer
    from .relay import Relay, kafka_producer

    kafka = {"bootstrap.servers": s.kafka_bootstrap, **s.kafka_config}
    relay = Relay(rt.store, rt.receiver.contracts, kafka_producer(kafka))
    relay.start()
    contract = rt.receiver.contracts.for_dataset(rt.cfg.replies)
    assert contract is not None
    replies = ReplyConsumer(
        rt.replies,
        Consumer(
            {
                **kafka,
                "group.id": f"{COMPONENT}.replies",
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
            }
        ),
        contract.topic,
        lambda: kafka_producer(kafka),
    )
    replies.start()
    rt.threads += [relay, replies]

    def report() -> None:
        stop = threading.Event()
        while not stop.wait(60):
            line = summary_line()
            if line:
                log.info(line)

    threading.Thread(target=report, name="datasets", daemon=True).start()
    cohorts.start_reporting()
    events.start_reporting()


def metrics_body() -> tuple[bytes, str]:
    """What the management port serves (management.py): every metric, the product events counter
    (valxel_events_total) among them."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def main() -> None:
    import uvicorn

    settings = Settings()
    telemetry.setup_logging(COMPONENT)
    # /metrics on the management port (MANAGEMENT_PORT, 8081), apart from the API, as in the Java
    # templates: the mesh lets the data plane's metrics collector reach that port only.
    management.serve(metrics_body, host="0.0.0.0")  # noqa: S104  NOSONAR: inside the container; the collector scrapes it from another pod
    uvicorn.run(create_app(settings), host="0.0.0.0", port=settings.port, log_config=None)  # noqa: S104
