"""Who is confirming a link: the IdP's JWT access token (audience: this service), passed on by the
product's BFF after the person signs in. The token's subject becomes the identity's user and its
single organization the tenant."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class Caller:
    subject: str
    client: str
    scopes: frozenset[str]
    tenants: frozenset[str] = field(default_factory=frozenset)

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise HTTPException(403, f"This needs the {scope} scope.")


class Verifier(Protocol):
    def verify(self, token: str) -> dict[str, Any] | None: ...


class JwtVerifier:
    def __init__(self, *, issuer: str, jwks_url: str, audience: str) -> None:
        import jwt

        if not (issuer and jwks_url):
            raise RuntimeError("Set CHANNEL_OIDC_ISSUER and CHANNEL_OIDC_JWKS_URL")
        self._jwt, self.issuer, self.audience = jwt, issuer, audience
        self.jwks = jwt.PyJWKClient(jwks_url, cache_keys=True)

    def verify(self, token: str) -> dict[str, Any] | None:
        try:
            key = self.jwks.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = self._jwt.decode(
                token, key.key, algorithms=["RS256", "ES256"], audience=self.audience, issuer=self.issuer
            )
            return claims
        except self._jwt.PyJWTError:
            return None


def tenants(claims: dict[str, Any], claim: str) -> frozenset[str]:
    raw = claims.get(claim)
    if not raw:
        return frozenset()
    if isinstance(raw, str):
        return frozenset([raw])
    return frozenset(str(k) for k in raw)


class RateLimiter:
    def __init__(self, per_minute: int, burst: int) -> None:
        self.rate, self.burst = per_minute / 60.0, float(burst)
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.buckets[key] = (tokens - 1 if ok else tokens, now)
            if len(self.buckets) > 10_000:
                self.buckets.clear()
            return ok


def authenticate(request: Request, verifier: Verifier, tenant_claim: str, limiter: RateLimiter) -> Caller:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "A bearer token is required.", headers={"WWW-Authenticate": "Bearer"})
    claims = verifier.verify(header[7:].strip())
    if claims is None:
        raise HTTPException(401, "The token isn't valid.", headers={"WWW-Authenticate": "Bearer"})
    scope = claims.get("scope") or claims.get("scp") or ""
    caller = Caller(
        subject=str(claims.get("sub") or ""),
        client=str(claims.get("azp") or claims.get("client_id") or ""),
        scopes=frozenset(scope.split() if isinstance(scope, str) else scope),
        tenants=tenants(claims, tenant_claim),
    )
    if not caller.tenants:
        raise HTTPException(403, "Your token names no organization, so nothing can be linked.")
    if not limiter.allow(caller.subject or caller.client):
        raise HTTPException(429, "Too many requests; try again shortly.", headers={"Retry-After": "10"})
    return caller
