"""Is this request really from the provider? Each provider's own scheme, checked before the body is
parsed, in constant time, with the current or (during a rotation) previous secret.

  slack   X-Slack-Signature = "v0=" + HMAC-SHA256(signing secret, "v0:<timestamp>:<raw body>"),
          X-Slack-Request-Timestamp within 5 minutes.
  sms     Twilio's X-Twilio-Signature = base64(HMAC-SHA1(auth token, <public URL> + the form's
          parameters sorted by name, each name followed by its value)).
  email   Mailgun's form fields: signature = HMAC-SHA256(signing key, <timestamp><token>), with the
          timestamp within 5 minutes; each token is accepted once (replays are refused).
  teams   a Bot Framework JWT: signed by a key from the Bot Framework's JWKS, issuer
          https://api.botframework.com, audience this bot's app id, not expired.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Callable
from typing import Any

WINDOW_S = 300


def _any_equal(expected: list[str], given: str) -> bool:
    ok = False
    for e in expected:  # every candidate is compared, so timing doesn't tell which matched
        ok |= hmac.compare_digest(e, given)
    return ok


def slack(secrets: list[str], headers: dict[str, str], body: bytes, now: float) -> bool:
    stamp, given = headers.get("x-slack-request-timestamp", ""), headers.get("x-slack-signature", "")
    if not stamp.isdigit() or abs(now - int(stamp)) > WINDOW_S or not given.startswith("v0="):
        return False
    base = b"v0:" + stamp.encode() + b":" + body
    return _any_equal(
        ["v0=" + hmac.new(s.encode(), base, hashlib.sha256).hexdigest() for s in secrets], given
    )


def twilio_signature(secret: str, url: str, params: dict[str, str]) -> str:
    data = url + "".join(k + params[k] for k in sorted(params))
    return base64.b64encode(hmac.new(secret.encode(), data.encode(), hashlib.sha1).digest()).decode()


def sms(secrets: list[str], headers: dict[str, str], url: str, params: dict[str, str]) -> bool:
    given = headers.get("x-twilio-signature", "")
    return bool(given) and _any_equal([twilio_signature(s, url, params) for s in secrets], given)


def mailgun_signature(secret: str, timestamp: str, token: str) -> str:
    return hmac.new(secret.encode(), (timestamp + token).encode(), hashlib.sha256).hexdigest()


def email(secrets: list[str], params: dict[str, str], now: float, seen: Callable[[str], bool]) -> bool:
    stamp, token, given = params.get("timestamp", ""), params.get("token", ""), params.get("signature", "")
    if not (stamp.isdigit() and token and given) or abs(now - int(stamp)) > WINDOW_S:
        return False
    if not _any_equal([mailgun_signature(s, stamp, token) for s in secrets], given):
        return False
    return not seen(f"mailgun-token:{token}")  # a token used before is a replay


class TeamsVerifier:
    ISSUER = "https://api.botframework.com"
    JWKS = "https://login.botframework.com/v1/.well-known/keys"

    def __init__(self, app_id: Callable[[], str], jwks: Any = None) -> None:
        import jwt

        self._jwt, self.app_id = jwt, app_id
        self.jwks = jwks or jwt.PyJWKClient(self.JWKS, cache_keys=True)

    def __call__(self, headers: dict[str, str]) -> bool:
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return False
        token = auth[7:].strip()
        try:
            key = self.jwks.get_signing_key_from_jwt(token)
            self._jwt.decode(
                token, key.key, algorithms=["RS256"], audience=self.app_id(), issuer=self.ISSUER, leeway=300
            )
        except self._jwt.PyJWTError:
            return False
        return True


def now() -> float:
    return time.time()
