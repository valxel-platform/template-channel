"""People's addresses (a phone number, an email address, a Slack or Teams user id) are personal data.

They are stored two ways, never in the clear: a keyed hash to find an identity by (HMAC-SHA256
with the `address-pepper` secret), and the address itself encrypted (Fernet, with the
`address-key` secret, whose previous value still decrypts during a rotation) for sending replies.
Logs, events and audit records carry the identity's id, never an address.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .secrets import Secrets

PEPPER, KEY = "address-pepper", "address-key"


class Addresses:
    def __init__(self, secrets: Secrets) -> None:
        self.secrets = secrets

    def lookup(self, kind: str, address: str) -> str:
        norm = address.strip().lower()
        return hmac.new(
            self.secrets.current(PEPPER).encode(), f"{kind}:{norm}".encode(), hashlib.sha256
        ).hexdigest()

    def _fernet(self) -> MultiFernet:
        return MultiFernet([Fernet(k.encode()) for k in self.secrets.values(KEY)])

    def seal(self, address: str) -> str:
        return self._fernet().encrypt(address.encode()).decode()

    def open(self, sealed: str) -> str:
        try:
            return self._fernet().decrypt(sealed.encode()).decode()
        except InvalidToken as exc:
            raise ValueError(
                "an address couldn't be decrypted (was the key rotated without its previous value?)"
            ) from exc
