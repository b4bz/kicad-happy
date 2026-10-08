"""DigiKey OAuth with a credential-bound, process-only cache.

Tokens and credentials are never written to disk. In particular, legacy shared
temporary-file caches are never read, modified, or migrated. Process-only caching
also avoids permission and symlink races on POSIX and Windows alike.
"""

import hashlib
import json
import math
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_lock = threading.Lock()
_cached_token = None
_credential_fingerprint = None
_expires_at = 0.0


def get_digikey_token() -> tuple[str, str] | None:
    """Return (token, client_id), or None; reuse only within this process.

    Refresh before expiry, invalidate on either credential changing, and never
    include credentials, tokens, or server response bodies in error messages.
    """
    global _cached_token, _credential_fingerprint, _expires_at
    client_id = os.environ.get("DIGIKEY_CLIENT_ID", "")
    client_secret = os.environ.get("DIGIKEY_CLIENT_SECRET", "")
    fingerprint = hashlib.sha256(json.dumps(
        [client_id, client_secret], separators=(",", ":")
    ).encode()).digest()

    with _lock:
        if fingerprint != _credential_fingerprint:
            _cached_token = None
            _expires_at = 0.0
            _credential_fingerprint = fingerprint
        if not client_id or not client_secret:
            return None
        started = time.monotonic()
        if _cached_token and started < _expires_at:
            return _cached_token, client_id

        _cached_token = None
        _expires_at = 0.0
        data = urllib.parse.urlencode({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }).encode()
        request = urllib.request.Request(
            "https://api.digikey.com/v1/oauth2/token", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                return None
            payload = json.loads(raw)
            token = payload.get("access_token")
            lifetime = float(payload.get("expires_in", 600))
            if (not isinstance(token, str) or not token.strip()
                    or not math.isfinite(lifetime) or lifetime <= 0):
                return None
        except (urllib.error.URLError, OSError, ValueError, TypeError,
                AttributeError, OverflowError):
            return None

        # Bound the reuse window even if the server returns an unusually long
        # lifetime. Short-lived tokens are returned once without being cached.
        _expires_at = started + max(0, min(540, lifetime - 60))
        _cached_token = token
        return token, client_id
