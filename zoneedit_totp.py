"""RFC 6238 time-based one-time passwords (HMAC-SHA1, 30 second step, six digits).

Pure: stdlib only, no I/O, no clock read. The caller passes ``at`` (epoch seconds). A seed is never
echoed: an invalid seed raises ``ValueError("invalid_seed")``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct


def _key(seed_b32: str) -> bytes:
    """Base32 seed to key bytes. Spaces and hyphens are dropped, case is ignored, padding is rebuilt."""
    cleaned = "".join(ch for ch in seed_b32 if ch not in " -").upper().rstrip("=")
    if not cleaned:
        raise ValueError("invalid_seed")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned)
    except (binascii.Error, ValueError):
        raise ValueError("invalid_seed") from None


def totp(seed_b32: str, at: float, digits: int = 6, step: int = 30) -> str:
    """The RFC 6238 code for ``seed_b32`` at epoch second ``at``, zero-padded to ``digits``."""
    counter = int(at // step)
    digest = hmac.new(_key(seed_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10 ** digits:0{digits}d}"


def seconds_left(at: float, step: int = 30) -> float:
    """Seconds until the current step ends. A time exactly on a boundary has a full step left."""
    return step - (at % step)
