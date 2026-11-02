"""In-process vault resolution for zoneedit-mcp (adapted from amt-mcp's amt_vault).

Reads a vault entry by running the vault CLI (``secrets.py get <key>``) as a child process and
capturing stdout. A value is returned to the caller and never logged, echoed, put in argv or env,
or included in an exception. Every failure raises VaultError naming the vault KEY only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from zoneedit_totp import totp

CLI_ENV = "ZONEEDIT_SECRETS_CLI"
TIMEOUT_SECONDS = 15
USERNAME_KEY = "zoneedit-panel-username"
PASSWORD_KEY = "zoneedit-panel-password"
TOTP_SEED_KEY = "zoneedit-panel-totp-seed"


class VaultError(Exception):
    """Vault read failed. The message names the vault key, never a value or stderr."""


def _cli() -> str:
    path = os.environ.get(CLI_ENV, "").strip()
    if not path:
        raise VaultError(f"vault_cli_unset:{CLI_ENV}")
    return path


def get_secret(key: str) -> str:
    """Resolve a vault entry. Raises VaultError on a miss, an empty value or a timeout."""
    if not key or not key.strip():
        raise VaultError("vault_key_missing")
    cli = _cli()
    try:
        out = subprocess.run(
            [sys.executable, cli, "get", key],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except UnicodeDecodeError as ex:
        raise VaultError(f"vault_decode_error:{key}:{type(ex).__name__}") from None
    except (OSError, subprocess.SubprocessError) as ex:
        raise VaultError(f"vault_unavailable:{key}:{type(ex).__name__}") from None
    if out.returncode != 0:
        raise VaultError(f"vault_miss:{key}")
    value = out.stdout.rstrip("\n")
    if not value:
        raise VaultError(f"vault_empty:{key}")
    return value


def _unwrap(key: str, raw: str, preferred: str) -> str:
    """Raw text is the value. A JSON object is read in the order: the field this key is for
    (``preferred``), then ``value``, then the other credential field. A two-field object therefore
    never hands one key's field to the other key."""
    try:
        data = json.loads(raw)
    except ValueError:
        return raw
    if not isinstance(data, dict):
        return raw
    other = "password" if preferred == "username" else "username"
    for field in (preferred, "value", other):
        candidate = data.get(field)
        if isinstance(candidate, str) and candidate:
            return candidate
    raise VaultError(f"vault_field_missing:{key}")


def get_credentials() -> tuple[str, str]:
    """The ZoneEdit panel (username, password) from the vault."""
    username = _unwrap(USERNAME_KEY, get_secret(USERNAME_KEY), "username")
    password = _unwrap(PASSWORD_KEY, get_secret(PASSWORD_KEY), "password")
    return username, password


def get_totp_seed() -> str:
    """The panel's TOTP seed from the vault. Raw text, or a JSON object whose ``seed`` or ``value``
    string field holds it (checked in that order). The seed is validated once here, so a bad entry
    fails at the vault and not at login. The seed is never part of any message."""
    raw = get_secret(TOTP_SEED_KEY)
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        seed = next((data[f] for f in ("seed", "value")
                     if isinstance(data.get(f), str) and data.get(f)), None)
        if seed is None:
            raise VaultError(f"vault_field_missing:{TOTP_SEED_KEY}")
    else:
        seed = raw
    seed = seed.strip()
    try:
        totp(seed, 0)
    except ValueError:
        raise VaultError(f"vault_seed_invalid:{TOTP_SEED_KEY}") from None
    return seed
