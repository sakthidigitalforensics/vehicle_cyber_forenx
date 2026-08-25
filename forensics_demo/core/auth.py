"""
Local access control for this downloaded copy of the tool, with two
independent layers that must BOTH pass before any case data becomes
readable:

1. ONE-TIME PASSWORD: set exactly once, by whoever runs this copy first.
   There is no "forgot password" / reset flow reachable from inside the
   app - set_password() itself refuses to run a second time.
2. MACHINE LOCK: the password is only accepted on the specific laptop it
   was first set up on. Copy this folder to another machine - even with
   the correct password - and it refuses to unlock.

The password also IS the encryption passphrase for the case vault (see
core/vault.py) - there's no separate "login password" vs "encryption key".
Verifying the password and decrypting the case data are the same
operation: if the derived key can decrypt the vault's marker token, the
password is correct; if it can't, it isn't. This means there is NO
recovery path if the password is forgotten - see factory_reset() below.
"""

import os
import json
import hashlib
import base64
import secrets
import platform
import subprocess
import uuid

from core import db, vault

META_PATH = os.path.join(db.DATA_DIR, "vault_meta.json")
VAULT_PATH = os.path.join(db.DATA_DIR, "vault.enc")
PBKDF2_ITERATIONS = 200_000
_MARKER = b"CFIT-VAULT-OK"


class PasswordAlreadySetError(Exception):
    """Raised by set_password() when a password already exists - this app's password may only be set once per downloaded copy."""


class MachineMismatchError(Exception):
    """Raised by verify_password() when this copy is being run on a different machine than the one it was set up on."""


class WrongPasswordError(Exception):
    """Raised by verify_password() when the password is simply incorrect (machine matched fine)."""


# --------------------------------------------------------------------------
# Machine fingerprint - offline only, no network calls.
# --------------------------------------------------------------------------

def _read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _os_machine_id():
    """The most stable identifier available per OS - survives reboots, network changes, and most software reinstalls."""
    system = platform.system()
    try:
        if system == "Linux":
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                val = _read_file(p)
                if val:
                    return val
        elif system == "Darwin":
            out = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        elif system == "Windows":
            out = subprocess.run(
                ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "MachineGuid" in line:
                    return line.strip().split()[-1]
    except Exception:
        pass
    return None


def _machine_fingerprint():
    """
    Prefer the OS-native machine ID (very stable). Fall back to
    hostname + MAC-derived node id if unavailable - less stable (can
    shift if network hardware changes), but still offline-only and far
    better than nothing.
    """
    os_id = _os_machine_id()
    if os_id:
        raw = f"os:{os_id}"
    else:
        raw = f"fallback:{platform.node()}:{uuid.getnode()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Password <-> encryption key
# --------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(raw)  # Fernet requires a urlsafe-base64, 32-byte key


def is_password_set():
    return os.path.exists(META_PATH)


def set_password(password: str):
    """
    Sets the password for this downloaded copy - ONCE - and initializes
    the encrypted case vault with it. Guarded here (not just by the caller
    checking is_password_set() first) so a future UI bug can't silently
    let someone overwrite an already-set password from within the app.
    Returns the derived encryption key (bytes) for the caller to hold in
    session state for the rest of this session.
    """
    if is_password_set():
        raise PasswordAlreadySetError(
            "A password has already been set for this copy of the app and cannot be changed from within it."
        )
    os.makedirs(db.DATA_DIR, exist_ok=True)
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    from cryptography.fernet import Fernet
    marker = Fernet(key).encrypt(_MARKER).decode("ascii")

    meta = {
        "salt": salt.hex(),
        "marker": marker,
        "machine_fingerprint": _machine_fingerprint(),
    }
    tmp_path = META_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(meta, f)
    os.replace(tmp_path, META_PATH)

    vault.init_empty_vault(key, db.LIVE_DIR, VAULT_PATH)
    return key


def verify_password(password: str):
    """
    Checks the password AND the machine lock, and if both pass, unlocks
    the case vault (decrypts data/vault.enc into data/live/). Returns the
    derived encryption key (bytes) on success - hold it in session state
    and pass it to reseal_vault() after anything changes.

    Raises MachineMismatchError if this isn't the machine the password was
    set up on (checked BEFORE the password itself, so a stolen/copied
    folder is refused regardless of whether the password is also known).
    Raises WrongPasswordError if the machine matches but the password is
    wrong.
    """
    if not is_password_set():
        raise WrongPasswordError("No password has been set yet.")
    with open(META_PATH) as f:
        meta = json.load(f)

    if not secrets.compare_digest(meta["machine_fingerprint"], _machine_fingerprint()):
        raise MachineMismatchError(
            "This copy of the tool is locked to the machine it was originally set up on. "
            "It won't unlock on a different machine, even with the correct password."
        )

    salt = bytes.fromhex(meta["salt"])
    key = _derive_key(password, salt)
    from cryptography.fernet import Fernet, InvalidToken
    try:
        decrypted = Fernet(key).decrypt(meta["marker"].encode("ascii"))
    except InvalidToken:
        raise WrongPasswordError("Incorrect password.")
    if decrypted != _MARKER:
        raise WrongPasswordError("Incorrect password.")

    vault.unlock(key, VAULT_PATH, db.LIVE_DIR)
    return key


def reseal_vault(key: bytes):
    """Re-encrypts the current state of data/live/ back into data/vault.enc. Call this after anything in the case data changes."""
    if key:
        vault.seal(key, db.LIVE_DIR, VAULT_PATH)


def lock_and_wipe(key: bytes):
    """Explicit 'Lock & Exit': seal the latest state, then delete the decrypted working copy so nothing sensitive is left in plaintext on disk."""
    reseal_vault(key)
    vault.wipe_live(db.LIVE_DIR)


# --------------------------------------------------------------------------
# Out-of-band recovery utilities - deliberately NOT exposed anywhere in the
# app UI. Both require direct terminal/filesystem access to this machine.
# --------------------------------------------------------------------------

def rebind_this_machine(password: str):
    """
    Recovery path for a LEGITIMATE machine identity change (OS reinstall,
    new disk, etc. on the SAME physical laptop) - proves knowledge of the
    correct password (independent of the machine check) and then updates
    the stored machine fingerprint to the current one. Run from a
    terminal on the machine in question, e.g.:
        python3 -c "from core.auth import rebind_this_machine; rebind_this_machine('your-password')"
    Does nothing to the vault/case data itself.
    """
    if not is_password_set():
        raise WrongPasswordError("No password has been set yet - nothing to rebind.")
    with open(META_PATH) as f:
        meta = json.load(f)
    salt = bytes.fromhex(meta["salt"])
    key = _derive_key(password, salt)
    from cryptography.fernet import Fernet, InvalidToken
    try:
        decrypted = Fernet(key).decrypt(meta["marker"].encode("ascii"))
    except InvalidToken:
        decrypted = None
    if decrypted != _MARKER:
        raise WrongPasswordError("Incorrect password - refusing to rebind.")
    meta["machine_fingerprint"] = _machine_fingerprint()
    with open(META_PATH, "w") as f:
        json.dump(meta, f)


def factory_reset():
    """
    NOT exposed anywhere in the app UI. Deletes the password/vault
    metadata, the encrypted vault, and any decrypted working copy - this
    PERMANENTLY AND IRRECOVERABLY DESTROYS all case data, because with
    real encryption there is no back door to recover a forgotten
    password. Only use this to start completely fresh. Run from a
    terminal, e.g.:
        python3 -c "from core.auth import factory_reset; factory_reset()"
    """
    for p in (META_PATH, VAULT_PATH):
        if os.path.exists(p):
            os.remove(p)
    vault.wipe_live(db.LIVE_DIR)
