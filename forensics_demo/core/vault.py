"""
Encrypted-at-rest storage for the case data. This is what turns "a
password gate on the app" into "actually encrypted case data" - the
difference matters because a password screen alone only stops someone
from using the app; it does nothing to stop someone with plain filesystem
access from opening the SQLite file or evidence folder directly with any
generic tool.

Design (a practical "envelope" scheme, chosen deliberately over SQLCipher
for portability - SQLCipher needs a native build per OS/architecture,
which is exactly the kind of thing that breaks silently on someone's
Windows laptop with no network to fetch a working wheel from):

- `data/live/` is the DECRYPTED working copy - the actual SQLite DB,
  evidence files, POC files, generated reports. This is what core/db.py
  and core/report_generator.py read and write while the app is unlocked.
- `data/vault.enc` is the single ENCRYPTED-AT-REST artifact: a tar.gz of
  the entire `data/live/` tree, encrypted with Fernet (AES-128-CBC +
  HMAC-SHA256, authenticated) using a key derived from the case password
  via PBKDF2-HMAC-SHA256.
- unlock(): decrypts vault.enc into data/live/. Wrong password -> the
  Fernet token fails to authenticate and this raises WrongPasswordError -
  there is no partial/silent decryption.
- seal(): re-tars data/live/ and overwrites vault.enc, atomically (write
  to a temp file, then os.replace so a crash mid-write can't corrupt the
  vault). Called after every meaningful action in the app (see app.py) so
  the on-disk encrypted copy stays current.
- wipe_live(): deletes the decrypted data/live/ tree. Used on explicit
  "Lock & Exit".

Known, deliberate limitation: while the app is open and unlocked,
`data/live/` exists in PLAINTEXT on disk (SQLite needs a real file to
operate on - this isn't unique to this tool, it's true of SQLCipher too,
which decrypts pages on the fly rather than keeping a separate plaintext
copy, but still has key material live in the running process). Using the
"🔒 Lock & Exit" button reseals and wipes that plaintext copy. If the
process is killed rather than exited cleanly, that plaintext copy can be
left behind on disk until the app is next unlocked and locked again -
this is disclosed in the README, not hidden.

There is NO back door: forgetting the password means data/vault.enc
cannot be decrypted by anyone, including us. That's the point of real
encryption - see core/auth.py's factory_reset() for the only recovery
path, which discards the old (unreadable) vault rather than recovering it.
"""

import os
import io
import shutil
import tarfile

from cryptography.fernet import Fernet, InvalidToken


class WrongPasswordError(Exception):
    """The provided password's derived key failed to decrypt the vault - either the password is wrong or the vault is corrupted."""


def _tar_dir(src_dir: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        if os.path.isdir(src_dir):
            tar.add(src_dir, arcname=".")
    return buf.getvalue()


def _untar_bytes(raw: bytes, dest_dir: str):
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        tar.extractall(dest_dir)


def vault_exists(vault_path: str) -> bool:
    return os.path.exists(vault_path)


def init_empty_vault(key: bytes, live_dir: str, vault_path: str):
    """First-run: start from a fresh, empty live directory and seal it immediately, so a vault file exists from the moment the password is set."""
    if os.path.exists(live_dir):
        shutil.rmtree(live_dir)
    os.makedirs(live_dir, exist_ok=True)
    seal(key, live_dir, vault_path)


def seal(key: bytes, live_dir: str, vault_path: str):
    """Encrypt the current live directory and atomically overwrite the vault file."""
    raw = _tar_dir(live_dir)
    token = Fernet(key).encrypt(raw)
    tmp_path = vault_path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(token)
    os.replace(tmp_path, vault_path)


def unlock(key: bytes, vault_path: str, live_dir: str):
    """Decrypt the vault into the live directory. Raises WrongPasswordError if `key` can't decrypt it."""
    if not os.path.exists(vault_path):
        os.makedirs(live_dir, exist_ok=True)
        return
    with open(vault_path, "rb") as f:
        token = f.read()
    try:
        raw = Fernet(key).decrypt(token)
    except InvalidToken:
        raise WrongPasswordError("Incorrect password, or the vault file is corrupted/tampered with.")
    _untar_bytes(raw, live_dir)


def wipe_live(live_dir: str):
    """Delete the decrypted working copy. Only safe to call right after seal() has captured its current state."""
    if os.path.exists(live_dir):
        shutil.rmtree(live_dir)
    os.makedirs(live_dir, exist_ok=True)
