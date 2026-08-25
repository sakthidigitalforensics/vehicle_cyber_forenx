"""
Account storage for the public demo's login/signup gate.

This is deliberately separate from core/auth.py and core/vault.py, which are
the private tool's real password-plus-machine-lock-plus-encryption system
for a single analyst's own case data. That system has no notion of "a user
account" at all, it locks one laptop to one password. This module is a much
simpler, ordinary multi-user login: a name, an email, a bcrypt password
hash, and the date someone signed up, so the demo can require a real
account and cut access off after a 7 day trial.

Storage: a Postgres connection string in st.secrets["DATABASE_URL"] (a free
Neon or Supabase project works well here) is used when present, so accounts
survive a redeploy. If that secret isn't set, this falls back to a local
SQLite file under ./data/, which works with zero setup but, like the rest
of this demo's local data, is not guaranteed to survive every redeploy on
Streamlit Community Cloud's free tier.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from sqlalchemy import create_engine, text

TRIAL_DAYS = 7
SESSION_DAYS = 30

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _database_url():
    try:
        import streamlit as st
        url = st.secrets.get("DATABASE_URL")
        if url:
            return url
    except Exception:
        pass
    return os.environ.get("DATABASE_URL")


def _engine():
    url = _database_url()
    if url:
        return create_engine(url, pool_pre_ping=True)
    os.makedirs(_DATA_DIR, exist_ok=True)
    return create_engine(f"sqlite:///{os.path.join(_DATA_DIR, 'accounts.db')}")


_ENGINE = _engine()
USING_HOSTED_DB = bool(_database_url())


def init_db():
    with _ENGINE.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                signup_date TIMESTAMP NOT NULL,
                session_token TEXT,
                session_expires TIMESTAMP
            )
        """))


def _now():
    return datetime.now(timezone.utc)


def _to_dt(value):
    """Normalize a timestamp coming back from either backend into an aware datetime.
    SQLite (via the raw text() queries below) hands back plain strings; Postgres
    hands back real datetime objects. Both need a timezone attached if missing,
    since everything is written as UTC."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


class AccountExistsError(Exception):
    """Raised when signing up with an email that's already registered."""


class InvalidLoginError(Exception):
    """Raised when the email/password combination doesn't check out."""


def create_user(name, email, password):
    email = email.strip().lower()
    name = name.strip()
    if not name or not email or not password:
        raise ValueError("Name, email, and password are all required.")

    with _ENGINE.begin() as conn:
        existing = conn.execute(
            text("SELECT 1 FROM users WHERE email = :email"), {"email": email}
        ).fetchone()
        if existing:
            raise AccountExistsError(f"There's already an account for {email}.")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            text("""
                INSERT INTO users (email, name, password_hash, signup_date)
                VALUES (:email, :name, :password_hash, :signup_date)
            """),
            {"email": email, "name": name, "password_hash": password_hash, "signup_date": _now().isoformat()},
        )
    return get_user(email)


def verify_login(email, password):
    email = email.strip().lower()
    with _ENGINE.begin() as conn:
        row = conn.execute(
            text("SELECT email, name, password_hash, signup_date FROM users WHERE email = :email"),
            {"email": email},
        ).fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row.password_hash.encode()):
        raise InvalidLoginError("That email and password don't match an account here.")
    return {"email": row.email, "name": row.name, "signup_date": _to_dt(row.signup_date)}


def get_user(email):
    email = email.strip().lower()
    with _ENGINE.begin() as conn:
        row = conn.execute(
            text("SELECT email, name, signup_date FROM users WHERE email = :email"),
            {"email": email},
        ).fetchone()
    return {"email": row.email, "name": row.name, "signup_date": _to_dt(row.signup_date)} if row else None


def days_elapsed(signup_date):
    signup_date = _to_dt(signup_date)
    return (_now() - signup_date).days


def days_remaining(signup_date):
    return max(0, TRIAL_DAYS - days_elapsed(signup_date))


def create_session(email):
    token = secrets.token_urlsafe(32)
    expires = _now() + timedelta(days=SESSION_DAYS)
    with _ENGINE.begin() as conn:
        conn.execute(
            text("UPDATE users SET session_token = :token, session_expires = :expires WHERE email = :email"),
            {"token": token, "expires": expires.isoformat(), "email": email.strip().lower()},
        )
    return token, expires


def get_user_by_session_token(token):
    if not token:
        return None
    with _ENGINE.begin() as conn:
        row = conn.execute(
            text("""
                SELECT email, name, signup_date, session_expires FROM users
                WHERE session_token = :token
            """),
            {"token": token},
        ).fetchone()
    if not row:
        return None
    expires = _to_dt(row.session_expires)
    if expires and expires < _now():
        return None
    return {"email": row.email, "name": row.name, "signup_date": _to_dt(row.signup_date)}


def list_users():
    """Every account, newest signup first. Used only by the admin view in
    login_gate.py, never shown to an ordinary signed-in visitor."""
    with _ENGINE.begin() as conn:
        rows = conn.execute(
            text("SELECT email, name, signup_date FROM users ORDER BY signup_date DESC")
        ).fetchall()
    return [
        {"email": r.email, "name": r.name, "signup_date": _to_dt(r.signup_date)}
        for r in rows
    ]


def clear_session(email):
    with _ENGINE.begin() as conn:
        conn.execute(
            text("UPDATE users SET session_token = NULL, session_expires = NULL WHERE email = :email"),
            {"email": email.strip().lower()},
        )
