from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import re
import secrets
import sqlite3

import jwt
from pwdlib import PasswordHash
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from config import DB_PATH


router = APIRouter(prefix="/api/auth", tags=["Authentication"])
password_hash = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

TOKEN_HOURS = 12


def get_secret():
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET must contain at least 32 characters."
        )
    return secret


def connect_auth():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with connect_auth() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            jti TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
        ON auth_sessions(user_id);
        """)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


def public_user(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
    }


def create_session(user):
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=TOKEN_HOURS)
    jti = secrets.token_urlsafe(32)

    payload = {
        "sub": str(user["id"]),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }

    token = jwt.encode(payload, get_secret(), algorithm="HS256")

    with connect_auth() as conn:
        conn.execute(
            """
            INSERT INTO auth_sessions (jti, user_id, expires_at)
            VALUES (?, ?, ?)
            """,
            (jti, user["id"], int(expires.timestamp())),
        )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": public_user(user),
    }


def get_auth_session(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        payload = jwt.decode(
            credentials.credentials,
            get_secret(),
            algorithms=["HS256"],
        )
        jti = payload["jti"]
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    with connect_auth() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.name, u.email, s.jti
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.jti = ?
              AND s.user_id = ?
              AND s.revoked_at IS NULL
              AND s.expires_at > ?
            """,
            (jti, user_id, int(datetime.now(timezone.utc).timestamp())),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Session expired or revoked.")

    return dict(row)


@router.post("/register")
def register(data: RegisterRequest):
    name = data.name.strip()
    email = data.email.strip().lower()

    if not name:
        raise HTTPException(status_code=400, detail="Name is required.")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")

    hashed = password_hash.hash(data.password)
    now = datetime.now(timezone.utc).isoformat()

    try:
        with connect_auth() as conn:
            conn.execute(
                """
                INSERT INTO users (name, email, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, email, hashed, now),
            )
            user = conn.execute(
                "SELECT id, name, email FROM users WHERE email = ?",
                (email,),
            ).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    return create_session(user)


@router.post("/login")
def login(data: LoginRequest):
    email = data.email.strip().lower()

    with connect_auth() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not user or not password_hash.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    return create_session(user)


@router.get("/me")
def me(session=Depends(get_auth_session)):
    return {
        "user": {
            "id": session["id"],
            "name": session["name"],
            "email": session["email"],
        }
    }


@router.post("/logout")
def logout(session=Depends(get_auth_session)):
    now = datetime.now(timezone.utc).isoformat()

    with connect_auth() as conn:
        conn.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ?",
            (now, session["jti"]),
        )

    return {"message": "Logged out successfully."}