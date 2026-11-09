"""Per-client bearer tokens (stored as SHA-256 hashes) and the ASGI middleware that checks them."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone

current_client: contextvars.ContextVar[str] = contextvars.ContextVar("current_client", default="unknown")

_PUBLIC_PATHS = {"/health"}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    """tokens.json: {"clients": {"aios": {"sha256": "...", "created": "..."}}}. Re-read when it changes."""

    def __init__(self, path: str):
        self.path = path
        self._mtime = None
        self._clients: dict[str, dict] = {}

    def _load(self) -> None:
        try:
            mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            self._clients, self._mtime = {}, None
            return
        if mtime != self._mtime:
            with open(self.path, encoding="utf-8") as fh:
                self._clients = (json.load(fh) or {}).get("clients", {})
            self._mtime = mtime

    def identify(self, token: str) -> str | None:
        self._load()
        digest = hash_token(token)
        found = None
        for name, rec in self._clients.items():
            if rec.get("disabled"):
                continue
            if hmac.compare_digest(digest, rec.get("sha256", "")):
                found = name
        return found

    # -- management (used by the mcp-token CLI) -------------------------------

    def _read_raw(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh) or {}
        except FileNotFoundError:
            return {}

    def _write_raw(self, data: dict) -> None:
        tmp = f"{self.path}.tmp"
        old_umask = os.umask(0o027)
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            # Keep the existing group and mode (root:cisco-mcp 0640) so the service can still read it.
            try:
                st = os.stat(self.path)
                os.chmod(tmp, st.st_mode & 0o777)
                if os.geteuid() == 0:
                    os.chown(tmp, st.st_uid, st.st_gid)
            except FileNotFoundError:
                pass
            os.replace(tmp, self.path)
        finally:
            os.umask(old_umask)

    def add(self, name: str) -> str:
        data = self._read_raw()
        clients = data.setdefault("clients", {})
        if name in clients:
            raise ValueError(f"client {name!r} already exists (use rotate)")
        token = secrets.token_urlsafe(32)
        clients[name] = {"sha256": hash_token(token), "created": _now()}
        self._write_raw(data)
        return token

    def rotate(self, name: str) -> str:
        data = self._read_raw()
        clients = data.setdefault("clients", {})
        if name not in clients:
            raise ValueError(f"no client {name!r}")
        token = secrets.token_urlsafe(32)
        clients[name].update(sha256=hash_token(token), rotated=_now(), disabled=False)
        self._write_raw(data)
        return token

    def revoke(self, name: str) -> None:
        data = self._read_raw()
        if name not in data.get("clients", {}):
            raise ValueError(f"no client {name!r}")
        del data["clients"][name]
        self._write_raw(data)

    def list(self) -> dict:
        return {k: {kk: vv for kk, vv in v.items() if kk != "sha256"}
                for k, v in self._read_raw().get("clients", {}).items()}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class BearerAuthMiddleware:
    """Pure ASGI middleware (keeps streaming responses intact)."""

    def __init__(self, app, store: TokenStore, disabled: bool = False):
        self.app = app
        self.store = store
        self.disabled = disabled

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in _PUBLIC_PATHS:
            return await self.app(scope, receive, send)
        if self.disabled:
            token_ctx = current_client.set("auth-disabled")
            try:
                return await self.app(scope, receive, send)
            finally:
                current_client.reset(token_ctx)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        client = None
        if auth[:7].lower() == "bearer ":
            client = self.store.identify(auth[7:].strip())
        if client is None:
            body = json.dumps({"error": "unauthorized"}).encode()
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"www-authenticate", b'Bearer realm="cisco-stack-mcp"')]})
            await send({"type": "http.response.body", "body": body})
            return
        token_ctx = current_client.set(client)
        try:
            await self.app(scope, receive, send)
        finally:
            current_client.reset(token_ctx)


class RateLimiter:
    """Sliding one-minute window of tool calls per client."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._calls: dict[str, list[float]] = {}

    def check(self, client: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        window = [t for t in self._calls.get(client, []) if now - t < 60]
        if len(window) >= self.per_minute:
            self._calls[client] = window
            return False
        window.append(now)
        self._calls[client] = window
        return True
