"""Manage client bearer tokens: cisco-stack-mcp-token add|rotate|revoke|list <client>."""

from __future__ import annotations

import argparse
import re
import sys

from .auth import TokenStore
from .config import Settings

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cisco-stack-mcp-token", description=__doc__)
    ap.add_argument("action", choices=["add", "rotate", "revoke", "list"])
    ap.add_argument("client", nargs="?", help="client name, e.g. aios, claude-code, mac-mini")
    ap.add_argument("--file", default=None, help="tokens file (default: $CSM_TOKENS_FILE)")
    args = ap.parse_args(argv)
    store = TokenStore(args.file or Settings().tokens_file)

    if args.action == "list":
        clients = store.list()
        if not clients:
            print("no clients")
        for name, meta in clients.items():
            print(f"{name:20} {meta}")
        return 0
    if not args.client or not _NAME_RE.match(args.client):
        print("client name required: lowercase letters, digits, - or _", file=sys.stderr)
        return 2
    try:
        if args.action == "add":
            token = store.add(args.client)
        elif args.action == "rotate":
            token = store.rotate(args.client)
        else:
            store.revoke(args.client)
            print(f"revoked {args.client}")
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Token for {args.client} (shown once, store it in the client's secret store, never in chat):")
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
