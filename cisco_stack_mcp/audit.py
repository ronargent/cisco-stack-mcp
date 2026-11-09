"""JSON-lines audit log: one line per tool call (ship to Wazuh with the host's other logs)."""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone

log = logging.getLogger("cisco_stack_mcp.audit")


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        directory = os.path.dirname(path)
        if directory:
            try:
                os.makedirs(directory, exist_ok=True)
            except OSError as exc:
                log.warning("cannot create audit directory %s: %s", directory, exc)

    def write(self, **fields) -> None:
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **fields}
        line = json.dumps(record, default=str, separators=(",", ":"))
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                # Never fail a read because the audit file is unwritable, but say so loudly.
                log.error("audit write failed (%s): %s", exc, line)
