"""Stack inventory (stacks.yaml)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import yaml

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class InventoryError(ValueError):
    pass


@dataclass(frozen=True)
class Stack:
    name: str
    host: str
    site: str = ""
    expected_members: int = 2
    port: int | None = None
    description: str = ""

    def public(self) -> dict:
        return {
            "name": self.name,
            "host": self.host,
            "site": self.site,
            "expected_members": self.expected_members,
            "description": self.description,
        }


class Inventory:
    def __init__(self, stacks: list[Stack]):
        if not stacks:
            raise InventoryError("inventory has no stacks")
        self._stacks = {s.name: s for s in stacks}
        if len(self._stacks) != len(stacks):
            raise InventoryError("duplicate stack names in inventory")

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Inventory":
        stacks = []
        for i, raw in enumerate(data.get("stacks") or []):
            name = str(raw.get("name", "")).strip()
            host = str(raw.get("host", "")).strip()
            if not _NAME_RE.match(name):
                raise InventoryError(f"stack #{i + 1}: invalid name {name!r} (lowercase, digits, - _)")
            if not host or not _HOST_RE.match(host):
                raise InventoryError(f"stack {name}: invalid host {host!r}")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass  # a DNS name is fine
            members = int(raw.get("expected_members", 2))
            if not 1 <= members <= 8:
                raise InventoryError(f"stack {name}: expected_members must be 1-8 (C9300 stacks up to 8)")
            port = raw.get("port")
            stacks.append(Stack(
                name=name,
                host=host,
                site=str(raw.get("site", "") or ""),
                expected_members=members,
                port=int(port) if port else None,
                description=str(raw.get("description", "") or ""),
            ))
        return cls(stacks)

    def names(self) -> list[str]:
        return list(self._stacks)

    def get(self, name: str) -> Stack:
        try:
            return self._stacks[name]
        except KeyError:
            raise InventoryError(
                f"unknown stack {name!r}; known stacks: {', '.join(self._stacks)} (or 'all')"
            ) from None

    def resolve(self, name: str) -> list[Stack]:
        """'all' -> every stack, otherwise the named one."""
        if name in ("all", "*"):
            return list(self._stacks.values())
        return [self.get(name)]

    def all(self) -> list[Stack]:
        return list(self._stacks.values())
