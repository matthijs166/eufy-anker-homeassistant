"""Decode a device record into a readable property dump."""
from __future__ import annotations

import base64
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .api import redact


@lru_cache(maxsize=1)
def _names() -> dict[str, list[str]]:
    return json.loads((Path(__file__).parent / "param_names.json").read_text())


def _decode(value: Any) -> Any:
    """Decode base64-wrapped JSON param values; return the value unchanged otherwise."""
    if not isinstance(value, str) or len(value) < 8:
        return value
    try:
        return json.loads(base64.b64decode(value, validate=True).decode())
    except Exception:  # noqa: BLE001 - not base64 JSON
        pass
    try:
        return json.loads(value) if value[0] in "{[" else value
    except ValueError:
        return value


def describe_device(device: dict[str, Any]) -> dict[str, Any]:
    """Return device fields plus params as {id: {name, type, value, updated}}."""
    names = _names()
    params: dict[str, Any] = {}
    for p in sorted(device.get("params") or [], key=lambda x: int(x.get("param_type") or 0)):
        pid = str(p.get("param_type"))
        name, kind = names.get(pid, (None, None))
        params[pid] = {
            "name": name,
            "type": kind,
            "value": _decode(p.get("param_value")),
            "updated": p.get("update_time"),
        }
    rest = {k: v for k, v in device.items() if k != "params"}
    return {"device": redact(rest), "params": redact(params)}
