"""Integration tests against the real Eufy cloud (email + password only).

Needs EUFY_EMAIL and EUFY_PASSWORD, from the environment or a .env file in the repo root.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import types
from pathlib import Path

import pytest
from aiohttp import ClientSession

_ROOT = Path(__file__).parent.parent
_PKG_DIR = _ROOT / "custom_components" / "eufy_anker_ha"
if "eufy_anker_ha" not in sys.modules:
    _pkg = types.ModuleType("eufy_anker_ha")
    _pkg.__path__ = [str(_PKG_DIR)]
    sys.modules["eufy_anker_ha"] = _pkg
api_mod = importlib.import_module("eufy_anker_ha.api")


def _load_env() -> None:
    env_file = _ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_env()

EMAIL = os.environ.get("EUFY_EMAIL")
PASSWORD = os.environ.get("EUFY_PASSWORD")
COUNTRY = os.environ.get("EUFY_COUNTRY", "US")
_LOGIN_CACHE = _ROOT / "login_cache.json"


def _load_cached_auth() -> dict:
    try:
        cached = json.loads(_LOGIN_CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if cached.get("email") != EMAIL or cached.get("country") != COUNTRY:
        return {}
    auth = cached.get("auth")
    return auth if isinstance(auth, dict) else {}


def _save_cached_auth(auth: dict) -> None:
    payload = {"email": EMAIL, "country": COUNTRY, "auth": auth}
    fd = os.open(_LOGIN_CACHE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as cache_file:
        os.fchmod(cache_file.fileno(), 0o600)
        json.dump(payload, cache_file, indent=2)
        cache_file.write("\n")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (EMAIL and PASSWORD), reason="EUFY_EMAIL / EUFY_PASSWORD not set"),
]


async def _login(session: ClientSession):
    api = api_mod.EufyApi(session, EMAIL, PASSWORD, auth=_load_cached_auth(), country=COUNTRY)
    try:
        if api.auth.get("token"):
            await api.get_cameras()
        else:
            await api.login()
    except api_mod.EufyCaptchaRequired:
        pytest.skip("account requires a captcha; log in via the app first")
    except api_mod.EufyTwoFactorRequired:
        pytest.skip("account requires 2FA; email/password only is supported here")
    _save_cached_auth(api.auth)
    return api


@pytest.mark.asyncio
async def test_login():
    async with ClientSession() as session:
        api = await _login(session)
        assert api.auth.get("token")
        assert api.auth.get("user_id")


@pytest.mark.asyncio
async def test_list_devices_returns_one(caplog):
    async with ClientSession() as session:
        api = await _login(session)
        devices = await api.get_cameras()
        # Store device info to root device_cache.json
        device_cache = _ROOT / "device_cache.json"
        fd = os.open(device_cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as cache_file:
            os.fchmod(cache_file.fileno(), 0o600)
            json.dump(api_mod.redact(devices), cache_file, indent=2)
            cache_file.write("\n")
        assert len(devices) == 1, [d.get("device_name") for d in devices]
        assert devices[0].get("device_sn")


@pytest.mark.asyncio
async def test_toggle_privacy_mode():
    async with ClientSession() as session:
        api = await _login(session)
        device = (await api.get_cameras())[0]

        async def read_privacy_value() -> str | None:
            params = await api.get_device_params(device["device_sn"])
            if params is None:
                fresh_device = next(
                    (item for item in await api.get_cameras() if item.get("device_sn") == device["device_sn"]),
                    None,
                )
                params = fresh_device.get("params") if fresh_device else None
            privacy_param = next(
                (
                    param
                    for param in params or []
                    if str(param.get("param_type")) == str(api_mod.PARAM_PRIVACY_6250)
                ),
                None,
            )
            return str(privacy_param.get("param_value")) if privacy_param else None

        original = await read_privacy_value()
        if original is None:
            pytest.skip("device does not report privacy param 6250")
        assert original in ("0", "1"), f"unexpected privacy param 6250 value: {original!r}"
        opposite = "0" if original == "1" else "1"

        try:
            for expected in (opposite, original):
                await api.set_privacy(device, expected == "1")
                actual = await read_privacy_value()
                assert actual is not None, "device status does not include privacy param 6250 after update"
                assert actual == expected, f"privacy param 6250: expected {expected}, got {actual}"
        finally:
            await api.set_privacy(device, original == "1")


@pytest.mark.asyncio
async def test_snapshot_returned():
    async with ClientSession() as session:
        api = await _login(session)
        device = (await api.get_cameras())[0]
        device_events = [
            event for event in await api.get_events()
            if event.get("device_sn") == device["device_sn"]
        ]
        latest_event = max(device_events, key=lambda event: event.get("create_time", 0), default=None)
        url = (latest_event or {}).get("pic_url") or device.get("cover_path")
        if not url:
            pytest.skip("device has no snapshot URL in recent events or cover_path")
        image = await api.get_image(url)
        assert image, "no image bytes returned"
        print(f"\nSNAPSHOT: {len(image)} bytes, header={image[:4]!r}")
        assert image[:2] == b"\xff\xd8" or image[:4] == b"\x89PNG", "not a JPEG/PNG"
