"""Async client for the Eufy (Anker) cloud.

Implements the signed/encrypted ``algo_ecdh`` transport and passport login
documented by https://github.com/mega-yfue/eufy-sdk. The protocol is reverse
engineered and may change without notice.

Login flow (``mega-client.ts`` in the SDK):
  1. ``estimate_domain`` on ``mega-{region}.eufy.com`` -> region shard.
  2. ECDH key exchange on the bootstrap host -> shareKey + X-Key-Ident that
     sign and encrypt every later call.
  3. ``/passport/login`` on ``app-passport-{region}.eufy.com``.
  4. Re-exchange the key with the auth token so it binds to the user.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any

from aiohttp import ClientError, ClientSession

from .p2p import CMD_CONTROL_PAYLOAD, CMD_SET_PAYLOAD, P2PError, P2PSession, decode_cloud_ips, keyframe_to_jpeg
from .crypto import (
    EUFYLIFE_LOCAL_KEY_HEX,
    MEGA_LOCAL_KEY_HEX,
    decrypt_body,
    encrypt_body,
    encrypt_login_password,
    finish_key_exchange,
    gtoken,
    prepare_key_exchange,
    signed_headers,
)

_LOGGER = logging.getLogger(__name__)

_SECRET_KEYS = {
    "password", "token", "auth_token", "x-auth-token", "authorization", "gtoken", "share_key",
    "public_key", "verify_code", "answer", "x-key-sign", "x-signature", "private_key",
}


def redact(obj: Any) -> Any:
    """Return a copy of obj with secrets masked, for verbose logging."""
    if isinstance(obj, dict):
        return {
            k: "***" if str(k).lower() in _SECRET_KEYS and v else redact(v) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _fmt(obj: Any, limit: int = 4000) -> str:
    try:
        text = obj if isinstance(obj, str) else json.dumps(redact(obj), default=str)
    except (TypeError, ValueError):
        text = str(obj)
    return text if len(text) <= limit else text[:limit] + f"...(+{len(text) - limit} chars)"


APP_NAME = "eufy_mega"
APP_VERSION = "6.0.41_26142"
OS_VERSION = "36"
PHONE_MODELS = ("Pixel 8", "Pixel 7", "SM-S911B", "OnePlus 11", "Redmi Note 12")
REGIONS = ("us-pr", "eu-pr")

PARAM_PRIVACY_MODE = 99904
# 6250 is the privacy param the camera itself reacts to and reports; 99904 is only
# written by us and can be stale.
PARAM_PRIVACY_6250 = 6250
PARAM_NIGHT_VISION = 1277
PTZ_COMMAND = 6030
PTZ_DIRECTIONS = {"left": 1, "right": 2, "up": 3, "down": 4}
PTZ_EVIDENCE_PARAMS = {1029, 6090, 6091, 6092, 6210}
PTZ_PRESET_DEVICE_TYPES = {38, 47, 48, 87, 89, 98, 104, 105, 111, 10008, 10009, 10010, 10011}
PTZ_DEVICE_TYPES = {31, 35, *PTZ_PRESET_DEVICE_TYPES}
PTZ_PRESET_COMMAND = 1700
PTZ_SAVE_PRESET_COMMAND = 6032
PTZ_GOTO_PRESET_COMMAND = 6035
DEFAULT_PTZ_PRESET = 0
KEY_TTL = 12 * 3600

CODE_OK = 0
CODE_IDENTITY_STALE = 4404
CODE_SIGNATURE_INVALID = 4416
CODE_PROBE_RETRY = 10000
CODE_BAD_PASSWORD = 26006
CODE_SESSION_KICKED = 26084
CODE_CAPTCHA_REQUIRED = 100032
CODE_CAPTCHA_WRONG = 100033
CODE_LOGIN_LIMIT = 100028


class EufyError(Exception):
    """Base error."""


class EufyConnectionError(EufyError):
    """Could not reach the Eufy cloud or got an unparseable response."""


class EufyAuthError(EufyError):
    """Invalid credentials or verification code."""


class EufyApiError(EufyError):
    """The cloud answered with an error envelope."""

    def __init__(self, message: str, code: int | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


class EufyRateLimited(EufyApiError):
    """Too many logins; retry_after is seconds to wait, if the server said."""

    def __init__(self, message: str, retry_after: int | None = None, code: int | None = None, status: int | None = None) -> None:
        super().__init__(message, code, status)
        self.retry_after = retry_after


def _retry_after_seconds(headers: dict[str, str], message: str = "") -> int | None:
    """Seconds to wait from rate-limit headers or an explicit server message."""
    for name in ("retry-after", "x-ratelimit-reset", "x-rate-limit-reset", "ratelimit-reset"):
        value = headers.get(name)
        if not value:
            continue
        try:
            seconds = int(float(value))
        except ValueError:
            try:
                from email.utils import parsedate_to_datetime

                seconds = int(parsedate_to_datetime(value).timestamp() - time.time())
            except (TypeError, ValueError):
                continue
        # large values are epoch timestamps
        if seconds > 10**9:
            seconds -= int(time.time())
        return max(seconds, 0)

    match = re.search(
        r"\b(?:retry|try again|wait|blocked|locked)(?:\s+(?:again|after|in|for))?\s*[:=]?\s*"
        r"(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b",
        message,
        re.IGNORECASE,
    )
    if match:
        amount = float(match.group(1))
        unit = match.group(2).lower()
        multiplier = 3600 if unit.startswith(("hour", "hr", "h")) else 60 if unit.startswith(("minute", "min", "m")) else 1
        return max(int(amount * multiplier), 0)
    return None


class EufyCaptchaRequired(EufyError):
    """A captcha must be answered."""

    def __init__(self, captcha_id: str, image: str) -> None:
        super().__init__("captcha required")
        self.captcha_id = captcha_id
        self.image = image


class EufyTwoFactorRequired(EufyError):
    """A 2FA verification code was sent to the user."""


def privacy_enabled(device: dict[str, Any]) -> bool:
    """Read the privacy-mode param (6250, else 99904) from a device record."""
    values = {str(p.get("param_type")): str(p.get("param_value")) for p in device.get("params") or []}
    for key in (PARAM_PRIVACY_6250, PARAM_PRIVACY_MODE):
        if str(key) in values:
            return values[str(key)] in ("1", "True", "true")
    return False


def supports_ptz(device: dict[str, Any]) -> bool:
    """Whether the device record identifies a pan/tilt camera."""
    model = str(device.get("device_model") or device.get("model") or "")
    if model.upper() == "T8134":
        return False
    params = {
        int(param["param_type"])
        for param in device.get("params") or []
        if str(param.get("param_type", "")).isdigit()
    }
    device_type = device.get("device_type", device.get("deviceType"))
    try:
        device_type = int(device_type)
    except (TypeError, ValueError):
        device_type = None
    return (
        bool(params & PTZ_EVIDENCE_PARAMS)
        or device_type in PTZ_DEVICE_TYPES
        or re.search(r"pan.{0,3}tilt|\bptz\b|\bpt\b|s3[45]0", model, re.IGNORECASE) is not None
        or model.upper() == "T8E00"
    )


def supports_ptz_presets(device: dict[str, Any]) -> bool:
    """Whether the device supports native PTZ preset save and recall commands."""
    device_type = device.get("device_type", device.get("deviceType"))
    try:
        device_type = int(device_type)
    except (TypeError, ValueError):
        return False
    return device_type in PTZ_PRESET_DEVICE_TYPES


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith(("<!doctype html", "<html", "<!--"))


def _proxy_error_message(url: str, status: int, text: str) -> str:
    """Describe a non-JSON (HTML) answer such as a Cloudflare/proxy error page."""
    match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    title = " ".join(match.group(1).split()) if match else ""
    if "cloudflare" in text.lower() or "cf-error" in text:
        who = "A Cloudflare/proxy error page"
    else:
        who = "An HTML error page"
    hint = (
        " The request was likely blocked or timed out by a Cloudflare/reverse proxy in front of "
        "Home Assistant or Eufy; try again via the local Home Assistant address."
    )
    return f"{who} was returned for {url} (HTTP {status}{': ' + title if title else ''}).{hint}"


class EufyApi:
    """Eufy cloud client."""

    def __init__(
        self,
        session: ClientSession,
        email: str,
        password: str,
        auth: dict[str, Any] | None = None,
        verbose: bool = False,
        country: str = "US",
    ) -> None:
        self.verbose = verbose
        self._session = session
        self._email = email
        self._password = password
        self._country = (country or "US").upper()
        self._auth: dict[str, Any] = dict(auth or {})
        self._openudid = self._auth.get("openudid") or hashlib.md5(
            f"eufy-mega:{email}".encode()
        ).hexdigest()[:16]
        self._phone_model = PHONE_MODELS[int(self._openudid, 16) % len(PHONE_MODELS)]
        self._region: str = self._auth.get("region") or "us-pr"
        self._bootstrap: str | None = self._auth.get("bootstrap")
        # session key of the mega host stack and per-host keys for eufylife hosts
        self._key: dict[str, Any] | None = None
        if self._auth.get("share_key") and self._auth.get("key_ident"):
            self._key = {
                "share_key": self._auth["share_key"],
                "ident": self._auth["key_ident"],
                "at": time.time(),
            }
        self._host_keys: dict[str, dict[str, Any]] = {}
        self._content_types: dict[str, str] = {}
        self._last_headers: dict[str, str] = {}
        self._captcha_id = ""
        self._pending_2fa = False

    def _vlog(self, msg: str, *args: Any) -> None:
        if self.verbose:
            _LOGGER.info("[verbose] " + msg, *args)

    # -- state ------------------------------------------------------------

    @property
    def auth(self) -> dict[str, Any]:
        """Serialisable auth state for storing in the config entry."""
        out = {**self._auth, "openudid": self._openudid, "region": self._region}
        if self._bootstrap:
            out["bootstrap"] = self._bootstrap
        if self._key:
            out.update(share_key=self._key["share_key"], key_ident=self._key["ident"])
        return out

    def _base_headers(self) -> dict[str, str]:
        return {
            "app-name": APP_NAME,
            "app-version": APP_VERSION,
            "app_version": APP_VERSION,
            "os-type": "android",
            "os_type": "android",
            "os-version": OS_VERSION,
            "os_version": OS_VERSION,
            "phone-model": self._phone_model,
            "phone_model": self._phone_model,
            "model-type": "PHONE",
            "country": self._country,
            "ab_code": self._country,
            "openudid": self._openudid,
            "language": "en",
            "test-flag": "false",
            "user-agent": "ktor-client",
            "accept": "application/json",
            "accept-charset": "UTF-8",
        }

    def _token_headers(self) -> dict[str, str]:
        token = self._auth.get("token")
        if not token:
            return {}
        uid = self._auth.get("account_user_id") or self._auth.get("user_id", "")
        return {"x-auth-token": token, "authorization": token, "gtoken": gtoken(uid)}

    # -- transport --------------------------------------------------------

    async def _http_post(self, url: str, body: str, headers: dict[str, str]) -> tuple[int, Any]:
        self._vlog("HTTP POST %s headers=%s body=%s", url, _fmt(headers), _fmt(body, 500))
        try:
            async with self._session.post(url, data=body.encode(), headers=headers, timeout=20) as resp:
                text = await resp.text()
                self._last_headers = {k.lower(): v for k, v in resp.headers.items()}
                self._vlog("HTTP response headers: %s", _fmt(self._last_headers, 1500))
                self._vlog("HTTP POST %s -> HTTP %s: %s", url, resp.status, _fmt(text, 1500))
                try:
                    return resp.status, json.loads(text) if text else {}
                except ValueError:
                    pass
                if _looks_like_html(text) or "cf-ray" in resp.headers or "cloudflare" in resp.headers.get("server", "").lower():
                    raise EufyConnectionError(_proxy_error_message(url, resp.status, text))
                return resp.status, text
        except (ClientError, TimeoutError) as err:
            raise EufyConnectionError(
                f"Request to {url} failed: {type(err).__name__}: {err or 'no details'}"
            ) from err

    async def _estimate_domain(self) -> None:
        """Discover the region shard (step 1)."""
        last: Exception | None = None
        self._vlog("estimate_domain: start region=%s country=%s", self._region, self._country)
        for region in dict.fromkeys((self._region, *REGIONS)):
            try:
                status, res = await self._http_post(
                    f"https://mega-{region}.eufy.com/passport/estimate_domain",
                    json.dumps({"ab": self._country.lower(), "mode": 1}),
                    {**self._base_headers(), "content-type": "application/json"},
                )
            except EufyConnectionError as err:
                last = err
                continue
            data = res.get("data") if isinstance(res, dict) else None
            if status != 200 or not isinstance(data, dict):
                last = EufyConnectionError(f"estimate_domain on {region} failed (HTTP {status}): {str(res)[:200]}")
                continue
            domain = str(data.get("domain") or data.get("host") or data.get("server_secret_info") or "")
            blob = json.dumps(data)
            if "-eu-" in blob or "-eu-" in domain:
                self._region = "eu-pr"
            elif "-us-" in blob or "-us-" in domain:
                self._region = "us-pr"
            else:
                self._region = region
            self._bootstrap = domain if domain and not domain.startswith("mega-") else None
            self._vlog("estimate_domain: region=%s bootstrap=%s", self._region, self._bootstrap)
            return
        raise last or EufyConnectionError("estimate_domain failed")

    async def _ensure_key(self, host: str | None = None) -> dict[str, Any]:
        """Return the session key for the mega stack or a eufylife host (step 2)."""
        lifehost = bool(host and ".eufylife.com" in host)
        cached = self._host_keys.get(host or "") if lifehost else self._key
        if cached and time.time() - cached["at"] < KEY_TTL:
            return cached
        target = host if lifehost else (self._bootstrap or f"app-openapi-{self._region}.eufy.com")
        path = "/v3/openapi/oauth/key/exchange" if lifehost else "/openapi/oauth/key/exchange"
        self._vlog("key exchange with %s (lifehost=%s)", target, lifehost)
        prep = prepare_key_exchange(EUFYLIFE_LOCAL_KEY_HEX if lifehost else MEGA_LOCAL_KEY_HEX)
        status, res = await self._http_post(
            f"https://{target}{path}",
            json.dumps(prep["body"]),
            {
                **self._base_headers(),
                **prep["headers"],
                **self._token_headers(),
                "content-type": "application/json",
            },
        )
        env = res if isinstance(res, dict) else {}
        server_pub = (env.get("data") or {}).get("server_public_key") if isinstance(env.get("data"), dict) else None
        if status != 200 or env.get("code") != CODE_OK or not server_pub:
            raise EufyApiError(
                f"key exchange on {target} failed (HTTP {status}/{env.get('code')}): "
                f"{env.get('msg') or str(res)[:160]}",
                env.get("code"),
                status,
            )
        self._vlog("key exchange ok, ident=%s", prep["ident"])
        entry = {"share_key": finish_key_exchange(prep, server_pub), "ident": prep["ident"], "at": time.time()}
        if lifehost:
            self._host_keys[host or ""] = entry
        else:
            self._key = entry
        return entry

    async def _post_signed(
        self, host: str, path: str, body: Any, authed: bool = True, _retried: bool = False
    ) -> Any:
        """Signed + encrypted POST; returns the decrypted ``data``."""
        self._vlog("REQUEST https://%s%s authed=%s body=%s", host, path, authed, _fmt(body))
        entry = await self._ensure_key(host)
        enc_body = encrypt_body(json.dumps(body if body is not None else {}), entry["share_key"])
        cached = self._content_types.get(host)
        wants_text = "/passport/" in path or ".eufylife.com" in host
        preferred = cached or ("text/plain" if wants_text else "application/json")
        order = [preferred, "application/json" if preferred == "text/plain" else "text/plain"]
        code: int | None = None
        status = 0
        msg = ""
        for content_type in order:
            headers = {
                **self._base_headers(),
                "content-type": content_type,
                **signed_headers(entry["ident"], entry["share_key"], enc_body),
                "x-replay-info": "replay",
            }
            if authed:
                headers.update(self._token_headers())
            status, res = await self._http_post(f"https://{host}{path}", enc_body, headers)
            env = res if isinstance(res, dict) else {}
            code = env.get("code")
            if status == 200 and code == CODE_OK:
                self._content_types[host] = content_type
                data = env.get("data")
                if isinstance(data, str) and data:
                    plain = decrypt_body(data, entry["share_key"])
                    try:
                        data = json.loads(plain)
                    except ValueError:
                        data = plain
                self._vlog("RESPONSE %s%s -> %s", host, path, _fmt(data))
                return data
            msg = str(env.get("msg") or res)[:200]
            data = env.get("data")
            if isinstance(data, str) and data:
                try:
                    msg += f" | data={decrypt_body(data, entry['share_key'])[:300]}"
                except Exception:  # noqa: BLE001 - not decryptable
                    pass
            if not (
                (status == 403 and code == CODE_SIGNATURE_INVALID) or code == CODE_PROBE_RETRY or status == 400
            ):
                break
        if authed and not _retried and (code == CODE_IDENTITY_STALE or "identity error" in msg.lower()):
            if ".eufylife.com" in host:
                self._host_keys.pop(host, None)
            else:
                self._key = None
            return await self._post_signed(host, path, body, authed, True)
        self._vlog("RESPONSE %s%s FAILED HTTP %s code=%s msg=%s", host, path, status, code, msg)
        if code == CODE_LOGIN_LIMIT or status == 429:
            retry_after = _retry_after_seconds(self._last_headers, msg)
            _LOGGER.warning(
                "Eufy rate limit on %s (HTTP %s/%s), retry_after=%s, headers=%s",
                path, status, code, retry_after, self._last_headers,
            )
            wait = (
                f"retry in about {-(-retry_after // 60)} min"
                if retry_after is not None
                else "Eufy did not provide a retry time; wait before trying again"
            )
            raise EufyRateLimited(
                f"{path} rate limited (HTTP {status}/{code}): {msg}; {wait}",
                retry_after, code, status,
            )
        raise EufyApiError(f"{path} failed (HTTP {status}/{code}): {msg}", code, status)

    def _mega_host(self, service: str) -> str:
        return f"app-{service}-{self._region}.eufy.com"

    def _security_host(self) -> str:
        shard = self._region.split("-")[0]
        return "security-app.eufylife.com" if shard == "us" else f"security-app-{shard}.eufylife.com"

    # -- login ------------------------------------------------------------

    def _login_body(self, captcha_id: str, answer: str, verify_code: str | None) -> dict[str, Any]:
        public_key, password = encrypt_login_password(self._password)
        body: dict[str, Any] = {
            "email": self._email,
            "password": password,
            "ab": self._country,
            "client_secret_info": {"public_key": public_key},
        }
        if verify_code:
            return {**body, "verify_code": verify_code, "login_id": ""}
        if captcha_id:
            return {**body, "answer": answer, "captcha_id": captcha_id, "verify_code": "", "login_id": ""}
        return {**body, "answer": "", "captcha_id": "", "verify_code": "", "login_id": ""}

    async def _generate_captcha(self) -> tuple[str, str]:
        res = await self._post_signed(self._mega_host("passport"), "/passport/generate/captcha", {}, False)
        return res.get("captcha_id", ""), res.get("item", "")

    async def login(
        self,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
        verify_code: str | None = None,
    ) -> None:
        """Log in. Raises captcha / 2FA exceptions when more input is needed."""
        verifying = bool(verify_code) and self._pending_2fa
        self._vlog(
            "LOGIN start email=%s captcha=%s verify_code=%s 2fa_pending=%s",
            self._email, bool(captcha_id), bool(verify_code), self._pending_2fa,
        )
        if not verifying:
            # a fresh attempt must not carry an old token or key
            self._auth.pop("token", None)
            self._key = None
            if not (captcha_id or self._captcha_id):
                await self._estimate_domain()
            await self._ensure_key()
        elif not self._key:
            await self._ensure_key()
        body = self._login_body(
            (captcha_id or self._captcha_id) if captcha_answer else "",
            captcha_answer or "",
            verify_code if verifying else None,
        )
        try:
            res = await self._post_signed(
                self._mega_host("passport"), "/passport/login", body, authed=verifying
            )
        except EufyApiError as err:
            if err.code in (CODE_CAPTCHA_REQUIRED, CODE_CAPTCHA_WRONG):
                self._captcha_id, image = await self._generate_captcha()
                raise EufyCaptchaRequired(self._captcha_id, image) from err
            if err.code == CODE_BAD_PASSWORD or "password" in str(err).lower():
                raise EufyAuthError(str(err)) from err
            raise
        if not isinstance(res, dict):
            raise EufyError(f"login returned no session: {str(res)[:200]}")
        user_id = res.get("ap_cloud_user_id") or res.get("user_id") or res.get("userId")
        token = res.get("auth_token") or res.get("token")
        if not user_id or not token:
            raise EufyError(f"login returned no session: {json.dumps(res)[:200]}")
        self._auth.update(
            token=token,
            user_id=user_id,
            account_user_id=res.get("user_id") or res.get("userId") or user_id,
            expires=int(res.get("token_expires_at") or 0),
        )
        self._captcha_id = ""
        if not verifying and (res.get("fa_info") or {}).get("info"):
            # keep the limited token: the code and the verify-login must carry it
            self._pending_2fa = True
            await self._post_signed(
                self._mega_host("push"),
                "/app/sendmsg/verify_code",
                {"biz_type": 1004, "message_type": 2, "transaction": str(int(time.time() * 1000))},
            )
            raise EufyTwoFactorRequired
        self._pending_2fa = False
        self._vlog("LOGIN ok user_id=%s token_expires=%s", self._auth.get("user_id"), self._auth.get("expires"))
        # re-exchange WITH the token so the gateway binds the key ident to the user
        self._key = None
        await self._ensure_key()

    # -- data -------------------------------------------------------------

    async def _authed(self, host_kind: str, path: str, body: dict[str, Any], service: str = "") -> Any:
        """Authed call; logs in first / again when the session is gone."""

        async def call() -> Any:
            host = self._security_host() if host_kind == "security" else self._mega_host(service)
            return await self._post_signed(host, path, body)

        self._vlog("CALL %s %s service=%s", host_kind, path, service)
        if not self._auth.get("token"):
            await self.login()
        try:
            return await call()
        except EufyApiError as err:
            if err.status != 401 and err.code != CODE_SESSION_KICKED:
                raise
        self._vlog("session rejected, logging in again")
        await self.login()
        return await call()

    async def get_cameras(self) -> list[dict[str, Any]]:
        """Return all devices of the account (merged across houses)."""
        self._vlog("get_cameras: fetching house + device lists")
        bodies: list[dict[str, Any]] = [{}]
        try:
            houses = await self._authed("mega", "/app/house/get_house_list", {}, "house")
            bodies += [{"house_id": h["house_id"]} for h in (houses or {}).get("house_infos") or []]
        except EufyApiError as err:
            _LOGGER.debug("get_house_list failed: %s", err)
            self._vlog("get_house_list failed: %s", err)
        seen: dict[str, dict[str, Any]] = {}
        for body in bodies:
            data = await self._authed("mega", "/app/house/get_devs_list", body, "house")
            for dev in (data or {}).get("devices") or []:
                if dev.get("device_sn"):
                    seen[dev["device_sn"]] = dev
        self._vlog("get_cameras: %d devices: %s", len(seen), {k: v.get("device_name") for k, v in seen.items()})
        return list(seen.values())

    async def get_events(self) -> list[dict[str, Any]]:
        """Return recent alarm/motion events across all devices."""
        self._vlog("get_events: fetching alarm records")
        data = await self._authed(
            "security",
            "/v1/event/app/get_all_alarm_record",
            {"device_sn": "", "end_time": 0, "start_time": 0, "num": 50,
             "pullup": True, "shared": True, "station_sn": ""},
        )
        return data if isinstance(data, list) else []

    async def get_image(self, url: str) -> bytes | None:
        """Download an image."""
        async with self._session.get(url) as resp:
            self._vlog("GET image %s -> HTTP %s", url, resp.status)
            return await resp.read() if resp.status == 200 else None

    async def get_dsk_key(self, device_sn: str) -> str | None:
        """Per-station key the PPCS cloud lookup needs."""
        data = await self._authed(
            "mega",
            "/app/devicerelation/get_dsk_keys",
            {
                "device_dsks": [{"invalid_dsk": "", "device_sn": device_sn, "category": "eufy_security"}],
                "invalid_dsks": {device_sn: ""},
                "station_sns": [device_sn],
            },
            "devicerelation",
        )
        for entry in (data or {}).get("device_dsks") or []:
            if entry.get("device_sn") == device_sn:
                return entry.get("dsk_key")
        return None

    async def _open_p2p(self, device: dict[str, Any]) -> P2PSession:
        did = device.get("p2p_did")
        if not did:
            raise P2PError(f"{device.get('device_sn')} has no p2p_did")
        sn = device["device_sn"]
        try:
            dsk = await self.get_dsk_key(sn)
        except EufyApiError as err:
            _LOGGER.debug("get_dsk_keys failed, using local lookup only: %s", err)
            dsk = None
        conn = device.get("p2p_conn") or device.get("app_conn")
        lan = next(
            (p.get("param_value") for p in device.get("params") or [] if str(p.get("param_type")) == "1176"),
            None,
        ) or device.get("ip_addr") or None
        account_id = (device.get("member") or {}).get("admin_user_id") or self._auth.get("user_id", "")
        return P2PSession(
            sn, did, account_id,
            cloud_addrs=decode_cloud_ips(conn) if conn else None,
            dsk_key=dsk, local_addr=lan, channel=device.get("device_channel") or 0,
        )

    async def get_cipher_key(self, cipher_id: int, user_id: str) -> dict[str, Any] | None:
        """Cloud-held key material (RSA and/or ECC) the camera's level-2 session key is sealed to."""
        data = await self._authed(
            "security",
            "/v1/app/cipher/get_ciphers",
            {"cipher_ids": [cipher_id], "user_id": user_id, "transaction": str(int(time.time() * 1000))},
        )
        items = data if isinstance(data, list) else (data or {}).get("ciphers") or []
        return next((item for item in items if item.get("cipher_id") == cipher_id), None)

    async def _push_to_device(
        self, device: dict[str, Any], message: dict[str, Any], cmd_id: int = CMD_CONTROL_PAYLOAD
    ) -> int | None:
        """Apply a setting on the camera itself; the cloud write alone is not picked up by the device."""
        sn = device.get("device_sn")
        try:
            session = await self._open_p2p(device)
            try:
                await session.connect(20.0)
                if await session.wait_gateway() and session.cipher_id:
                    account_id = (device.get("member") or {}).get("admin_user_id") or self._auth.get("user_id", "")
                    cipher = await self.get_cipher_key(session.cipher_id, account_id)
                    if cipher:
                        session.set_cipher(cipher.get("private_key"), cipher.get("ecc_private_key"))
                code = await session.send_control(message, cmd_id)
            finally:
                await session.close()
        except (P2PError, EufyError, ValueError, OSError) as err:
            _LOGGER.warning("Could not apply setting on camera %s over P2P: %s", sn, err)
            return None
        self._vlog("p2p push %s cmd=%s msg=%s result=%s", sn, cmd_id, message, code)
        if code not in (0, None):
            _LOGGER.warning("Camera %s rejected setting %s (code %s)", sn, message, code)
        return code

    async def _push_setting(self, device: dict[str, Any], cmd: int, payload: dict[str, Any]) -> None:
        """Wrapped CMD_SET_PAYLOAD envelope the Eufy app uses for per-device settings."""
        account_id = (device.get("member") or {}).get("admin_user_id") or self._auth.get("user_id", "")
        message = {"account_id": account_id, "cmd": cmd, "mChannel": device.get("device_channel") or 0, "mValue3": 0, "payload": payload}
        await self._push_to_device(device, message, CMD_SET_PAYLOAD)

    async def open_live_session(self, device: dict[str, Any], timeout: float = 20.0):
        """Connected P2P session ready for stream(); caller must close it."""
        session = await self._open_p2p(device)
        try:
            await session.connect(timeout)
            if await session.wait_gateway() and session.cipher_id:
                account_id = (device.get("member") or {}).get("admin_user_id") or self._auth.get("user_id", "")
                cipher = await self.get_cipher_key(session.cipher_id, account_id)
                if cipher:
                    session.set_cipher(cipher.get("private_key"), cipher.get("ecc_private_key"))
        except BaseException:
            await session.close()
            raise
        return session

    async def get_snapshot(self, device: dict[str, Any], ffmpeg: str = "ffmpeg", timeout: float = 20.0) -> bytes:
        """Fresh JPEG from the camera's live P2P stream."""
        session = await self._open_p2p(device)
        try:
            await session.connect(timeout)
            codec, annexb = await session.capture_keyframe(timeout)
        finally:
            await session.close()
        return await keyframe_to_jpeg(codec, annexb, ffmpeg)

    async def get_device_params(self, device_sn: str) -> list[dict[str, Any]] | None:
        """Fresh param list of one device (owner-only endpoint; None when unavailable)."""
        try:
            data = await self._authed(
                "mega", "/app/devicemanage/get_device_param_list", {"device_sns": [device_sn]}, "devicemanage"
            )
        except EufyApiError as err:
            self._vlog("get_device_param_list unavailable for %s: %s", device_sn, err)
            return None
        items = data if isinstance(data, list) else (data or {}).get("params") or (data or {}).get("device_params")
        return items if isinstance(items, list) else None

    async def set_privacy(self, device: dict[str, Any], enabled: bool) -> None:
        """Turn privacy mode on or off (writes 99904, plus 6250 when the device has it)."""
        push = asyncio.create_task(self._push_setting(device, PARAM_PRIVACY_6250, {"switch": int(enabled)}))
        try:
            present = {str(p.get("param_type")) for p in device.get("params") or []}
            if str(PARAM_PRIVACY_6250) not in present:
                fresh_params = await self.get_device_params(device["device_sn"])
                present.update(str(p.get("param_type")) for p in fresh_params or [])
            types = [PARAM_PRIVACY_MODE] + ([PARAM_PRIVACY_6250] if str(PARAM_PRIVACY_6250) in present else [])
            value = "1" if enabled else "0"
            self._vlog("set_privacy %s -> %s params=%s", device.get("device_sn"), value, types)
            res = await self._upload_privacy(device, types, value)
        finally:
            await push
        self._vlog("set_privacy %s result=%s", device.get("device_sn"), _fmt(res))

    async def _upload_privacy(self, device: dict[str, Any], types: list, value: str):
        return await self._authed(
            "security",
            "/v1/app/upload_devs_params",
            {
                "device_sn": device["device_sn"],
                "station_sn": device.get("station_sn", device["device_sn"]),
                "params": [{"param_type": t, "param_value": value} for t in types],
                "transaction": str(int(time.time() * 1000)),
            },
        )

    async def set_night_vision(self, device: dict[str, Any], mode: int) -> None:
        """Set night vision type (param 1277: 0 off, 1 auto, 3 on)."""
        self._vlog("set_night_vision %s -> %s", device.get("device_sn"), mode)
        push = asyncio.create_task(
            self._push_setting(device, PARAM_NIGHT_VISION, {"channel": device.get("device_channel") or 0, "night_sion": mode})
        )
        try:
            res = await self._authed(
                "security",
                "/v1/app/upload_devs_params",
                {
                    "device_sn": device["device_sn"],
                    "station_sn": device.get("station_sn", device["device_sn"]),
                    "params": [{"param_type": PARAM_NIGHT_VISION, "param_value": str(mode)}],
                    "transaction": str(int(time.time() * 1000)),
                },
            )
        finally:
            await push
        self._vlog("set_night_vision %s result=%s", device.get("device_sn"), _fmt(res))

    async def move_ptz(self, device: dict[str, Any], direction: str) -> None:
        """Move a PTZ camera one step in the requested direction over P2P."""
        if direction not in PTZ_DIRECTIONS:
            raise ValueError(f"Unsupported PTZ direction: {direction}")
        message = {
            "commandType": PTZ_COMMAND,
            "data": {"cmd_type": 1, "rotate_type": PTZ_DIRECTIONS[direction], "zoom": 1.0},
        }
        await self._push_to_device(device, message)

    async def save_default_ptz_position(self, device: dict[str, Any]) -> None:
        """Save the current PTZ position to the camera's default preset slot."""
        if not supports_ptz_presets(device):
            raise ValueError("Device does not support PTZ presets")
        await self._push_to_device(
            device,
            {"commandType": PTZ_SAVE_PRESET_COMMAND, "data": {"value": DEFAULT_PTZ_PRESET}},
        )

    async def go_to_default_ptz_position(self, device: dict[str, Any]) -> None:
        """Move the camera to its saved default preset position."""
        if not supports_ptz_presets(device):
            raise ValueError("Device does not support PTZ presets")
        await self._push_to_device(
            device,
            {"commandType": PTZ_GOTO_PRESET_COMMAND, "data": {"value": DEFAULT_PTZ_PRESET}},
        )
