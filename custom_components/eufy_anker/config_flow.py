"""Config flow with captcha and 2FA support."""
from __future__ import annotations

from typing import Any

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import EufyApi, EufyAuthError, EufyCaptchaRequired, EufyError, EufyTwoFactorRequired
from .const import CONF_AUTH, CONF_CAMERAS, CONF_EMAIL, CONF_PASSWORD, DOMAIN

_LOGGER = logging.getLogger(__name__)

CONF_DEBUG = "debug"


async def _camera_options(api: EufyApi) -> dict[str, str]:
    cams = await api.get_cameras()
    return {c["device_sn"]: f"{c.get('device_name', c['device_sn'])} ({c['device_sn']})" for c in cams}


class EufyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._api: EufyApi | None = None
        self._creds: dict[str, str] = {}
        self._captcha_id = ""
        self._captcha_image = ""
        self._options: dict[str, str] = {}
        self._error_detail = ""

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return EufyOptionsFlow()

    async def _try_login(self, step: str, errors: dict, **kwargs):
        assert self._api
        try:
            await self._api.login(**kwargs)
            self._options = await _camera_options(self._api)
        except EufyCaptchaRequired as err:
            self._captcha_id, self._captcha_image = err.captcha_id, err.image
            return await self.async_step_captcha()
        except EufyTwoFactorRequired:
            return await self.async_step_2fa()
        except EufyAuthError as err:
            self._error_detail = str(err)
            errors["base"] = "invalid_auth"
        except EufyError as err:
            _LOGGER.error("Eufy login failed: %s", err, exc_info=self._api.debug)
            self._error_detail = str(err)
            errors["base"] = "cannot_connect"
        else:
            return await self.async_step_cameras()
        return None

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        self._error_detail = ""
        if user_input:
            self._creds = {k: v for k, v in user_input.items() if k != CONF_DEBUG}
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()
            self._api = EufyApi(async_get_clientsession(self.hass), user_input[CONF_EMAIL], user_input[CONF_PASSWORD],
                debug=user_input.get(CONF_DEBUG, False),
                country=self.hass.config.country or "US",
            )
            if result := await self._try_login("user", errors):
                return result
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_DEBUG, default=False): bool,
                }
            ),
            description_placeholders={"error": self._error_detail},
            errors=errors,
        )

    async def async_step_captcha(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input:
            if result := await self._try_login(
                "captcha", errors, captcha_id=self._captcha_id, captcha_answer=user_input["captcha"]
            ):
                return result
        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema({vol.Required("captcha"): str}),
            description_placeholders={
                "image": f"![captcha]({self._captcha_image})",
                "error": self._error_detail,
            },
            errors=errors,
        )

    async def async_step_2fa(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input:
            if result := await self._try_login("2fa", errors, verify_code=user_input["code"]):
                return result
        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({vol.Required("code"): str}),
            description_placeholders={"error": self._error_detail},
            errors=errors,
        )

    async def async_step_cameras(self, user_input: dict[str, Any] | None = None):
        assert self._api
        if user_input:
            return self.async_create_entry(
                title=self._creds[CONF_EMAIL],
                data={**self._creds, CONF_AUTH: self._api.auth, CONF_CAMERAS: user_input[CONF_CAMERAS]},
            )
        return self.async_show_form(
            step_id="cameras",
            data_schema=vol.Schema(
                {vol.Required(CONF_CAMERAS, default=list(self._options)): cv.multi_select(self._options)}
            ),
        )


class EufyOptionsFlow(OptionsFlow):
    """Change which cameras are added."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input:
            return self.async_create_entry(data=user_input)
        coordinator = self.hass.data[DOMAIN][self.config_entry.entry_id]
        options = await _camera_options(coordinator.api)
        current = [c for c in coordinator.cameras if c in options]
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required(CONF_CAMERAS, default=current): cv.multi_select(options)}),
        )
