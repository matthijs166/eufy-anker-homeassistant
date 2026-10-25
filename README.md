# Eufy Anker Cameras for Home Assistant

[![Open your Home Assistant instance and open this repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=matthijs166&repository=eufy-anker-homeassistant&category=integration)

A HACS custom integration that connects your Eufy (Anker) cameras to Home Assistant through the Eufy cloud.

> ⚠️ **Disclaimer:** this integration is **vibe coded** with **very little human review**. It has not been tested against real hardware and the Eufy cloud protocol is reverse engineered, so expect bugs. Use at your own risk.

> 💡 **Missing a feature?** [Create an issue](https://github.com/matthijs166/eufy-anker-homeassistant/issues) and I will build it.

## What it does (camera support only, for now)

For every camera you pick, the integration creates:

| Entity | Purpose |
| --- | --- |
| `camera` | Shows the **last image** of the camera |
| `binary_sensor` (Detection) | Turns on for 60 s after a detection event — use it as an **automation trigger** |
| `switch` (Privacy mode) | **Enable / disable privacy mode** |

Data is polled from the Eufy cloud every 30 seconds.

## Install

1. Click the button above (or in HACS: *Custom repositories* → add this repo as type *Integration*).
2. Download **Eufy Anker Cameras** in HACS and restart Home Assistant.
3. Add the integration: [![Add integration](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=eufy_anker)

## Setup

1. Enter your Eufy email and password.
2. If Eufy asks for a captcha and/or a **2FA code**, the setup dialog shows the prompt in the Home Assistant UI.
3. All cameras on your account are **listed** — tick the ones you want to add.
4. Change the selection any time via *Configure* on the integration.

Tip: create a second Eufy account, share your cameras with it, and use that account here.

## Credits

The login flow and the signed/encrypted `algo_ecdh` transport (region discovery, ECDH key exchange, encrypted passport login, captcha and 2FA) are a Python port of the work in **[mega-yfue/eufy-sdk](https://github.com/mega-yfue/eufy-sdk)** — big thanks to its authors. Not affiliated with Anker or Eufy.
