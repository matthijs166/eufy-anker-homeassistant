"""Constants for the Eufy Anker integration."""

DOMAIN = "eufy_anker_ha"
PLATFORMS = ["camera", "binary_sensor", "switch", "button", "sensor"]

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_AUTH = "auth"
CONF_CAMERAS = "cameras"
CONF_VERBOSE = "verbose_logging"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_LOG_PROPERTIES = "log_device_properties"

DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 10
MAX_SCAN_INTERVAL = 3600
PACKAGE_LOGGER = "custom_components.eufy_anker_ha"
MOTION_WINDOW = 60
