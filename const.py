from datetime import timedelta

DOMAIN = "hondalink"

CONF_EMAIL = "email"
CONF_PASSWORD = "password"
CONF_VIN = "vin"
CONF_NAME = "name"
CONF_CLIENT_REG_KEY = "client_reg_key"
CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_EXPIRES_AT = "expires_at"
CONF_COUNTRY = "country"
CONF_LANGUAGE = "language"
CONF_HIDAS_IDENT = "hidas_ident"
CONF_DEVICE_ID = "device_id"
CONF_SESSION_ID = "session_id"
CONF_VEHICLE_INFO = "vehicle_info"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_LOGIN_TIMES = "login_times"
CONF_LOGIN_FAILURES = "login_failures"

DEFAULT_NAME = "HondaLink"
DEFAULT_COUNTRY = "US"
DEFAULT_LANGUAGE = "en"
DEFAULT_SCAN_INTERVAL = 15  # minutes
MIN_SCAN_INTERVAL = 5  # minutes
MAX_SCAN_INTERVAL = 1440  # minutes
MAX_BACKOFF_INTERVAL = 60  # minutes, cap for failure backoff
# Failed password sign-ins (the ones that can lock an account) allowed per rolling window.
# An attempt whose outcome is unknown (timeout, crash) counts as failed.
LOGIN_FAILURE_BUDGET_HOUR = 3  # per rolling hour
LOGIN_FAILURE_BUDGET_DAY = 8  # per rolling 24 h
# All password sign-ins, successful or not: a loop guard in case tokens expire quickly.
LOGIN_BUDGET_HOUR = 6  # per rolling hour
LOGIN_BUDGET_DAY = 100  # per rolling 24 h
REFRESH_COOLDOWN_SECONDS = 900  # min seconds between live "Refresh" requests
# Keys written by other forks that this read-only fork must delete from stored config.
LEGACY_COMMAND_KEYS = ("pin", "lock_command", "unlock_command")
DEFAULT_DASHBOARD_FILTERS = [
    "DigitalTwin",
    "VEHICLE RANGE",
    "odometer",
    "TIRE PRESSURE",
]
DASHBOARD_FILTER_SETS = (
    DEFAULT_DASHBOARD_FILTERS,
    ["DigitalTwin"],
    [],
)

CLIENT_ID = "HondaLinkAndroidApp0074"
CLIENT_SECRET = "rETFrZcLyUycsSblksCP"
DEVICE_DESCRIPTION = "Android"
APP_USER_AGENT = "HondaLink/5.5.0 (Android)"

IDENTITY_BASE = "https://identity.services.honda.com"
API_BASE = "https://wsc.hondaweb.com"

HONDALINK_BUSINESS_ID = "HONDALINK CONNECT"
HONDALINK_SYSTEM_ID = "com.honda.hondalink.cv_android"
HONDA_HEADER_VERSION = "1.0"

UPDATE_INTERVAL = timedelta(minutes=DEFAULT_SCAN_INTERVAL)

DATA_API = "api"
DATA_COORDINATOR = "coordinator"
