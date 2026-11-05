"""DNS Authenticator for tropicalspace.de.

Solves dns-01 challenges with the tropicalspace.de developer API
(https://tropicalspace.de/entwickler). An API key created with the
template "Let's Encrypt" is enough: it may only change TXT records
named _acme-challenge(.*).

Per challenge the plugin

1. finds the zone (the longest zone of the account the domain ends
   with),
2. adds the TXT record (sending it again changes nothing, so retries
   are safe),
3. waits until the zone is on all of our nameservers ("synced"),

and on cleanup deletes exactly the record it added, so parallel
challenges for the same name stay untouched.
"""

import logging
import time
from typing import Any
from typing import Callable
from typing import Literal
from typing import Optional
from urllib.parse import quote
from urllib.parse import urlsplit

import requests
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from . import __version__

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://api.tropicalspace.de/v1"
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


class Authenticator(dns_common.DNSAuthenticator):
    """Obtain certificates with a DNS TXT record at tropicalspace.de."""

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using tropicalspace.de for DNS)."
    )
    ttl = 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self._client: Optional[_DNSAPIClient] = None

    @classmethod
    def add_parser_arguments(
        cls,
        add: Callable[..., None],
        default_propagation_seconds: int = 10,
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="tropicalspace.de credentials INI file.")
        add(
            "sync-timeout",
            type=int,
            default=120,
            help=(
                "Seconds to wait until the TXT record is on all "
                "tropicalspace.de nameservers (0 = do not wait)."
            ),
        )

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to a "
            "dns-01 challenge using the tropicalspace.de developer API."
        )

    def _validate_credentials(
        self, credentials: CredentialsConfiguration
    ) -> None:
        filename = credentials.confobj.filename
        key = credentials.conf("api-key")
        if not key:
            raise errors.PluginError(
                f"{filename}: dns_tropicalspace_api_key is required."
            )
        if not key.startswith("tsk_"):
            raise errors.PluginError(
                f"{filename}: dns_tropicalspace_api_key must start with "
                "tsk_ (create one in the customer center)."
            )
        _check_endpoint(credentials.conf("api-endpoint") or DEFAULT_ENDPOINT)

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "tropicalspace.de credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(
        self, domain: str, validation_name: str, validation: str
    ) -> None:
        client = self._get_api_client()
        zone = client.find_zone(validation_name)
        client.add_txt_record(zone, validation_name, validation, self.ttl)
        timeout = self.conf("sync-timeout")
        if timeout:
            client.wait_synced(zone, timeout)

    def _cleanup(
        self, domain: str, validation_name: str, validation: str
    ) -> None:
        client = self._get_api_client()
        try:
            zone = client.find_zone(validation_name)
            client.del_txt_record(zone, validation_name, validation)
        except errors.PluginError as exc:
            logger.warning(
                "Could not remove the TXT record %s: %s", validation_name, exc
            )

    def _get_api_client(self) -> "_DNSAPIClient":
        if self._client is None:
            self._client = _DNSAPIClient(
                api_key=self.credentials.conf("api-key"),
                api_endpoint=self.credentials.conf("api-endpoint"),
            )
        return self._client


def _check_endpoint(endpoint: str) -> None:
    """Allow HTTPS only, except a local test installation.

    Local means http://localhost, a loopback address or *.localhost.
    """
    parts = urlsplit(endpoint)
    host = parts.hostname or ""
    local = host in LOCAL_HOSTS or host.endswith(".localhost")
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return
    raise errors.PluginError(
        f"Insecure or invalid API endpoint: {endpoint} (use https://)."
    )


class _DNSAPIClient:
    """Client for zones and records of the tropicalspace.de API."""

    def __init__(
        self,
        api_key: str,
        api_endpoint: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_key = api_key
        self.api_endpoint = (api_endpoint or DEFAULT_ENDPOINT).rstrip("/")
        _check_endpoint(self.api_endpoint)
        self.session = session or _session()
        self._zones: Optional[list[str]] = None

    # --- zones and records --------------------------------------------

    def find_zone(self, validation_name: str) -> str:
        """Return the zone a name belongs to.

        That is the longest zone of the account the name ends with,
        so shop.example.de wins over example.de.
        """
        name = validation_name.rstrip(".").lower()
        if self._zones is None:
            self._zones = [
                str(z["zone_ascii"]).lower()
                for z in self._request("GET", "/dns/zones")
            ]
        matches = [
            z for z in self._zones if name == z or name.endswith(f".{z}")
        ]
        if not matches:
            raise errors.PluginError(
                f"No DNS zone for {name} found. Check that the domain "
                "uses tropicalspace.de nameservers and that the API key "
                "has a right for this zone."
            )
        return max(matches, key=len)

    @staticmethod
    def relative_name(zone: str, validation_name: str) -> str:
        name = validation_name.rstrip(".").lower()
        return "@" if name == zone else name[: -(len(zone) + 1)]

    def add_txt_record(
        self, zone: str, validation_name: str, validation: str, ttl: int
    ) -> None:
        name = self.relative_name(zone, validation_name)
        record = self._request(
            "POST",
            f"/dns/zones/{quote(zone)}/records",
            json={
                "type": "TXT",
                "name": name,
                "value": validation,
                "ttl": ttl,
            },
        )
        logger.debug(
            "TXT record %s in %s %s",
            name,
            zone,
            "added" if record.get("changed", True) else "already existed",
        )

    def del_txt_record(
        self, zone: str, validation_name: str, validation: str
    ) -> None:
        name = self.relative_name(zone, validation_name)
        records = self._request(
            "GET",
            f"/dns/zones/{quote(zone)}/records",
            params={"type": "TXT", "name": name},
        )
        found = [r for r in records if r.get("value") == validation]
        if not found:
            logger.debug("TXT record %s in %s is already gone", name, zone)
        for record in found:
            self._request(
                "DELETE", f"/dns/zones/{quote(zone)}/records/{record['id']}"
            )

    def wait_synced(
        self, zone: str, timeout: int, interval: float = 2.0
    ) -> None:
        """Wait until every nameserver of the zone has the new state.

        Certbot then waits its propagation seconds on top.
        """
        deadline = time.monotonic() + timeout
        while True:
            state = self._request(
                "GET", f"/dns/zones/{quote(zone)}/status"
            ).get("sync")
            if state == "synced":
                return
            if state == "failed":
                raise errors.PluginError(
                    f"The zone {zone} could not be transferred to the "
                    "nameservers. Please try again later."
                )
            if time.monotonic() >= deadline:
                logger.warning(
                    "Zone %s is still %s after %s seconds, continuing.",
                    zone,
                    state,
                    timeout,
                )
                return
            time.sleep(interval)

    # --- HTTP ---------------------------------------------------------

    def _request(
        self,
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        path: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        timeout: float = 30,
    ) -> Any:
        url = f"{self.api_endpoint}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": f"certbot-dns-tropicalspace/{__version__}",
            "Accept": "application/json",
        }
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json,
                headers=headers,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise errors.PluginError(
                f"tropicalspace.de API not reachable: {exc}"
            ) from exc
        if response.status_code == 204:
            return {}
        if response.status_code >= 400:
            raise errors.PluginError(_error_message(response))
        try:
            return response.json()
        except ValueError as exc:
            raise errors.PluginError(
                "Unexpected answer from the tropicalspace.de API "
                f"(HTTP {response.status_code})."
            ) from exc


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


HINTS = {
    "invalid_api_key": (
        "Check dns_tropicalspace_api_key: the key is wrong, revoked or "
        "expired."
    ),
    "ip_not_allowed": (
        "Add the address of this server to the API key's IP addresses "
        "in the customer center."
    ),
    "permission_denied": (
        "The API key may not change this record; use the template "
        '"Let\'s Encrypt" for the zone.'
    ),
    "not_found": (
        "The zone or record does not exist or the API key may not see it."
    ),
    "throttled": "Too many requests; please try again later.",
    "maintenance": (
        "tropicalspace.de is in maintenance; please try again later."
    ),
}


def _error_message(response: requests.Response) -> str:
    """Return the API's own message (German) plus an English hint.

    Example: "HTTP 403 ip_not_allowed: … – Add the address …".
    """
    code, detail = "", ""
    try:
        error = (response.json().get("errors") or [{}])[0]
        code = str(error.get("code") or "")
        detail = str(error.get("detail") or "")
    except (ValueError, AttributeError):
        pass
    message = f"tropicalspace.de API: HTTP {response.status_code}"
    if code:
        message += f" {code}"
    if detail:
        message += f": {detail}"
    if code in HINTS:
        message += f" – {HINTS[code]}"
    return message
