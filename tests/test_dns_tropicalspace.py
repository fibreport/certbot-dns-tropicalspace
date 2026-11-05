"""Tests for certbot_dns_tropicalspace.

No network: the HTTP session is a fake.
"""

import re
import sys
import unittest
from unittest import mock

import pytest
from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

import certbot_dns_tropicalspace
from certbot_dns_tropicalspace.dns_tropicalspace import Authenticator
from certbot_dns_tropicalspace.dns_tropicalspace import _DNSAPIClient

API_KEY = "tsk_abcdefgh_" + "x" * 43


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super().setUp()
        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write({"tropicalspace_api_key": API_KEY}, path)
        self.config = mock.MagicMock(
            tropicalspace_credentials=path,
            tropicalspace_propagation_seconds=0,
            tropicalspace_sync_timeout=30,
        )
        self.auth = Authenticator(self.config, "tropicalspace")
        self.mock_client = mock.MagicMock()
        self.mock_client.find_zone.return_value = DOMAIN
        self.auth._get_api_client = mock.MagicMock(
            return_value=self.mock_client
        )

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])
        name = "_acme-challenge." + DOMAIN
        self.mock_client.find_zone.assert_called_with(name)
        self.mock_client.add_txt_record.assert_called_with(
            DOMAIN, name, mock.ANY, 60
        )
        self.mock_client.wait_synced.assert_called_with(DOMAIN, 30)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])
        self.mock_client.del_txt_record.assert_called_with(
            DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
        )

    def test_cleanup_only_warns(self):
        self.auth._attempt_cleanup = True
        self.mock_client.del_txt_record.side_effect = errors.PluginError(
            "gone"
        )
        self.auth.cleanup([self.achall])  # does not raise

    def test_key_must_look_like_a_key(self):
        dns_test_common.write(
            {"tropicalspace_api_key": "abc"},
            self.config.tropicalspace_credentials,
        )
        with pytest.raises(errors.PluginError, match="tsk_"):
            self.auth._setup_credentials()

    def test_insecure_endpoint_is_refused(self):
        dns_test_common.write(
            {
                "tropicalspace_api_key": API_KEY,
                "tropicalspace_api_endpoint": "http://api.example.net/v1",
            },
            self.config.tropicalspace_credentials,
        )
        with pytest.raises(errors.PluginError, match="Insecure"):
            self.auth._setup_credentials()


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeSession:
    """Answer like the API (zones, records, status), log every call."""

    def __init__(
        self, zones=("example.de", "shop.example.de"), statuses=("synced",)
    ):
        self.zones = list(zones)
        self.records = []
        self.statuses = list(statuses)
        self.calls = []

    def request(
        self, method, url, params=None, json=None, headers=None, timeout=None
    ):
        self.calls.append((method, url, params, json, headers))
        assert headers["Authorization"] == f"Bearer {API_KEY}"
        path = url.split("/v1", 1)[1]
        if method == "GET" and path == "/dns/zones":
            return FakeResponse(
                200, [{"zone": z, "zone_ascii": z} for z in self.zones]
            )
        if method == "GET" and path.endswith("/status"):
            return FakeResponse(
                200,
                {
                    "sync": self.statuses.pop(0)
                    if len(self.statuses) > 1
                    else self.statuses[0]
                },
            )
        match = re.match(r"^/dns/zones/([^/]+)/records(?:/([^/]+))?$", path)
        if match and method == "POST":
            record = {
                "id": f"id-{len(self.records)}",
                "zone": match[1],
                **json,
            }
            self.records.append(record)
            return FakeResponse(201, {**record, "changed": True})
        if match and method == "GET":
            found = [
                r
                for r in self.records
                if r["zone"] == match[1]
                and r["type"] == params["type"]
                and r["name"] == params["name"]
            ]
            return FakeResponse(200, found)
        if match and method == "DELETE":
            self.records = [r for r in self.records if r["id"] != match[2]]
            return FakeResponse(204)
        return FakeResponse(
            404,
            {
                "type": "client_error",
                "errors": [
                    {
                        "code": "not_found",
                        "detail": "Diese Zone gibt es nicht.",
                        "attr": None,
                    }
                ],
            },
        )


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession()
        self.client = _DNSAPIClient(
            API_KEY, "https://api.tropicalspace.de/v1", session=self.session
        )

    def test_longest_zone_wins(self):
        assert (
            self.client.find_zone("_acme-challenge.shop.example.de")
            == "shop.example.de"
        )
        assert (
            self.client.find_zone("_acme-challenge.www.example.de.")
            == "example.de"
        )
        with pytest.raises(errors.PluginError, match="No DNS zone"):
            self.client.find_zone("_acme-challenge.other.org")
        assert (
            sum(1 for c in self.session.calls if c[1].endswith("/dns/zones"))
            == 1
        )  # the zone list is asked once

    def test_add_and_delete_only_its_own_record(self):
        name = "_acme-challenge.example.de"
        self.client.add_txt_record("example.de", name, "token-one", 60)
        self.client.add_txt_record(
            "example.de", name, "token-two", 60
        )  # wildcard and base domain: two values
        assert self.session.records[0] | {"id": None} == {
            "id": None,
            "zone": "example.de",
            "type": "TXT",
            "name": "_acme-challenge",
            "value": "token-one",
            "ttl": 60,
        }
        self.client.del_txt_record("example.de", name, "token-one")
        assert [r["value"] for r in self.session.records] == ["token-two"]
        self.client.del_txt_record(
            "example.de", name, "token-one"
        )  # already gone: no error

    def test_wait_until_synced(self):
        self.session.statuses = ["pending", "pending", "synced"]
        with mock.patch("time.sleep") as sleep:
            self.client.wait_synced("example.de", 60)
        assert sleep.call_count == 2

    def test_failed_transfer_is_an_error(self):
        self.session.statuses = ["failed"]
        with pytest.raises(
            errors.PluginError, match="could not be transferred"
        ):
            self.client.wait_synced("example.de", 60)

    def test_api_errors_carry_message_and_hint(self):
        def refuse(*args, **kwargs):
            return FakeResponse(
                403,
                {
                    "type": "client_error",
                    "errors": [
                        {
                            "code": "ip_not_allowed",
                            "detail": (
                                "Die IP-Adresse 192.0.2.1 ist nicht "
                                "freigegeben."
                            ),
                            "attr": None,
                        }
                    ],
                },
            )

        self.session.request = refuse
        with pytest.raises(
            errors.PluginError,
            match=(
                r"HTTP 403 ip_not_allowed: Die IP-Adresse 192\.0\.2\.1 "
                r".* Add the address"
            ),
        ):
            self.client.find_zone("_acme-challenge.example.de")

    def test_local_http_endpoint_is_allowed_for_tests(self):
        _DNSAPIClient(
            API_KEY,
            "http://api.tropicalspace.localhost/v1",
            session=self.session,
        )
        with pytest.raises(errors.PluginError):
            _DNSAPIClient(
                API_KEY, "http://api.example.net/v1", session=self.session
            )


def test_versions_match():
    with open(
        os.path.join(os.path.dirname(__file__), "..", "setup.py"),
        encoding="utf-8",
    ) as setup:
        assert (
            f'version = "{certbot_dns_tropicalspace.__version__}"'
            in setup.read()
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
