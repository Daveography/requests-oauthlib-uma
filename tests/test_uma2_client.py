import urllib.parse as urlparse
from unittest import TestCase

from requests_oauthlib_uma import UMA2Client


class UMA2ClientTest(TestCase):
    client_id = "someclientid"
    ticket = "auth-server-issued-ticket"
    token = {
        "access_token": "2YotnFZFEjr1zCsicMWpAA",
        "token_type": "example",
        "expires_in": 3600,
        "expires_at": 4600,
        "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
        "example_parameter": "example_value",
    }

    def test_prepare_request_body(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_request_body(self.ticket)
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 3)
        self.assertEqual(params["grant_type"], "urn:ietf:params:oauth:grant-type:uma-ticket")
        self.assertEqual(params["ticket"], self.ticket)
        self.assertEqual(params["rpt"], self.token["access_token"])

    def test_prepare_request_body_with_provided_body(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_request_body(self.ticket, body="extant_body=true")
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 4)
        self.assertEqual(params["grant_type"], "urn:ietf:params:oauth:grant-type:uma-ticket")
        self.assertEqual(params["ticket"], self.ticket)
        self.assertEqual(params["rpt"], self.token["access_token"])
        self.assertEqual(params["extant_body"], "true")

    def test_prepare_request_body_with_extra_args(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_request_body(self.ticket, audience="some-audience")
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 4)
        self.assertEqual(params["grant_type"], "urn:ietf:params:oauth:grant-type:uma-ticket")
        self.assertEqual(params["ticket"], self.ticket)
        self.assertEqual(params["rpt"], self.token["access_token"])
        self.assertEqual(params["audience"], "some-audience")

    def test_prepare_request_body_should_not_include_client_id(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_request_body(self.ticket)
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertNotIn("client_id", params)

    def test_prepare_refresh_body(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_refresh_body(self.token["refresh_token"])
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 3)
        self.assertEqual(params["grant_type"], "refresh_token")
        self.assertEqual(params["refresh_token"], self.token["refresh_token"])
        self.assertEqual(params["client_id"], self.client_id)

    def test_prepare_refresh_body_with_provided_body(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_refresh_body(self.token["refresh_token"], body="extant_body=true")
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 4)
        self.assertEqual(params["grant_type"], "refresh_token")
        self.assertEqual(params["refresh_token"], self.token["refresh_token"])
        self.assertEqual(params["client_id"], self.client_id)
        self.assertEqual(params["extant_body"], "true")

    def test_prepare_refresh_body_with_extra_args(self):
        client = UMA2Client(self.client_id, self.token)
        body = client.prepare_refresh_body(self.token["refresh_token"], audience="some-audience")
        params = dict(urlparse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(len(params.keys()), 4)
        self.assertEqual(params["grant_type"], "refresh_token")
        self.assertEqual(params["refresh_token"], self.token["refresh_token"])
        self.assertEqual(params["client_id"], self.client_id)
        self.assertEqual(params["audience"], "some-audience")
