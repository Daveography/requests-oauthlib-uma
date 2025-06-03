import json
import time
from base64 import b64encode
from unittest import TestCase, mock

from oauthlib.oauth2 import (
    BackendApplicationClient,
    LegacyApplicationClient,
    MobileApplicationClient,
    TokenExpiredError,
    WebApplicationClient,
)
from requests.exceptions import HTTPError, InvalidHeader
from requests_oauthlib import TokenUpdated

from requests_oauthlib_uma import UMA2Client, UMA2Session
from requests_oauthlib_uma.exceptions import MaxUMAFlowsReachedError

fake_time = time.time()

fake_uma_unauthorized = mock.MagicMock(
    status_code=401,
    headers={
        "WWW-Authenticate": 'UMA realm="example", as_uri="https://as.example.com", ticket="auth-server-issued-ticket"'
    },
)
fake_well_known = mock.MagicMock(status_code=200, json=lambda: {"token_endpoint": "https://as.example.com/realm/token"})
fake_rpt_token = mock.MagicMock(status_code=201, text='{"access_token": "2YotnFZFEjr1zCsicMWpAA"}')
fake_final_response = mock.MagicMock(status_code=200, text="Success")

fake_basic_unauthorized = mock.MagicMock(
    status_code=401,
    headers={"WWW-Authenticate": 'Basic realm="example"'},
    text="Unauthorized",
)


class UMA2SessionTest(TestCase):
    def setUp(self):
        self.token = {
            "token_type": "Bearer",
            "access_token": "asdfoiw37850234lkjsdfsdf",
            "refresh_token": "sldvafkjw34509s8dfsdf",
            "expires_in": 3600,
            "expires_at": fake_time + 3600,
        }
        # use someclientid:someclientsecret to easily differentiate between client and user credentials
        # these are the values used in oauthlib tests
        self.client_id = "someclientid"
        self.client_secret = "someclientsecret"
        self.user_username = "user_username"
        self.user_password = "user_password"
        self.client_WebApplication = WebApplicationClient(self.client_id, code="asdf345xdf")
        self.client_LegacyApplication = LegacyApplicationClient(self.client_id)
        self.client_BackendApplication = BackendApplicationClient(self.client_id)
        self.client_MobileApplication = MobileApplicationClient(self.client_id)
        self.clients = [
            self.client_WebApplication,
            self.client_LegacyApplication,
            self.client_BackendApplication,
        ]
        self.all_clients = self.clients + [self.client_MobileApplication]

    def test_all_client_compatibility(self):
        token = "Bearer " + self.token["access_token"]

        def verifier(r, **kwargs):
            auth_header = r.headers.get(str("Authorization"), None)
            self.assertEqual(auth_header, token)
            resp = mock.MagicMock()
            resp.cookes = []
            return resp

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token)
            sess.send = verifier  # type: ignore
            sess.get("https://i.b")

    def test_should_include_provided_default_headers(self):
        headers = {"User-Agent": "test_uma2_session"}

        def verifier(r, **kwargs):
            default_header = r.headers.get(str("User-Agent"), None)
            self.assertEqual(default_header, "test_uma2_session")
            resp = mock.MagicMock()
            resp.cookes = []
            return resp

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, headers=headers)
            sess.send = verifier  # type: ignore
            sess.get("https://i.b")

    @mock.patch("time.time", new=lambda: fake_time)
    def test_refresh_token_request(self):
        self.expired_token = dict(self.token)
        self.expired_token["expires_in"] = "-1"
        del self.expired_token["expires_at"]

        def fake_refresh(r, **kwargs):
            if "/refresh" in r.url:
                self.assertNotIn("Authorization", r.headers)
            resp = mock.MagicMock()
            resp.text = json.dumps(self.token)
            return resp

        # No auto refresh setup
        for client in self.clients:
            sess = UMA2Session(client=client, token=self.expired_token)
            self.assertRaises(TokenExpiredError, sess.get, "https://i.b")

        # Auto refresh but no auto update
        for client in self.clients:
            sess = UMA2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
            )
            sess.send = fake_refresh  # type: ignore
            self.assertRaises(TokenUpdated, sess.get, "https://i.b")

        # Auto refresh and auto update
        def token_updater(token):
            self.assertEqual(token, self.token)

        for client in self.clients:
            sess = UMA2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
                token_updater=token_updater,
            )
            sess.send = fake_refresh  # type: ignore
            sess.get("https://i.b")

        def fake_refresh_with_auth(r, **kwargs):
            if "/refresh" in r.url:
                self.assertIn("Authorization", r.headers)
                encoded = b64encode(
                    "{client_id}:{client_secret}".format(
                        client_id=self.client_id, client_secret=self.client_secret
                    ).encode("latin1")
                )
                content = "Basic {encoded}".format(encoded=encoded.decode("latin1"))
                self.assertEqual(r.headers["Authorization"], content)
            resp = mock.MagicMock()
            resp.text = json.dumps(self.token)
            return resp

        for client in self.clients:
            sess = UMA2Session(
                client=client,
                token=self.expired_token,
                auto_refresh_url="https://i.b/refresh",
                token_updater=token_updater,
            )
            sess.send = fake_refresh_with_auth  # type: ignore
            sess.get("https://i.b", client_id=self.client_id, client_secret=self.client_secret)  # type: ignore

    def test_should_parse_uma_authenticate_header(self):
        sess = UMA2Session(client=mock.MagicMock())
        realm, ticket, as_uri = sess._get_uma_params(fake_uma_unauthorized)
        self.assertEqual(realm, "example")
        self.assertEqual(ticket, "auth-server-issued-ticket")
        self.assertEqual(as_uri, "https://as.example.com")

    def test_should_parse_uma_authenticate_header_params_in_any_order(self):
        uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={
                "WWW-Authenticate": 'UMA as_uri="https://as.example.com", ticket="auth-server-issued-ticket", realm="example"'  # noqa E501
            },
        )
        sess = UMA2Session(client=mock.MagicMock())
        realm, ticket, as_uri = sess._get_uma_params(uma_unauthorized_response)
        self.assertEqual(realm, "example")
        self.assertEqual(ticket, "auth-server-issued-ticket")
        self.assertEqual(as_uri, "https://as.example.com")

    def test_should_parse_uma_authenticate_header_params_with_extra_whitespace(self):
        uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={
                "WWW-Authenticate": 'UMA  as_uri="https://as.example.com",  ticket="auth-server-issued-ticket",  realm="example"'  # noqa E501
            },
        )
        sess = UMA2Session(client=mock.MagicMock())
        realm, ticket, as_uri = sess._get_uma_params(uma_unauthorized_response)
        self.assertEqual(realm, "example")
        self.assertEqual(ticket, "auth-server-issued-ticket")
        self.assertEqual(as_uri, "https://as.example.com")

    def test_should_parse_uma_authenticate_header_params_with_no_whitespace(self):
        uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={
                "WWW-Authenticate": 'UMA as_uri="https://as.example.com",ticket="auth-server-issued-ticket",realm="example"'  # noqa E501
            },
        )
        sess = UMA2Session(client=mock.MagicMock())
        realm, ticket, as_uri = sess._get_uma_params(uma_unauthorized_response)
        self.assertEqual(realm, "example")
        self.assertEqual(ticket, "auth-server-issued-ticket")
        self.assertEqual(as_uri, "https://as.example.com")

    def test_should_raise_if_not_uma_authenticate_header(self):
        sess = UMA2Session(client=mock.MagicMock())
        with self.assertRaises(InvalidHeader):
            sess._get_uma_params(fake_basic_unauthorized)

    def test_should_raise_if_uma_authenticate_header_missing_realm(self):
        incomplete_uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={"WWW-Authenticate": 'UMA realm="example", ticket="auth-server-issued-ticket"'},
        )
        sess = UMA2Session(client=mock.MagicMock())
        with self.assertRaises(InvalidHeader):
            sess._get_uma_params(incomplete_uma_unauthorized_response)

    def test_should_raise_if_uma_authenticate_header_missing_as_uri(self):
        incomplete_uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={"WWW-Authenticate": 'UMA realm="example", ticket="auth-server-issued-ticket"'},
        )
        sess = UMA2Session(client=mock.MagicMock())
        with self.assertRaises(InvalidHeader):
            sess._get_uma_params(incomplete_uma_unauthorized_response)

    def test_should_raise_if_uma_authenticate_header_missing_ticket(self):
        incomplete_uma_unauthorized_response = mock.MagicMock(
            status_code=401,
            headers={"WWW-Authenticate": 'UMA realm="example",as_uri="https://as.example.com"'},
        )
        sess = UMA2Session(client=mock.MagicMock())
        with self.assertRaises(InvalidHeader):
            sess._get_uma_params(incomplete_uma_unauthorized_response)

    def test_should_get_token_url_from_as_uri_well_known(self):
        def fake_well_known(r, **kwargs):
            self.assertEqual(r.url, "https://as.example.com/realm/.well-known/uma2-configuration")
            return mock.MagicMock(
                json=lambda: {"token_endpoint": "https://as.example.com/realm/token"},
            )

        sess = UMA2Session(client=mock.MagicMock())
        sess.send = fake_well_known  # type: ignore
        sess._get_token_url("https://as.example.com/realm")

    def test_get_token_url_get_well_known_should_not_include_token(self):
        def fake_well_known(r, **kwargs):
            self.assertNotIn("Authentication", r.headers)
            return mock.MagicMock(
                json=lambda: {"token_endpoint": "https://as.example.com/realm/token"},
            )

        sess = UMA2Session(client=mock.MagicMock())
        sess.send = fake_well_known  # type: ignore
        sess._get_token_url("https://as.example.com/realm")

    def test_should_ignore_trailing_slash_in_as_uri(self):
        def fake_well_known(r, **kwargs):
            self.assertNotIn("Authentication", r.headers)
            return mock.MagicMock(json=lambda: {"token_endpoint": "https://as.example.com/realm/token"})

        sess = UMA2Session(client=mock.MagicMock())
        sess.send = fake_well_known  # type: ignore
        sess._get_token_url("https://as.example.com/realm/")

    def test_uma_unauthorized_request_should_trigger_workflow(self):
        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token)

            # Ensure we start with the provided client
            self.assertIsInstance(sess._client, client.__class__)

            sess.send = mock.MagicMock(
                side_effect=[
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_final_response,
                ]
            )

            resp = sess.get("https://i.b")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.text, "Success")

            # Ensure the client was replaced with UMA2Client
            self.assertIsInstance(sess._client, UMA2Client)

            # Ensure that the `fetch_token` call for the RPT included the expected parameters
            body = sess.send.mock_calls[2][1][0].body
            self.assertIn("ticket=auth-server-issued-ticket", body)
            self.assertIn("rpt=asdfoiw37850234lkjsdfsdf", body)

            # Ensure the session token is now the RPT
            self.assertEqual(sess.token["access_token"], "2YotnFZFEjr1zCsicMWpAA")

    def test_should_handle_up_to_configured_max_sequential_uma_flows(self):
        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, max_flows_per_request=2)
            sess.send = mock.MagicMock(
                side_effect=[
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_final_response,
                ]
            )

            resp = sess.get("https://i.b")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.text, "Success")
            self.assertEqual(7, sess.send.call_count)

    def test_should_raise_after_configured_max_sequential_uma_flows(self):
        fake_uma_unauthorized_final = mock.MagicMock(
            status_code=401,
            text="Unauthorized",
            headers={
                "WWW-Authenticate": 'UMA realm="example", as_uri="https://as.example.com", ticket="auth-server-issued-ticket"'  # noqa E501
            },
        )

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, max_flows_per_request=2)
            sess.send = mock.MagicMock(
                side_effect=[
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized_final,
                ]
            )

            with self.assertRaises(MaxUMAFlowsReachedError):
                sess.get("https://i.b")

            self.assertEqual(7, sess.send.call_count)

    def test_should_raise_normally_if_unexpected_error_raised(self):
        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, max_flows_per_request=2)
            sess.send = mock.MagicMock(
                side_effect=[
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized,
                    HTTPError("Unexpected error"),
                ]
            )

            with self.assertRaises(HTTPError) as err:
                sess.get("https://i.b")

            self.assertEqual(5, sess.send.call_count)
            self.assertEqual("Unexpected error", str(err.exception))

    def test_raised_error_should_contain_last_response(self):
        fake_uma_unauthorized_final = mock.MagicMock(
            status_code=401,
            text="Unauthorized",
            headers={
                "WWW-Authenticate": 'UMA realm="example", as_uri="https://as.example.com", ticket="auth-server-issued-ticket"'  # noqa E501
            },
        )

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, max_flows_per_request=2)
            sess.send = mock.MagicMock(
                side_effect=[
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_uma_unauthorized_final,
                ]
            )

            with self.assertRaises(MaxUMAFlowsReachedError) as err:
                sess.get("https://i.b")

            self.assertEqual(err.exception.last_attempt.attempt_number, 3)

            last_resp = err.exception.last_attempt.result()
            self.assertEqual(last_resp.status_code, 401)
            self.assertEqual(last_resp.text, "Unauthorized")

    def test_should_not_retry_on_other_response_types(self):
        fake_forbidden = mock.MagicMock(status_code=403, text="Forbidden")
        fake_server_error = mock.MagicMock(status_code=500, text="Server Error")

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, max_flows_per_request=2)
            sess.send = mock.MagicMock(side_effect=[fake_basic_unauthorized])

            resp = sess.get("https://i.b")
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.text, "Unauthorized")
            self.assertEqual(1, sess.send.call_count)

            sess.send = mock.MagicMock(side_effect=[fake_forbidden])

            resp = sess.get("https://i.b")
            self.assertEqual(resp.status_code, 403)
            self.assertEqual(resp.text, "Forbidden")
            self.assertEqual(1, sess.send.call_count)

            sess.send = mock.MagicMock(side_effect=[fake_server_error])

            resp = sess.get("https://i.b")
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(resp.text, "Server Error")
            self.assertEqual(1, sess.send.call_count)

    def test_fetch_token_should_include_fetch_rpt_kwargs_when_provided(self):
        fake_unauthorized = mock.MagicMock(
            status_code=401,
            headers={
                "WWW-Authenticate": 'UMA realm="example", as_uri="https://as.example.com", ticket="auth-server-issued-ticket"'  # noqa E501
            },
        )
        fake_well_known = mock.MagicMock(json=lambda: {"token_endpoint": "https://as.example.com/realm/token"})
        fake_rpt_token = mock.MagicMock(text='{"access_token": "2YotnFZFEjr1zCsicMWpAA"}')
        fake_final_response = mock.MagicMock(text="Success")

        for client in self.all_clients:
            sess = UMA2Session(client=client, token=self.token, fetch_rpt_kwargs={"audience": "someotherclientid"})

            # Ensure we start with the provided client
            self.assertIsInstance(sess._client, client.__class__)

            sess.send = mock.MagicMock(
                side_effect=[
                    fake_unauthorized,
                    fake_well_known,
                    fake_rpt_token,
                    fake_final_response,
                ]
            )

            resp = sess.get("https://i.b")
            self.assertEqual(resp.text, "Success")

            self.assertIn("audience=someotherclientid", sess.send.mock_calls[2][1][0].body)

    def test_authorized_false(self):
        sess = UMA2Session("someclientid")
        self.assertFalse(sess.authorized)

    @mock.patch("time.time", new=lambda: fake_time)
    def test_authorized_true(self):
        def fake_token(token):
            def fake_send(r, **kwargs):
                resp = mock.MagicMock()
                resp.text = json.dumps(token)
                return resp

            return fake_send

        url = "https://example.com/token"

        for client in self.clients:
            sess = UMA2Session(client=client)
            sess.send = fake_token(self.token)  # type: ignore
            self.assertFalse(sess.authorized)
            if isinstance(client, LegacyApplicationClient):
                # this client requires a username+password
                # if unset, an error will be raised
                self.assertRaises(ValueError, sess.fetch_token, url)
                self.assertRaises(ValueError, sess.fetch_token, url, username="username1")
                self.assertRaises(ValueError, sess.fetch_token, url, password="password1")
                # otherwise it will pass
                sess.fetch_token(url, username="username1", password="password1")
            else:
                sess.fetch_token(url)
            self.assertTrue(sess.authorized)
