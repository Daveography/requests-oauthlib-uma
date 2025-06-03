import re
from typing_extensions import Any, Callable, Optional

from oauthlib.oauth2 import Client
from requests import Response, codes
from requests.exceptions import InvalidHeader
from requests.sessions import merge_setting
from requests.structures import CaseInsensitiveDict
from requests_oauthlib import OAuth2, OAuth2Session
from tenacity import Retrying, retry_if_result, stop_after_attempt

from .exceptions import MaxUMAFlowsReachedError
from .uma2_client import UMA2Client


def _is_uma_unauthorized(response: Response) -> bool:
    return (
        response.status_code == codes.unauthorized
        and "WWW-Authenticate" in response.headers
        and response.headers["WWW-Authenticate"].startswith("UMA")
    )


class UMA2Session(OAuth2Session):
    """
    An subclass of :class`requests_oauthlib.OAuth2Session' that automatically handles UMA 2.0 permission flows:
    https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html

    Internally, when a Resource Server responds with 401 Unauthorized and a UMA WWW-Authenticate header, the session
    will automatically attempt to fetch a Requesting Party Token (RPT) from the Authorization Server for the necessary
    claims, and then retry the original request.
    """

    UMA_WWW_AUTH_HEADER_REGEX = re.compile(
        r"(?=UMA\s+)"
        r'(?=.*(?=realm="(?P<realm>[^"]+)"),?\s*)'
        r'(?=.*(?=ticket="(?P<ticket>[^"]+)"),?\s*)'
        r'(?=.*(?=as_uri="(?P<as_uri>[^"]+)"),?\s*)'
        r".*"
    )
    UMA_WELL_KNOWN_URL_PATH = "/.well-known/uma2-configuration"

    def __init__(
        self,
        client_id: Optional[str] = None,
        client: Optional[Client] = None,
        auto_refresh_url: Optional[str] = None,
        auto_refresh_kwargs: Optional[dict[str, Any]] = None,
        scope: Optional[list[str]] = None,
        redirect_uri: Optional[str] = None,
        token: Optional[dict[str, Any]] = None,
        state: Optional[str] = None,
        token_updater: Optional[Callable[[dict[str, Any]], None]] = None,
        headers: Optional[dict[str, str]] = None,
        fetch_rpt_kwargs: Optional[dict[str, Any]] = None,
        max_flows_per_request: int = 1,
        **kwargs,
    ):
        """
        Create a new Oauth2 Session with UMA 2.0 support.

        Args:
            client_id (str, optional): Client id obtained during registration. Defaults to None.
            client (Client, optional): :class:`oauthlib.oauth2.Client` to be used. Default is WebApplicationClient
                which is useful for any hosted application but not mobile or desktop.
            auto_refresh_url (str, optional): Refresh token endpoint URL, must be HTTPS. Supply this if you wish the
                client to automatically refresh your access tokens. Defaults to None.
            auto_refresh_kwargs (dict[str, Any], optional): Extra arguments to pass to the refresh token endpoint.
                Defaults to None.
            scope (list[str], optional): List of scopes you wish to request access to. Defaults to None.
            redirect_uri (str, optional): Redirect URI you registered as callback. Defaults to None.
            token (dict[str, Any], optional): Token dictionary, must include access_token and token_type. Defaults to
                None.
            state (str, optional): State string used to prevent CSRF. This will be given when creating the
                authorization url and must be supplied when parsing the authorization response. Can be either a string
                or a no argument callable. Defaults to None.
            token_updater (Callable[[dict[str, Any]], None], optional): Method with one argument, token, to be used to
                update your token database on automatic token refresh. If not set a TokenUpdated warning will be raised
                when a token has been refreshed. This warning will carry the token in its token argument. Defaults to
                None.
            headers (dict[str, str], optional): Default headers to include on all requests. Defaults to None.
            fetch_rpt_kwargs (dict[str, Any], optional): Extra arguments to pass to the RPT token endpoint. Defaults to
                None.
            max_flows_per_request (int, optional): Maximum number of sequential UMA flows to attempt per request; e.g.,
                if a Resource requires multiple permission assessments before authorization can be granted. Raises
                :class:`requests_oauthlib_uma.exceptions.MaxUMAFlowsReachedError` if the Resource is still requesting
                UMA authorization after reaching this limit (i.e., to prevent infinite loops). Defaults to 1.
            kwargs: Arguments to pass to the Session constructor.

        Raises:
            :class:`requests_oauthlib_uma.exceptions.MaxUMAFlowsReachedError`: If the Resource Server is still
                requesting UMA authorization after reaching the configured limit.
        """

        super().__init__(
            client_id,
            client,
            auto_refresh_url,
            auto_refresh_kwargs,
            scope,
            redirect_uri,
            token,
            state,
            token_updater,
            **kwargs,
        )

        self.headers = merge_setting(headers, self.headers, dict_class=CaseInsensitiveDict)
        self.fetch_rpt_kwargs = fetch_rpt_kwargs or {}
        self.max_flows_per_request = max_flows_per_request

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        client_id=None,
        client_secret=None,
        files=None,
        **kwargs,
    ) -> Response:
        response = super().request(
            method, url, data, headers, withhold_token, client_id, client_secret, files, **kwargs
        )

        if _is_uma_unauthorized(response):
            # Intercept and handle UMA Unauthorized responses up to configured retry limit
            for attempt in Retrying(
                retry=retry_if_result(_is_uma_unauthorized),
                stop=stop_after_attempt(self.max_flows_per_request),
                reraise=True,
                retry_error_cls=MaxUMAFlowsReachedError,
            ):
                with attempt:
                    _, ticket, as_uri = self._get_uma_params(response)

                    if not isinstance(self._client, UMA2Client):
                        # Replace client with UMA client from here on
                        if self.client_id is None:
                            raise ValueError("client_id must be provided")

                        self._client = UMA2Client(self.client_id, token=self.token)

                    # Fetch a (new) Requesting Party Token (RPT)
                    token_url = self._get_token_url(as_uri)

                    self.fetch_token(
                        token_url, auth=OAuth2(client=self._client), ticket=ticket, **self.fetch_rpt_kwargs
                    )

                    # Retry the request
                    response = super().request(
                        method, url, data, headers, withhold_token, client_id, client_secret, files, **kwargs
                    )

                if not attempt.retry_state.outcome.failed:  # type: ignore
                    attempt.retry_state.set_result(response)

        if (
            response.status_code == codes.forbidden
            and "Warning" in response.headers
            and response.headers["Warning"].startswith("199")
        ):
            # TODO: Occurs if the UMA Authorization Server is not available, not sure if needs to be handled?
            pass

        return response

    def _get_uma_params(self, response: Response) -> tuple[str, str, str]:
        matches = re.match(self.UMA_WWW_AUTH_HEADER_REGEX, response.headers["WWW-Authenticate"])

        if matches is None:
            # TODO: What is the correct exception to raise here?
            raise InvalidHeader(
                f"Received invalid UMA WWW-Authenticate header from resource server: "
                f'{response.headers["WWW-Authenticate"]};'
                'expected format: UMA realm="<realm>", ticket="<ticket>", as_uri="<as_uri>"',
                response=response,
            )

        return matches.group("realm"), matches.group("ticket"), matches.group("as_uri")

    def _get_token_url(self, as_uri: str) -> str:
        # Get Token Endpoint from Realm UMA well-known
        wk_url = as_uri.lstrip("/") + self.UMA_WELL_KNOWN_URL_PATH
        wk = super().request("GET", wk_url, withhold_token=True).json()
        return wk["token_endpoint"]
