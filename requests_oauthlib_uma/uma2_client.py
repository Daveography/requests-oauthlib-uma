from typing_extensions import Any

from oauthlib.oauth2 import Client
from oauthlib.oauth2.rfc6749.parameters import prepare_token_request


class UMA2Client(Client):
    """
    A :class:`oauthlib.oauth2.Client` that is used by a UMA Session to obtain and refresh an incremental Requesting
    Party Token (RPT) from an Authorization Server using the UMA 2.0 grant workflow:
    https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html
    """

    grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket"

    def __init__(self, client_id: str, token: dict[str, Any], **kwargs):
        """
        Initialize a new UMA 2.0 Client.

        Args:
            client_id (str, required): Client identifier given by the OAuth provider upon registration.
            token (dict[str, Any], required): A dict of token attributes such as ``access_token``, ``token_type`` and
                ``expires_at``.
            kwargs: Arguments to pass to the Client constructor.
        """
        super().__init__(client_id=client_id, token=token, **kwargs)

    def prepare_request_body(self, ticket: str, body="", **kwargs) -> str:
        """
        Prepare the RPT request body for UMA 2.0 grant workflow. Provides the current access token as the `rpt`
            parameter to upgrade it rather than issue a new one.
        https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html

        Args:
            ticket (str, required): The Permission Ticket returned from the Resource Server (obtained from the
                Authorization Server).
            body (str, optional): Existing request body (URL encoded string) to embed parameters into. This may contain
                extra parameters. Defaults to "".
            kwargs: Arguments to pass to the prepare_token_request method.

        Returns:
            str: A formatted RPT request body.
        """
        rpt = self.token["access_token"]
        return prepare_token_request(self.grant_type, ticket=ticket, rpt=rpt, body=body, **kwargs)

    def prepare_refresh_body(self, refresh_token: str, body="", **kwargs) -> str:
        """
        Prepare an access token request using a refresh token.

        Args:
            refresh_token (str, required): The refresh token issued to the client.
            body (str, optional): Existing request body (URL encoded string) to embed parameters into. This may contain
                extra parameters. Defaults to "".
            kwargs: Arguments to pass to the prepare_token_request method.

        Returns:
            str: A formatted refresh token request body.
        """

        return prepare_token_request(
            self.refresh_token_key, client_id=self.client_id, refresh_token=refresh_token, body=body, **kwargs
        )
