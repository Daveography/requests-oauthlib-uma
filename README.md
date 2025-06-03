# UMA 2.0 Session Support for Requests-OAuthlib

Provides OAuth2 Sessions that support UMA 2.0 flows.

The `UMA2Session` class extends [`requests_oauthlib.OAuth2Session`](https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html), and so supports any OAuth2 clients for initial authentication. Once authenticated, if a Resource Server requires UMA authorization, the session will automatically attempt to obtain the required Requesting Party Token (RPT) with the necessary permissions, then retry the request.

See [User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization](https://docs.kantarainitiative.org/uma/wg/oauth-uma-grant-2.0-09.html) for more information.

**NOTE:** This project is not affiliated with [Requests-OAuthlib](https://github.com/requests/requests-oauthlib) or any of its dependent libraries.


## Install
```bash
pip install requests-oauthlib-uma
```


## Example

```python
from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib_uma import UMA2Session

# This example uses Legacy flow for initial authentication, but any OAuth2 Client can be used.
client_id = "your_client_id"
client_secret = "your_client_secret"
username = "your_username"
password = "your_password"
session = UMA2Session(client=LegacyApplicationClient(client_id=client_id))
token = session.fetch_token(
    token_url="https://somesite.com/oauth2/token",
    username=username,
    password=password,
    client_id=client_id,
    client_secret=client_secret,
)
print(token)

# Attempt to access a UMA-protected resource:
response = session.get("https://somesite.com/secure/resource")

# The session now uses the newly issued RPT as the auth token going forward
print(session.token)
```

If the resource raises a `401 Unauthorized` response with a `WWW-Authenticate` challenge header for a `UMA` scheme, the Session will automatically:
1. Determine the Authorization Server from the challenge header
2. Obtain the RPT endpoint URL from the Authorization Server's UMA 2.0 Well-Known Configuration endpoint
3. Request a token with the requested permission claims from the Authorization Server's RPT endpoint
4. Attempt the request again with the RPT

Subsequent requests will continue to use the issued RPT as the Session token.

If a subsequent request requires additional UMA authorization permissions not yet available in the RPT claims, the Session will repeat the above flow and attempt to upgrade the last-issued RPT with the added permission claims. This allows clients to incrementally obtain permission claims as needed.

### Refreshing Tokens

The `UMA2Session` supports refreshing expired tokens via the same mechanism as OAuth2Session; see [Refreshing tokens](https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens) for more details. Automatic token refresh always uses the `refresh_token` from the last-issued RPT if provided.

### Extra RPT Endpoint Parameters

If the Authorization Server is known to accept additional parameters (e.g., [Keycloak](https://www.keycloak.org/docs/latest/authorization_services/#_service_obtaining_permissions)), they can be configured when initializing the `UMA2Session`:

```python
session = UMA2Session(
    client=LegacyApplicationClient(client_id=client_id),
    fetch_rpt_kwargs={"audience": "other-client"},
)
```

### Handling Sequential Flows

By default, `UMA2Session` will only attempt a UMA flow once per request. If a Resource requires multiple UMA flows in order to grant authorization, you can increase the maximum number of attempts permitted per request: If the Resource is still requesting UMA authorization after reaching this limit, `requests_oauthlib_uma.exceptions.MaxUMAFlowsReachedError` is raised.

```python
from requests_oauthlib_uma.exceptions import MaxUMAFlowsReachedError

session = UMA2Session(
    client=LegacyApplicationClient(client_id=client_id),
    max_flows_per_request=2,
)

try:
    response = session.get("https://somesite.com/secure/resource")
except MaxUMAFlowsReachedError as err:
    print(f"Giving up after {err.last_attempt.attempt_number} UMA authorization attempts.")

    # Get the last response before the session gave up
    last_response = err.last_attempt.result()
    print(f"Last response was {last_response.status_code} - {last_response.text}")
```

### Default Headers

You can also configure the Session to always provide a set of default headers that will be provided with all requests:

```python
session = UMA2Session(
    client=LegacyApplicationClient(client_id=client_id),
    headers={"Content-Type": "application/json"},
)
```


## Contributing

This package utilizes [Poetry](https://python-poetry.org) for dependency management and [pre-commit](https://pre-commit.com/) for ensuring code formatting is automatically done and code style checks are performed.

```bash
git clone https://github.com/alpha-layer/requests-oauthlib-uma.git requests-oauthlib-uma
cd requests-oauthlib-uma
pip install poetry
poetry install
poetry run pre-commit install
poetry run pre-commit autoupdate
```
