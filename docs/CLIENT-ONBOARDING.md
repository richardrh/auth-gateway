# Gateway client onboarding

This guide is for teams building a client of the auth gateway. Azure/Entra
administrators should use [AZURE-SETUP.md](AZURE-SETUP.md).

## Access model

The gateway is a **single-tenant, user-delegated** API edge:

- Browsers sign in with OpenID Connect and get an HttpOnly session cookie.
- Native, desktop and CLI clients obtain an Entra access token for the gateway
  API and send it as a bearer token.
- Only identities in the configured Entra tenant are accepted (other
  organizations' users must be B2B guests in that tenant).
- Every bearer token must contain the delegated scope `AzureAdApi:RequiredScope`
  (normally `access_as_user`) in `scp`.
- Requests to `AuthenticatedProxy` and `AuthenticatedGrpcProxy` routes need
  exactly one `Request-ID` header holding a UUID in `D` form, for example
  `2f1c2684-1d86-4a6f-86f8-61de9ff3408c`.

Not supported: client credentials, managed identity or other app-only tokens
(they carry `roles`, not `scp`); personal Microsoft accounts; cross-origin
browser SPAs (the gateway does not enable CORS); per-client or per-route scopes.
The gateway does not check the token's `azp`; Entra consent controls which
clients can obtain the scope.

| Client | Authentication | Entra registration |
| --- | --- | --- |
| Same-origin website | Gateway cookie | Existing confidential `AzureAdWeb` app |
| Desktop/native/CLI | Bearer access token, authorization code + PKCE | Public client app |
| Remote/headless CLI | Bearer access token, device code as fallback | Same public client app |
| Server/daemon | Not supported | None |

Use one public-client registration per independently owned client product and
environment. A public client ID is not a secret.

## Sign-in document

Native clients need the tenant, scope and their public client ID before they can sign in. The gateway does not
build that document: it serves whatever JSON you configure at a path you choose (`Gateway:Documents`), so the
content and the URL are deployment settings, not gateway code. It is anonymous and must hold no secrets.

```text
Gateway__Documents__0__Path=/.well-known/native-client
Gateway__Documents__0__Json={"schemaVersion":1, ...}
```

A document with no `Json` is not served (404). A relative path or invalid JSON fails startup, naming the path but
never the content. Responses use `Cache-Control: no-store`.

The gateway does not interpret the document, so its shape is a contract between your deployment and your
clients. A typical one carries the authority (`https://login.microsoftonline.com/<tenant>`), the tenant ID, one
public client ID per app, the full delegated scope (whose final segment matches `AzureAdApi:RequiredScope`) and
the allowed login methods. Set it from an environment variable such as `Gateway__Documents__0__Json`.

## Native, desktop and CLI clients

1. Use MSAL with the tenant-specific authority, public client ID, full scope and
   registered redirect URI.
2. Prefer authorization code with PKCE in the system browser. Use device code
   only when a loopback callback is impractical and the sign-in document
   advertises it; tenant policy may still block it.
3. Let MSAL cache tokens in OS-protected storage. Never log tokens, codes or
   PKCE verifiers.
4. Send the access token **for the gateway API**; ID tokens and Graph tokens are
   rejected.

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Request-ID: $(uuidgen)" \
  https://<gateway-public-host>/api/<backend-path>
```

Bearer requests need no CSRF token. Do not send an unrelated `Authorization`
header alongside a browser cookie: a bearer header switches the gateway to token
validation.

gRPC clients use the gateway's HTTP/2 port (`Gateway:GrpcPort`)
with `authorization: Bearer ...` and one `request-id` per call. Cookies are not
accepted there.

## Same-origin browser clients

Frontend JavaScript never handles Entra tokens.

1. Navigate to `/auth/login` (optional local `returnUrl`).
2. Call `/auth/me` to read the signed-in identity.
3. Before a `POST`, `PUT`, `PATCH` or `DELETE`, call `/auth/csrf` and send the
   returned `requestToken` in the `CSRF-Token` header.
4. Sign out with `POST /auth/logout`, also with the CSRF header.

## Expected failures

| Result | Likely cause |
| --- | --- |
| `401` | Missing token or cookie; invalid issuer, audience, signature or lifetime. |
| `403` | Bearer token lacks the required scope, or has no tenant/object ID. |
| `400` | Missing, malformed or duplicate `Request-ID`; failed CSRF validation. |
| Entra `AADSTS50011` | Redirect URI does not match the registration. |
| Entra consent error | Client lacks the delegated permission or admin consent. |

## Microsoft references

- [Configure a client to access a web API](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-access-web-apis)
- [Authorization code flow and PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Device authorization grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Public and confidential MSAL clients](https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-applications)
