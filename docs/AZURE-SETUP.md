# Microsoft Entra setup for the auth gateway

This runbook creates the Entra resources consumed by `auth-gateway`. It reflects
the current code: one workforce tenant, browser sessions, and delegated bearer
access. Client teams should use [CLIENT-ONBOARDING.md](CLIENT-ONBOARDING.md).

## Target design

Create three app registrations in the same tenant for each environment:

| Registration | Type | Purpose | Credential |
| --- | --- | --- | --- |
| `<env>-auth-gateway-api` | Web API resource | Defines the bearer audience and delegated scope. | None for current validation-only use. |
| `<env>-auth-gateway-web` | Confidential web app | Gateway OIDC login and logout. | Client secret stored server-side. |
| `<env>-<product>-client` | Public native client | Desktop/CLI access to the API scope. | None. |

Create separate registrations for production and nonproduction. Do not put local
development redirect URIs or test credentials on a production registration.
Assign at least two accountable owners to every registration and record the
application IDs, object IDs, tenant ID, App ID URI, secret expiry, and owner.

Configure all registrations as **Accounts in this organizational directory only
(single tenant)** and use the same tenant GUID for `AzureAdWeb:TenantId` and
`AzureAdApi:TenantId`. Single tenant includes members and B2B guests represented
in this tenant; it does not make arbitrary customer tenants trusted issuers.

## Prerequisites

- A Microsoft Entra workforce tenant owned by the company.
- A verified custom domain for production branding.
- At least `Application Developer` to create registrations. Configuring the API
  and granting tenant-wide consent normally requires `Cloud Application
  Administrator` or another approved privileged role.
- The final public HTTPS gateway origin, for example
  `https://gateway.example.com`.
- An external secret manager and a rotation owner for the web credential.

Use least-privilege, time-bound admin activation where the tenant supports it.

## 1. Register the gateway API resource

In **Microsoft Entra admin center > Entra ID > App registrations > New
registration**:

1. Name it `<env>-auth-gateway-api`.
2. Select **Single tenant**.
3. Do not add a redirect URI.
4. Add the accountable owners.
5. Record its **Application (client) ID** as `<api-client-id>` and the directory
   **Tenant ID** as `<tenant-id>`.

Under **Expose an API**:

1. Set the Application ID URI. The standard value is
   `api://<api-client-id>`; record the actual value as `<api-app-id-uri>`.
2. Add one delegated scope with these values:

   | Field | Value |
   | --- | --- |
   | Scope name | `access_as_user` |
   | Who can consent | `Admins only` |
   | Admin consent display name | `Access the auth gateway as the signed-in user` |
   | Admin consent description | `Allows this application to call protected gateway APIs on behalf of the signed-in user.` |
   | State | Enabled |

`AzureAdApi:Audience` must equal `<api-app-id-uri>`, while
`AzureAdApi:RequiredScope` is only the unqualified name `access_as_user`.

Do not add application permissions/app roles for machine access yet. The gateway
requires the delegated `scp` claim and would reject an app-only token. Entra app
roles may still be designed for downstream business authorization; the gateway
forwards them in the identity assertion, filtered by `Gateway:AllowedRoles`.

## 2. Register the confidential browser web app

Create `<env>-auth-gateway-web`:

1. Select **Single tenant**.
2. Under **Authentication**, add the **Web** redirect URI
   `https://<gateway-public-host>/signin-oidc`.
3. Set the front-channel logout URL to
   `https://<gateway-public-host>/signout-oidc`.
4. Do not enable implicit access-token or ID-token grants. The ASP.NET Core OIDC
   handler uses the authorization-code flow.
5. Add the accountable owners.
6. Record its **Application (client) ID** as `<web-client-id>`.

Under **Certificates & secrets**, create a client secret according to company
expiry policy. Copy the secret **value**, not its portal object ID, directly to
the external secret manager. It is the value consumed by
`AzureAdWeb:ClientSecret`. Never put it in source control, a frontend, a native
client, documentation, logs, or an image.

The web registration does not need the gateway API delegated permission. The
browser accesses `/api/**` with the gateway's local session cookie rather than a
bearer token.

For rotation, create an overlapping replacement, update the secret manager and
deployment, complete browser sign-in verification, then remove the old
credential. Do not delete the active credential first.

## 3. Register each approved public client

Create one `<env>-<product>-client` for each independently owned/revoked native,
desktop, or CLI product:

1. Select **Single tenant** and add accountable owners.
2. Under **Authentication > Add a platform > Mobile and desktop
   applications**, register the exact redirect URI used by MSAL. For a
   system-browser loopback flow, use the library's supported loopback URI such
   as `http://localhost` and keep its path consistent with the client.
3. Leave client secrets and certificates empty. A distributed application is a
   public client and cannot protect either.
4. Under **API permissions > Add a permission > My APIs**, select
   `<env>-auth-gateway-api`, **Delegated permissions**, and
   `access_as_user`.
5. Grant tenant admin consent through the approved change process.
6. If device code is genuinely required, set **Authentication > Advanced
   settings > Allow public client flows** to **Yes**. Leave it off when the
   client only needs authorization code + PKCE.

Optionally add a trusted first-party public client under the API registration's
**Expose an API > Authorized client applications** to suppress individual user
consent. Preauthorization is a consent experience, not a runtime gateway
allowlist; use it only for client IDs the company controls.

Return the tenant ID, public client ID, `<api-app-id-uri>/access_as_user`, exact
redirect URI, and gateway base URL to the client owner. Return no credential.

Device code can be restricted by Conditional Access or tenant policy. Treat it
as a headless fallback, test it against production policy, and prefer
system-browser PKCE when a local callback works.

## 4. Decide who may sign in

Authentication alone currently authorizes access to the gateway's common
`/api/**` policy. Before production:

1. Decide which tenant members and B2B guests may use the product.
2. Apply the organization's Enterprise Application assignment, group,
   Conditional Access, MFA, guest lifecycle, and access review policies to the
   web/public client applications as appropriate.
3. Keep business and customer-resource authorization in downstream services.
   They receive a signed identity assertion (`tid`, `oid`, optional `sid`,
   `roles`, `request_id`) in the `Gateway:AssertionHeader` header.
4. Ensure downstream ingress is reachable only through the gateway; otherwise a
   caller could bypass its authentication and identity-header replacement.

If downstream services authorize roles, design deliberately for both paths:
browser role claims originate from the web registration's sign-in token, while
bearer role claims originate from the API resource token. The gateway does not
make those two role sets equivalent and does not reject an absent role
(`Gateway:DefaultRole` may supply one).

## 5. Configure the gateway

Map the recorded values to runtime configuration:

| Gateway setting | Value |
| --- | --- |
| `AzureAdWeb:Instance` | `https://login.microsoftonline.com/` |
| `AzureAdWeb:TenantId` | `<tenant-id>` |
| `AzureAdWeb:ClientId` | `<web-client-id>` |
| `AzureAdWeb:ClientSecret` | Web secret **value** from the secret manager |
| `AzureAdWeb:CallbackPath` | `/signin-oidc` |
| `AzureAdWeb:SignedOutCallbackPath` | `/signout-callback-oidc` |
| `AzureAdApi:Instance` | `https://login.microsoftonline.com/` |
| `AzureAdApi:TenantId` | `<tenant-id>` |
| `AzureAdApi:ClientId` | `<api-client-id>` |
| `AzureAdApi:Audience` | `<api-app-id-uri>` |
| `AzureAdApi:RequiredScope` | `access_as_user` |

The Kubernetes base manifest reads these keys from the externally created
`auth-gateway-entra` Secret:

```bash
kubectl create secret generic auth-gateway-entra \
  --from-literal=web-tenant-id='<tenant-id>' \
  --from-literal=web-client-id='<web-client-id>' \
  --from-literal=web-client-secret='<web-client-secret-value>' \
  --from-literal=api-tenant-id='<tenant-id>' \
  --from-literal=api-client-id='<api-client-id>' \
  --from-literal=api-audience='<api-app-id-uri>' \
  --from-literal=api-required-scope='access_as_user' \
  --from-literal=identity-assertion-key='<base64-encoded-32-byte-or-longer-key>'
```

This command is an interface example, not a production secret-management
recommendation. Production delivery should reconcile the Kubernetes Secret from
the approved external secret manager.
The signing key must match the key your backend verifies with (for example the `primary` entry in its key set); Kubernetes does not generate or synchronize it.

The external TLS edge must preserve the public scheme and host through forwarded
headers. Configure only its known proxy address/network; never trust forwarded
headers from every source. The OIDC redirect URI generated by the gateway must
exactly match the HTTPS URI registered in Entra.

Persist ASP.NET Core Data Protection keys at the configured absolute
`DataProtection:KeysPath`, retain old key files, and share them across replicas.
Losing or isolating these keys invalidates browser sessions and OIDC state.

## 6. Production verification

Use real test identities and perform all checks before granting wider access.

### Browser

1. Request `/auth/login` and complete Entra sign-in, including MFA.
2. Confirm the callback returns to the public HTTPS origin without
   `AADSTS50011`.
3. Confirm `/auth/me` returns the expected tenant ID and object ID.
4. Call an `/api/**` GET with a UUID `Request-ID` and confirm the downstream
   identity is the signed-in user.
5. Fetch `/auth/csrf`, make a protected mutation with `CSRF-Token` and a new
   `Request-ID`, then complete `POST /auth/logout` with CSRF protection.

### Public client

1. Acquire a token with MSAL using the tenant-specific authority, public client
   ID, and `<api-app-id-uri>/access_as_user`.
2. Call `/api/**` with `Authorization: Bearer <access-token>` and one UUID
   `Request-ID`; confirm the expected downstream identity.
3. Confirm a token for Microsoft Graph or the wrong audience returns `401`.
4. Confirm a valid gateway token without `access_as_user` returns `403`.
5. If enabled, repeat token acquisition with device code under the actual
   Conditional Access policy.

Do not paste production tokens into third-party token viewers. Retain Entra
sign-in/audit evidence and gateway request IDs according to the organization's
security and privacy policy, but never log token or authorization-code values.

## Tenant expansion and service clients

A multitenant or app-only launch cannot be achieved safely by changing
`Supported account types` in the portal:

- both web and API settings name one tenant;
- issuer validation targets one tenant;
- bearer authorization requires delegated `scp`, not application `roles`;
- there is no tenant onboarding/allowlist or client-ID policy; and
- downstream data isolation still depends on tenant/object authorization.

Treat either capability as a separate security design and gateway change. For a
multitenant product, include verified-publisher setup, per-customer admin
consent, explicit issuer/tenant admission, offboarding, and audit controls.
Publisher verification requires a verified Microsoft AI Cloud Partner Program
account, an associated Entra tenant, a non-`onmicrosoft.com` publisher domain,
and the required Entra/Partner Center roles. It is useful for external
multitenant consent but is not a substitute for authorization.

## Microsoft references

- [Register an Entra application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Expose a web API and delegated scope](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis)
- [Configure a client application's API permission](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-access-web-apis)
- [Redirect URI restrictions and loopback behavior](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Public and confidential MSAL clients](https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-applications)
- [OAuth authorization code and PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [OAuth device authorization grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [Publisher verification](https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview)
