# Auth gateway

A lightweight Microsoft Entra authentication gateway: ASP.NET Core 10, YARP and Microsoft.Identity.Web.
It authenticates every request, removes the caller's credentials, and forwards the request to a backend
with a short-lived signed identity assertion. Backends never see Entra tokens or session cookies.

Request flow:

1. The access log assigns or accepts a `Request-ID` (outermost middleware).
2. Optional forwarded headers, routing, listener check (`Gateway:GrpcPort`), Request-ID check for program routes.
3. Authentication: the session cookie `__Host-auth-gateway` (Entra OIDC, 8 h sliding) or an Entra bearer
   access token carrying `AzureAdApi:RequiredScope`.
4. CSRF validation for cookie sessions on POST/PUT/PATCH/DELETE (bearer requests are exempt).
5. Route authorization policy, then YARP strips caller headers and adds the assertion.
6. One JSON access record is written to stdout.

## Quick start

Needs the .NET 10 SDK. The demo backend echoes every request it receives, so you can see what the gateway forwards.

```bash
# terminal 1: demo backend on http://localhost:5013
dotnet run --project src/backend-test

# terminal 2: the gateway on http://localhost:5295, using development credentials instead of Entra
ASPNETCORE_ENVIRONMENT=Development \
DevelopmentAuth__Enabled=true DevelopmentAuth__Password=dev-password \
DevelopmentAuth__TenantId=00000000-0000-0000-0000-000000000001 \
DevelopmentAuth__ObjectId=00000000-0000-0000-0000-000000000002 \
GATEWAY_CONFIG_FILE=$PWD/examples/quickstart.json \
dotnet run --project src/auth-gateway

# terminal 3
curl -u development-user:dev-password http://localhost:5295/app/hello
curl -u development-user:dev-password -H "Request-ID: $(uuidgen)" http://localhost:5295/api/hello
```

The backend's reply lists its request headers. `Authorization` is gone, and `Identity-Assertion` holds the
short-lived signed token that tells the backend who called. Programs must send a `Request-ID` (the second call);
browser routes get one assigned.

`appsettings.Development.json` supplies an assertion audience and key for local use. The routes live in
[`examples/quickstart.json`](examples/quickstart.json): one browser route (`BrowserUser`) and one API route
(`AuthenticatedProxy`) in front of one cluster. `DevelopmentAuth` only works in the Development environment; real
deployments use the `AzureAdWeb` and `AzureAdApi` settings below.

## Gateway endpoints

| Path | Purpose |
| --- | --- |
| `GET /auth/login?returnUrl=` | Starts Entra sign-in; only local return URLs are honoured. |
| `POST /auth/logout` | Signs out (cookie + OIDC). Requires the CSRF token. |
| `GET /auth/csrf` | Returns `{ "requestToken": ... }`; send it back in the `CSRF-Token` header. |
| `GET /auth/me` | Name, tenant ID, object ID and forwarded roles of the cookie session. |
| `/health/live`, `/health/ready` | Anonymous health checks. |
| `/` | Redirect to `Gateway:Home`, when set. |
| `Gateway:Documents` paths | Anonymous JSON documents served from configuration, for example a native-client sign-in document (see `docs/CLIENT-ONBOARDING.md`). |

## Route policies and metadata

Each YARP route sets `AuthorizationPolicy` to one of:

| Policy | Accepts | Unauthenticated |
| --- | --- | --- |
| `Anonymous` | anyone; caller credentials are still stripped, no assertion | n/a |
| `BrowserUser` | session cookie | redirect to `/auth/login?returnUrl=...`; htmx requests get `HX-Redirect` |
| `AuthenticatedProxy` | bearer with the required scope, or session cookie | bare 401/403 |
| `AuthenticatedGrpcProxy` | bearer with the required scope only | bare 401/403 |

`AuthenticatedProxy` and `AuthenticatedGrpcProxy` routes are for programs: the caller must send exactly one
canonical UUID `Request-ID` header or gets 400 (`request_id_invalid`). Browser and anonymous routes use the
Request-ID the gateway assigned. The response always carries the gateway's `Request-ID`.

Route metadata:

- `"ServiceToken": "Name"` sends `Authorization: Bearer <ServiceTokens:Name>` instead of an assertion,
  for internal services. If the token is not configured the gateway answers 503 (`unavailable`).
- Any other YARP transform (for example `RequestHeaderRouteValue`) is plain YARP configuration.

`BrowserUser` routes also receive the antiforgery request token in `Gateway:CsrfHeader` and the values of
`Gateway:CookieHeaders` cookies (only values matching `^[A-Za-z0-9._-]{1,64}$`; the cookie itself is never sent).

## Identity assertion

An HS256 JWT in the `Gateway:AssertionHeader` header (default `Identity-Assertion`), created with
`JsonWebTokenHandler`. Claims: `iss`, `aud`, `iat`, `exp`, `jti`, `tid`, `oid`, `request_id`, `roles`, and
`sid` when the Entra token has one. `roles` is filtered by `Gateway:AllowedRoles`; `Gateway:DefaultRole` is
used when none remain. A caller without a GUID `tid` and `oid` gets 403. Lifetime is
`IdentityAssertion:LifetimeSeconds` (1-60, default 30).

Key rotation: the header names the key in `kid`. Backends accept every key in `IdentityAssertion:Keys`;
the gateway signs with `IdentityAssertion:CurrentKeyId`. Add the new key to backends first, then switch
`CurrentKeyId`, then remove the old key. Keys are base64 and at least 32 bytes.

## Configuration

`Gateway` section (all optional):

| Key | Default | Meaning |
| --- | --- | --- |
| `ServiceName` | `auth-gateway` | `service` field of access records |
| `AssertionHeader` | `Identity-Assertion` | Header carrying the assertion |
| `CsrfHeader` | none | `BrowserUser` routes receive the antiforgery request token in it |
| `Home` | none | Redirect target of `/` and of htmx CSRF failures |
| `StripHeaders` | `[]` | Extra caller headers removed before proxying |
| `AllowedRoles` | `[]` (all) | Role claims forwarded in the assertion |
| `DefaultRole` | none | Role forwarded when the caller has no allowed role |
| `GrpcPort` | `0` | When set, this port serves only `AuthenticatedGrpcProxy` routes, which are served only there; others get 404 (`listener_rejected`) |
| `CookieHeaders` | `{}` | Cookie name to header name for `BrowserUser` routes |
| `Documents` | `[]` | `[{ "Path": "/.well-known/x", "Json": "{...}" }]`: served anonymously as `application/json` with `Cache-Control: no-store`. An entry with no `Json` is not served, so a profile can name the path and an environment variable (`Gateway__Documents__0__Json`) supply the content. A bad path or invalid JSON fails startup naming the path. |

Always removed from callers: `Authorization`, `Cookie`, `CSRF-Token`, the assertion header, `CsrfHeader`,
the `CookieHeaders` header names, and `StripHeaders`.

| Section | Keys |
| --- | --- |
| `AzureAdWeb` | `Instance`, `TenantId`, `ClientId`, `ClientSecret`, `CallbackPath`, `SignedOutCallbackPath` (browser OIDC app) |
| `AzureAdApi` | `Instance`, `TenantId`, `ClientId`, `Audience`, `RequiredScope` (bearer validation). Entra keys are required outside Development. |
| `IdentityAssertion` | `Issuer`, `Audience`, `CurrentKeyId`, `LifetimeSeconds`, `Keys:{kid}` |
| `ForwardedHeaders` | `Enabled`, `ForwardLimit` (default 1), `KnownProxies[]`, `KnownNetworks[]` (middleware runs only when enabled) |
| `DataProtection` | `KeysPath`: absolute directory for cookie keys, required outside Development |
| `ServiceTokens` | `{Name}`: tokens for `ServiceToken` routes |
| `DevelopmentAuth` | `Enabled`, `Username` (default `development-user`), `Password`, `TokenFile`, `TenantId`, `ObjectId` |
| `Logging:LogLevel` | Standard levels; `AuthGateway.AccessLog` gates access records |

`DevelopmentAuth` is allowed only in the Development environment and needs `Password` (HTTP Basic) or
`TokenFile` (a non-JWT bearer token of at least 32 characters; a token with two dots goes to Entra). The
identity gets `tid`, `oid`, `name` and `scp` = `AzureAdApi:RequiredScope`. Cookie/OIDC sign-in is bypassed:
`/auth/login` challenges for Basic/Bearer, `/auth/logout` returns 400, and the antiforgery cookie is
`auth-gateway-csrf`.

`GATEWAY_CONFIG_FILE` names a JSON deployment profile. Precedence, lowest first: `appsettings*.json`,
the profile, environment variables, command line.

## Access log

One JSON line per request on stdout (successful health checks are skipped):

```json
{"time":"2026-10-31T12:00:00.1234567Z","level":"WARN","msg":"http request","service":"auth-gateway",
 "request_id":"...","trace_id":"...","span_id":"...","method":"POST","route":"/api/{**catch-all}",
 "route_id":"api-route","status":401,"duration_ms":3,"outcome":"auth_unauthenticated"}
```

`level` is `INFO`, `WARN` (4xx) or `ERROR` (5xx). `route` is the matched template, never the raw path.
`route_id` and `proxy_error` (YARP `ForwarderError` name) appear only when relevant. Outcomes: `proxied`,
`local`, `listener_rejected`, `request_id_invalid`, `csrf_invalid`, `auth_unauthenticated`,
`auth_forbidden`, `unavailable`, `upstream_error`, `unhandled_exception`. Other logs use the plain
single-line console logger.

## Docker and Kubernetes

- The image listens on 8080 (HTTP/1.1) and 8082 (HTTP/2, for gRPC) through `Kestrel__Endpoints__*`.
- Multiple replicas must share `DataProtection:KeysPath` (a shared volume), or sessions break across pods.
- Behind an ingress set `ForwardedHeaders:Enabled=true` and list the ingress in `KnownProxies`/`KnownNetworks`.
- Supply secrets (`AzureAdWeb:ClientSecret`, `IdentityAssertion:Keys:*`, `ServiceTokens:*`) as environment variables.
- TLS ends at the ingress. Cookies are `Secure`-only, so without `ForwardedHeaders` a browser request over plain HTTP
  fails at the proxy step with an antiforgery "not an SSL request" error.
- Data Protection keys are written to `DataProtection:KeysPath` unencrypted (the framework logs "No XML encryptor
  configured"). Protect that volume as you would a secret; anyone who can read it can forge session cookies.
- Sessions live in the cookie, so `/auth/logout` clears it but does not revoke a copy that was already stolen; it stays
  valid until it expires (8 hours of inactivity).
- Failed bearer validation is logged at Information by `Microsoft.AspNetCore.Authentication.JwtBearer`, which the default
  `Logging:LogLevel` hides. Set `Logging__LogLevel__Microsoft.AspNetCore.Authentication=Information` to see why tokens are rejected.

## Kubernetes manifests

`deploy/kubernetes` is a kustomize base: a Deployment, a Service (80 for HTTP, 81 for gRPC), a PVC for the Data
Protection keys, and an empty profile ConfigMap. The pod runs as UID 1654 with a read-only root filesystem, all
capabilities dropped and the default seccomp profile, and pauses 5 s in `preStop` so the Service stops routing to it
before it refuses connections.

Configuration reaches the pod three ways, and every key is an environment variable name:

| Resource | Holds | Required |
| --- | --- | --- |
| ConfigMap `auth-gateway-env` | plain settings: `AzureAdWeb__TenantId`, `AzureAdApi__Audience`, `ForwardedHeaders__Enabled`, `ReverseProxy__Clusters__<id>__Destinations__<name>__Address` | no |
| Secret `auth-gateway-secrets` | `AzureAdWeb__ClientSecret`, `IdentityAssertion__Keys__<id>`, `ServiceTokens__<Name>` | yes |
| ConfigMap `auth-gateway-profile` | the deployment profile mounted at `GATEWAY_CONFIG_FILE` (routes, header names) | defaults to no routes |

An overlay supplies them and points the image at your registry:

```yaml
resources: [../../base]            # this directory
images:
  - name: auth-gateway
    newName: registry.example.com/auth-gateway
    newTag: "1.0.0"
configMapGenerator:
  - name: auth-gateway-profile
    behavior: replace
    files: [gateway.json=my-profile.json]
  - name: auth-gateway-env
    literals: [AzureAdWeb__TenantId=..., AzureAdApi__Audience=...]
secretGenerator:
  - name: auth-gateway-secrets
    literals: [AzureAdWeb__ClientSecret=..., IdentityAssertion__Keys__primary=...]
```

Generated names carry a content hash, so changing any of them rolls the pods. A bad value (for example a blank
client secret) makes the new pod fail at startup with the setting named; the old pod keeps serving and the rollout
stalls instead of taking the gateway down.

The PVC is `ReadWriteOnce`, which is enough for replicas on one node. Use a `ReadWriteMany` volume when they run on
several, since every replica must read the same key ring. Behind an ingress, set `ForwardedHeaders__Enabled=true` and
list the pod network and ingress in `ForwardedHeaders__KnownNetworks__<n>`.
