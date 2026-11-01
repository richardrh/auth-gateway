using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthGateway.E2E;

/// <summary>
/// A stand-in for Microsoft Entra, served over HTTPS on a loopback port: OpenID Connect discovery, signing keys, an
/// authorization endpoint that signs the user in without asking, and a token endpoint that checks the client secret,
/// the one-time code and the PKCE verifier before issuing an ID token. <see cref="Mint"/> issues API access tokens.
/// It is as strict as the gateway needs it to be and no stricter, so a gateway that sends the wrong response type,
/// redirect URI or verifier is refused.
/// </summary>
public sealed class FakeEntra : IAsyncDisposable
{
    public const string TenantId = "11111111-1111-1111-1111-111111111111";
    public const string UserObjectId = "22222222-2222-2222-2222-222222222222";
    public const string WebClientId = "55555555-5555-5555-5555-555555555555";
    public const string WebClientSecret = "fake-entra-client-secret";
    public const string ApiAudience = "api://44444444-4444-4444-4444-444444444444";
    public const string RequiredScope = "access_as_user";

    private const string KeyId = "k1";

    private sealed record Grant(string Nonce, string RedirectUri, string Challenge);

    private readonly RSA signingKey = RSA.Create(2048);
    private readonly RSA unknownKey = RSA.Create(2048);
    private readonly X509Certificate2 tls;
    private readonly ConcurrentDictionary<string, Grant> grants = new();
    private WebApplication? app;

    public FakeEntra(string directory)
    {
        using RSA tlsKey = RSA.Create(2048);
        CertificateRequest request = new("CN=fake-entra", tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SubjectAlternativeNameBuilder names = new();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        // Self-signed and marked as a CA so the gateway can trust this one file through SSL_CERT_FILE.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1));
        tls = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), null);
        CertificateFile = Path.Combine(directory, "fake-entra.pem");
        File.WriteAllText(CertificateFile, created.ExportCertificatePem());
        Thumbprint = created.GetCertHashString();
    }

    /// <summary>The certificate the gateway must trust (through SSL_CERT_FILE) to reach this server.</summary>
    public string CertificateFile { get; }

    public string Thumbprint { get; }

    public string BaseUrl { get; private set; } = string.Empty;

    public string Issuer => $"{BaseUrl}/{TenantId}/v2.0";

    public async Task StartAsync()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        _ = builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(tls)));
        app = builder.Build();
        Map(app);
        await app.StartAsync();
        BaseUrl = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().TrimEnd('/');
    }

    /// <summary>An API access token for the gateway's bearer routes. <paramref name="change"/> edits the claims.</summary>
    public string Mint(Action<Dictionary<string, object>>? change = null, bool signedByAnUnknownKey = false)
    {
        Dictionary<string, object> claims = Claims(ApiAudience);
        claims["scp"] = RequiredScope;
        claims["azp"] = WebClientId;
        change?.Invoke(claims);
        return Sign(claims, signedByAnUnknownKey ? unknownKey : signingKey);
    }

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.DisposeAsync();
        }
        signingKey.Dispose();
        unknownKey.Dispose();
        tls.Dispose();
    }

    private static string Sign(Dictionary<string, object> claims, RSA key) =>
        new JsonWebTokenHandler().CreateToken(
            JsonSerializer.Serialize(claims),
            new SigningCredentials(new RsaSecurityKey(key) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256));

    private Dictionary<string, object> Claims(string audience)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new()
        {
            ["iss"] = Issuer,
            ["aud"] = audience,
            ["sub"] = $"subject-{UserObjectId}",
            ["tid"] = TenantId,
            ["oid"] = UserObjectId,
            ["name"] = "Test User",
            ["preferred_username"] = "test@example.com",
            ["ver"] = "2.0",
            ["iat"] = now,
            ["nbf"] = now - 60,
            ["exp"] = now + 3600,
        };
    }

    private void Map(WebApplication endpoints)
    {
        _ = endpoints.MapGet("/{tenant}/v2.0/.well-known/openid-configuration", () =>
        {
            string tenant = $"{BaseUrl}/{TenantId}";
            return Results.Json(new Dictionary<string, object>
            {
                ["issuer"] = Issuer,
                ["authorization_endpoint"] = $"{tenant}/oauth2/v2.0/authorize",
                ["token_endpoint"] = $"{tenant}/oauth2/v2.0/token",
                ["jwks_uri"] = $"{tenant}/discovery/v2.0/keys",
                ["end_session_endpoint"] = $"{tenant}/oauth2/v2.0/logout",
                ["response_types_supported"] = new[] { "code", "id_token", "code id_token" },
                ["response_modes_supported"] = new[] { "query", "fragment", "form_post" },
                ["subject_types_supported"] = new[] { "pairwise" },
                ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
                ["scopes_supported"] = new[] { "openid", "profile", "email", "offline_access" },
                ["token_endpoint_auth_methods_supported"] = new[] { "client_secret_post", "client_secret_basic" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
            });
        });

        _ = endpoints.MapGet("/{tenant}/discovery/v2.0/keys", () =>
        {
            RSAParameters key = signingKey.ExportParameters(false);
            return Results.Json(new Dictionary<string, object>
            {
                ["keys"] = new[]
                {
                    new Dictionary<string, string>
                    {
                        ["kty"] = "RSA",
                        ["use"] = "sig",
                        ["alg"] = "RS256",
                        ["kid"] = KeyId,
                        ["n"] = Base64UrlEncoder.Encode(key.Modulus),
                        ["e"] = Base64UrlEncoder.Encode(key.Exponent),
                    },
                },
            });
        });

        _ = endpoints.MapGet("/{tenant}/oauth2/v2.0/authorize", (HttpContext context) =>
        {
            IQueryCollection query = context.Request.Query;
            string redirect = query["redirect_uri"].ToString();
            if (query["client_id"] != WebClientId || query["response_type"] != "code" || redirect.Length == 0
                || query["code_challenge_method"] != "S256" || query["code_challenge"].ToString().Length == 0)
            {
                return Results.BadRequest($"unsupported authorize request: {context.Request.QueryString}");
            }

            string code = Guid.NewGuid().ToString("N");
            grants[code] = new(query["nonce"].ToString(), redirect, query["code_challenge"].ToString());
            return Results.Redirect(QueryHelpers.AddQueryString(redirect, new Dictionary<string, string?>
            {
                ["code"] = code,
                ["state"] = query["state"].ToString(),
            }));
        });

        _ = endpoints.MapPost("/{tenant}/oauth2/v2.0/token", async (HttpContext context) =>
        {
            IFormCollection form = await context.Request.ReadFormAsync();
            string clientId = form["client_id"].ToString();
            string secret = form["client_secret"].ToString();
            string authorization = context.Request.Headers.Authorization.ToString();
            if (authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                string[] pair = Encoding.UTF8.GetString(Convert.FromBase64String(authorization[6..])).Split(':', 2);
                (clientId, secret) = (Uri.UnescapeDataString(pair[0]), Uri.UnescapeDataString(pair[1]));
            }

            bool found = grants.TryRemove(form["code"].ToString(), out Grant? grant);
            string verifier = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString())));
            if (!found || grant is null || clientId != WebClientId || secret != WebClientSecret
                || form["grant_type"] != "authorization_code" || form["redirect_uri"] != grant.RedirectUri || verifier != grant.Challenge)
            {
                return Results.Json(new Dictionary<string, string> { ["error"] = "invalid_grant" }, statusCode: 400);
            }

            Dictionary<string, object> claims = Claims(WebClientId);
            claims["nonce"] = grant.Nonce;
            claims["roles"] = new[] { "admin" };
            return Results.Json(new Dictionary<string, object>
            {
                ["token_type"] = "Bearer",
                ["expires_in"] = 3600,
                ["access_token"] = "opaque-token-for-another-api",
                ["id_token"] = Sign(claims, signingKey),
            });
        });

        _ = endpoints.MapGet("/{tenant}/oauth2/v2.0/logout", (HttpContext context) =>
        {
            string after = context.Request.Query["post_logout_redirect_uri"].ToString();
            return after.Length > 0 ? Results.Redirect(after) : Results.Text("signed out");
        });
    }
}
