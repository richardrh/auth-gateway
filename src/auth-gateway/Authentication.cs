using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;

namespace AuthGateway;

internal static class GatewayAuth
{
    /// <summary>Policy scheme that picks the cookie, Entra bearer or development scheme per request.</summary>
    public const string Scheme = "Gateway";

    public static readonly string[] RequiredEntraSettings =
    [
        "AzureAdWeb:TenantId", "AzureAdWeb:ClientId", "AzureAdWeb:ClientSecret",
        "AzureAdApi:TenantId", "AzureAdApi:ClientId", "AzureAdApi:Audience", "AzureAdApi:RequiredScope",
    ];

    public static string SelectScheme(HttpContext context, bool development)
    {
        if (!HasBearer(context.Request))
        {
            return development ? DevelopmentUser.Scheme : CookieAuthenticationDefaults.AuthenticationScheme;
        }

        // Entra access tokens are JWTs; the development token is not.
        bool jwt = context.Request.Headers.Authorization.Any(value => value is not null && value.Count(character => character == '.') == 2);
        return development && !jwt ? DevelopmentUser.Scheme : JwtBearerDefaults.AuthenticationScheme;
    }

    public static bool HasBearer(HttpRequest request) =>
        request.Headers.Authorization.Any(value => value is not null
            && value.StartsWith("Bearer", StringComparison.OrdinalIgnoreCase)
            && (value.Length == "Bearer".Length || char.IsWhiteSpace(value["Bearer".Length])));

    /// <summary>Whether the token's <c>scp</c> claim contains the scope.</summary>
    public static bool HasScope(ClaimsPrincipal user, string scope) =>
        user.FindAll("scp").Any(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(scope, StringComparer.Ordinal));

    public static bool IsLocalReturnUrl(string? returnUrl) => RedirectHttpResult.IsLocalUrl(returnUrl);

    public static void ConfigureCookie(CookieAuthenticationOptions options)
    {
        options.Cookie.Name = "__Host-auth-gateway";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.Path = "/";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.LoginPath = "/auth/login";
        options.AccessDeniedPath = "/auth/login";
        options.Events.OnRedirectToLogin = context => Reject(context, StatusCodes.Status401Unauthorized);
        options.Events.OnRedirectToAccessDenied = context => Reject(context, StatusCodes.Status403Forbidden);
    }

    // Browser routes send people to sign in (htmx gets HX-Redirect). Programs get a bare 401/403.
    private static Task Reject(RedirectContext<CookieAuthenticationOptions> context, int statusCode)
    {
        bool program = context.Request.Path.Equals("/auth/me", StringComparison.Ordinal)
            || (context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is { } route && !Policies.Is(route.Config, Policies.BrowserUser));
        if (program)
        {
            context.Response.StatusCode = statusCode;
            return Task.CompletedTask;
        }

        string returnUrl = $"{context.Request.PathBase}{context.Request.Path}{context.Request.QueryString}";
        string login = IsLocalReturnUrl(returnUrl) ? $"/auth/login?returnUrl={Uri.EscapeDataString(returnUrl)}" : "/auth/login";
        if (context.Request.Headers["HX-Request"] == "true")
        {
            context.Response.Headers["HX-Redirect"] = login;
            context.Response.StatusCode = statusCode;
        }
        else
        {
            context.Response.Redirect(login);
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// One fixed development identity, signed in with HTTP Basic or a static bearer token. Development
/// environment only. Both secrets are optional but at least one is required.
/// </summary>
public sealed record DevelopmentUser(string Username, string TenantId, string ObjectId, string Scope, byte[][] Digests)
{
    public const string Section = "DevelopmentAuth";
    public const string Scheme = "Development";

    public bool HasPassword { get; init; }

    public static DevelopmentUser? Load(IConfiguration configuration, IHostEnvironment environment)
    {
        IConfigurationSection section = configuration.GetSection(Section);
        if (!section.GetValue<bool>("Enabled"))
        {
            return null;
        }
        if (!environment.IsDevelopment())
        {
            throw new InvalidOperationException($"{Section} is permitted only in Development.");
        }

        string username = section["Username"] is { Length: > 0 } name ? name : "development-user";
        List<byte[]> digests = [];
        string? password = section["Password"];
        if (!string.IsNullOrEmpty(password))
        {
            digests.Add(Digest("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))));
        }
        if (section["TokenFile"] is { Length: > 0 } tokenFile)
        {
            string token = File.ReadAllText(tokenFile).Trim();
            if (token.Length < 32)
            {
                throw new InvalidOperationException($"{Section}:TokenFile must contain a token of at least 32 characters.");
            }
            digests.Add(Digest("Bearer " + token));
        }
        if (digests.Count == 0)
        {
            throw new InvalidOperationException($"{Section} requires Password or TokenFile.");
        }

        return new DevelopmentUser(
            username,
            Guid.Parse(section["TenantId"] ?? throw new InvalidOperationException($"{Section}:TenantId is required.")).ToString("D"),
            Guid.Parse(section["ObjectId"] ?? throw new InvalidOperationException($"{Section}:ObjectId is required.")).ToString("D"),
            configuration["AzureAdApi:RequiredScope"] ?? string.Empty,
            [.. digests])
        { HasPassword = !string.IsNullOrEmpty(password) };
    }

    private static byte[] Digest(string credentials) => SHA256.HashData(Encoding.UTF8.GetBytes(credentials));
}

public sealed class DevelopmentAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    DevelopmentUser user) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Request.Headers.Authorization.Count == 0)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Comparing digests keeps the comparison constant-time whatever the input length.
        byte[] presented = SHA256.HashData(Encoding.UTF8.GetBytes(Request.Headers.Authorization.ToString()));
        bool valid = AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out _)
            && Request.Headers.Authorization.Count == 1
            && user.Digests.Any(digest => CryptographicOperations.FixedTimeEquals(presented, digest));
        if (!valid)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid development credentials."));
        }

        ClaimsIdentity identity = new(
            [
                new Claim(ClaimTypes.NameIdentifier, user.ObjectId),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("tid", user.TenantId),
                new Claim("oid", user.ObjectId),
                new Claim("scp", user.Scope),
            ],
            DevelopmentUser.Scheme);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), DevelopmentUser.Scheme)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = user.HasPassword ? "Basic realm=\"Local development\", charset=\"UTF-8\"" : "Bearer";
        Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    }
}
