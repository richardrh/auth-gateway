using System.Text.Json;
using Yarp.ReverseProxy.Configuration;

namespace AuthGateway;

/// <summary>Route authorization policies. A YARP route selects one by name.</summary>
public static class Policies
{
    /// <summary>No authentication. Caller credentials are still stripped.</summary>
    public const string Anonymous = "Anonymous";

    /// <summary>A person in a browser, signed in with the session cookie. Unauthenticated callers are sent to sign in.</summary>
    public const string BrowserUser = "BrowserUser";

    /// <summary>A program or a browser: a bearer token with the required scope, or the session cookie.</summary>
    public const string AuthenticatedProxy = "AuthenticatedProxy";

    /// <summary>A gRPC client: a bearer token with the required scope.</summary>
    public const string AuthenticatedGrpcProxy = "AuthenticatedGrpcProxy";

    public static bool Is(RouteConfig route, string policy) =>
        string.Equals(route.AuthorizationPolicy, policy, StringComparison.OrdinalIgnoreCase);

    /// <summary>Programs get a 401 instead of a sign-in redirect, and must send their own Request-ID.</summary>
    public static bool IsProgram(RouteConfig route) => Is(route, AuthenticatedProxy) || Is(route, AuthenticatedGrpcProxy);
}

/// <summary>Deployment settings from the <c>Gateway</c> configuration section. Every setting is optional.</summary>
public sealed class GatewayOptions
{
    public const string Section = "Gateway";

    private string[]? stripped;

    /// <summary>The <c>service</c> field of access records.</summary>
    public string ServiceName { get; set; } = "auth-gateway";

    /// <summary>Header carrying the signed identity assertion to backends.</summary>
    public string AssertionHeader { get; set; } = "Identity-Assertion";

    /// <summary>When set, <c>BrowserUser</c> routes receive the antiforgery request token in this header.</summary>
    public string? CsrfHeader { get; set; }

    /// <summary>Browser entry point: served at <c>/</c> and the target of the htmx redirect after a CSRF failure.</summary>
    public string? Home { get; set; }

    /// <summary>Extra caller-supplied headers that never reach a backend.</summary>
    public string[] StripHeaders { get; set; } = [];

    /// <summary>Role claims that are forwarded. Empty forwards every role.</summary>
    public string[] AllowedRoles { get; set; } = [];

    /// <summary>The role forwarded when the caller has none of the allowed roles. Null forwards none.</summary>
    public string? DefaultRole { get; set; }

    /// <summary>
    /// When set, this port serves only <c>AuthenticatedGrpcProxy</c> routes and those routes are served
    /// only here. Zero applies no restriction.
    /// </summary>
    public int GrpcPort { get; set; }

    /// <summary>Cookie name to header name. A <c>BrowserUser</c> route receives the cookie's value (never the cookie) in the header.</summary>
    public Dictionary<string, string> CookieHeaders { get; set; } = [];

    /// <summary>
    /// JSON documents served anonymously at fixed paths, for example a client discovery document. A document
    /// with no <c>Json</c> is not served, so a profile can name the path and an environment can supply the content.
    /// </summary>
    public GatewayDocument[] Documents { get; set; } = [];

    /// <summary>Every header removed from a caller's request before it is proxied.</summary>
    public string[] Stripped => stripped ??=
    [
        "Authorization",
        "Cookie",
        "CSRF-Token",
        AssertionHeader,
        .. CsrfHeader is null ? [] : new[] { CsrfHeader },
        .. CookieHeaders.Values,
        .. StripHeaders,
    ];
}

/// <summary>A JSON document served at <see cref="Path"/> with <c>Cache-Control: no-store</c>.</summary>
public sealed class GatewayDocument
{
    public string Path { get; set; } = string.Empty;

    public string? Json { get; set; }

    /// <summary>Fails startup, naming the path (never the content), when the document cannot be served.</summary>
    public void Validate()
    {
        if (!Path.StartsWith('/') || Path.StartsWith("//", StringComparison.Ordinal) || Path.Any(char.IsWhiteSpace))
        {
            throw new InvalidOperationException($"Invalid configuration: {GatewayOptions.Section}:Documents path '{Path}'.");
        }

        try
        {
            using JsonDocument _ = JsonDocument.Parse(Json!);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"Invalid configuration: {GatewayOptions.Section}:Documents Json for '{Path}'.");
        }
    }
}
