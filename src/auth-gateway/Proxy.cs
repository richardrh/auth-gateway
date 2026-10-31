using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Antiforgery;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace AuthGateway;

/// <summary>
/// What a backend receives: the caller's credentials are removed and replaced by a signed identity assertion.
/// A route with metadata <c>"ServiceToken": "Name"</c> sends the bearer token <c>ServiceTokens:Name</c>
/// instead, for internal services that must not receive an assertion.
/// </summary>
internal static partial class Proxy
{
    private const string ServiceTokenMetadata = "ServiceToken";

    public static void Configure(TransformBuilderContext context, GatewayOptions gateway, IConfiguration configuration)
    {
        if (Policies.Is(context.Route, Policies.Anonymous))
        {
            context.AddRequestTransform(request =>
            {
                Strip(request, gateway);
                return ValueTask.CompletedTask;
            });
            return;
        }

        IdentityAssertion assertion = context.Services.GetRequiredService<IdentityAssertion>();
        bool browser = Policies.Is(context.Route, Policies.BrowserUser);
        bool serviceRoute = context.Route.Metadata?.TryGetValue(ServiceTokenMetadata, out string? name) is true;
        string? serviceToken = serviceRoute ? configuration[$"ServiceTokens:{context.Route.Metadata![ServiceTokenMetadata].Trim()}"]?.Trim() : null;
        context.AddRequestTransform(request =>
        {
            Strip(request, gateway);
            HttpContext http = request.HttpContext;
            if (Caller.From(http.User, gateway) is not { } caller)
            {
                Reject(http, StatusCodes.Status403Forbidden, AccessLog.AuthForbidden);
            }
            else if (serviceRoute)
            {
                if (string.IsNullOrEmpty(serviceToken))
                {
                    Reject(http, StatusCodes.Status503ServiceUnavailable, AccessLog.Unavailable);
                }
                else
                {
                    request.ProxyRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + serviceToken);
                }
            }
            else if (!Guid.TryParseExact(http.Request.Headers["Request-ID"].ToString(), "D", out Guid requestId))
            {
                Reject(http, StatusCodes.Status400BadRequest, AccessLog.RequestIdInvalid);
            }
            else
            {
                request.ProxyRequest.Headers.TryAddWithoutValidation(gateway.AssertionHeader, assertion.Create(caller, requestId.ToString("D")));
                if (browser)
                {
                    ProjectBrowserMetadata(request, gateway);
                }
            }
            return ValueTask.CompletedTask;
        });
    }

    // Server-rendered pages get the antiforgery token and finite cookie-backed settings as headers.
    // The raw cookies never leave the gateway.
    private static void ProjectBrowserMetadata(RequestTransformContext request, GatewayOptions gateway)
    {
        HttpContext http = request.HttpContext;
        if (gateway.CsrfHeader is not null)
        {
            AntiforgeryTokenSet tokens = http.RequestServices.GetRequiredService<IAntiforgery>().GetAndStoreTokens(http);
            if (string.IsNullOrEmpty(tokens.RequestToken))
            {
                Reject(http, StatusCodes.Status500InternalServerError, AccessLog.Unhandled);
                return;
            }
            request.ProxyRequest.Headers.TryAddWithoutValidation(gateway.CsrfHeader, tokens.RequestToken);
        }

        foreach ((string cookie, string header) in gateway.CookieHeaders)
        {
            if (http.Request.Cookies[cookie] is { } value && SimpleValue().IsMatch(value))
            {
                request.ProxyRequest.Headers.TryAddWithoutValidation(header, value);
            }
        }
    }

    private static void Strip(RequestTransformContext request, GatewayOptions gateway)
    {
        foreach (string header in gateway.Stripped)
        {
            RequestTransform.RemoveHeader(request, header);
        }
    }

    // Setting a status code stops YARP from forwarding the request.
    private static void Reject(HttpContext http, int status, string outcome)
    {
        AccessLog.SetOutcome(http, outcome);
        http.Response.StatusCode = status;
    }

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex SimpleValue();
}
