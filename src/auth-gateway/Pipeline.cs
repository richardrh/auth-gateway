using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Model;

namespace AuthGateway;

/// <summary>Request checks that run before and after authentication.</summary>
internal static class Pipeline
{
    public const string RequestIdHeader = "Request-ID";

    public static RouteModel? Route(HttpContext context) => context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>();

    /// <summary>The gRPC port serves only gRPC routes, and gRPC routes are served only there.</summary>
    public static async Task Listener(HttpContext context, RequestDelegate next, GatewayOptions gateway)
    {
        bool grpcRoute = Route(context) is { } route && Policies.Is(route.Config, Policies.AuthenticatedGrpcProxy);
        if (gateway.GrpcPort != 0 && (context.Connection.LocalPort == gateway.GrpcPort) != grpcRoute)
        {
            AccessLog.SetOutcome(context, AccessLog.ListenerRejected);
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await next(context);
    }

    /// <summary>
    /// Programs must send exactly one canonical UUID Request-ID. Browsers and anonymous routes cannot, so they
    /// use the one the access log assigned. Either way the proxied request and the response carry it.
    /// </summary>
    public static async Task RequestId(HttpContext context, RequestDelegate next)
    {
        if (Route(context) is not { } route)
        {
            await next(context);
            return;
        }

        string requestId;
        if (Policies.IsProgram(route.Config))
        {
            StringValues values = context.Request.Headers[RequestIdHeader];
            if (values.Count != 1 || !Guid.TryParseExact(values[0], "D", out Guid id))
            {
                AccessLog.SetOutcome(context, AccessLog.RequestIdInvalid);
                await Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "A valid Request-ID header is required.")
                    .ExecuteAsync(context);
                return;
            }
            requestId = id.ToString("D");
        }
        else
        {
            requestId = context.Response.Headers[RequestIdHeader].ToString();
        }

        context.Request.Headers[RequestIdHeader] = requestId;
        // A backend's own Request-ID response header must not replace the gateway's.
        context.Response.OnStarting(
            static state =>
            {
                (HttpResponse response, string value) = ((HttpResponse, string))state;
                response.Headers[RequestIdHeader] = value;
                return Task.CompletedTask;
            },
            (context.Response, requestId));
        await next(context);
    }

    /// <summary>
    /// Sessions must prove intent on every mutation: <c>/auth/logout</c> and any authenticated proxy route. Runs
    /// after authorization, so <see cref="HttpContext.User"/> is whoever the endpoint's policy authenticated.
    /// </summary>
    /// <param name="cookieSessions">False when development auth replaces the cookie scheme.</param>
    public static async Task Csrf(HttpContext context, RequestDelegate next, IAntiforgery antiforgery, GatewayOptions gateway, bool cookieSessions)
    {
        if (!RequiresValidation(context, cookieSessions))
        {
            await next(context);
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            AccessLog.SetOutcome(context, AccessLog.CsrfInvalid);
            if (gateway.Home is not null && context.Request.Headers["HX-Request"] == "true")
            {
                // Never replay a failed mutation. Reloading the entry point fetches a fresh token.
                context.Response.Headers["HX-Redirect"] = gateway.Home;
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            await Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "CSRF validation failed.").ExecuteAsync(context);
            return;
        }

        await next(context);
    }

    public static bool RequiresValidation(HttpContext context, bool cookieSessions)
    {
        bool mutation = HttpMethods.IsPost(context.Request.Method) || HttpMethods.IsPut(context.Request.Method)
            || HttpMethods.IsPatch(context.Request.Method) || HttpMethods.IsDelete(context.Request.Method);
        if (!mutation || context.User.Identity?.IsAuthenticated is not true)
        {
            return false;
        }

        // Proxy routes and /auth/logout carry their policy as endpoint metadata; anonymous routes carry IAllowAnonymous.
        EndpointMetadataCollection? metadata = context.GetEndpoint()?.Metadata;
        if (metadata is null || metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            return false;
        }

        // A bearer token is not an ambient credential. The session cookie is, and a BrowserUser endpoint
        // authenticates it whatever else the request carries, so a bearer header does not exempt it there.
        bool browser = string.Equals(metadata.GetMetadata<IAuthorizeData>()?.Policy, Policies.BrowserUser, StringComparison.OrdinalIgnoreCase);
        return !GatewayAuth.HasBearer(context.Request) || (browser && cookieSessions);
    }
}
