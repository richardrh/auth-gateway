using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Routing;
using Yarp.ReverseProxy.Forwarder;

namespace AuthGateway;

/// <summary>
/// Writes exactly one JSON line per request to stdout: time, level, msg "http request", service, request_id,
/// trace_id, span_id, method, route, route_id, status, duration_ms, outcome, proxy_error. It is the outermost
/// middleware, so it also records requests rejected before routing or authentication. Paths, queries, headers,
/// cookies and exception messages are never logged: the route is the matched template.
/// </summary>
public sealed class AccessLog(RequestDelegate next, ILogger<AccessLog> logger, GatewayOptions gateway, TextWriter output)
{
    public const string Proxied = "proxied";
    public const string Local = "local";
    public const string ListenerRejected = "listener_rejected";
    public const string RequestIdInvalid = "request_id_invalid";
    public const string CsrfInvalid = "csrf_invalid";
    public const string AuthUnauthenticated = "auth_unauthenticated";
    public const string AuthForbidden = "auth_forbidden";
    public const string Unavailable = "unavailable";
    public const string UpstreamError = "upstream_error";
    public const string Unhandled = "unhandled_exception";

    private const string OutcomeKey = "gateway.outcome";

    private static readonly string[] Methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"];

    // Kept alive for the process lifetime: a collected listener stops sampling.
    private static ActivityListener? traceContext;

    /// <summary>Records why the gateway ended a request. The first reason wins.</summary>
    public static void SetOutcome(HttpContext context, string outcome) => context.Items.TryAdd(OutcomeKey, outcome);

    /// <summary>
    /// Gives every request a trace ID even when no one listens to ASP.NET's activity source, so the gateway
    /// logs trace_id and YARP forwards traceparent. Sampling is propagation only: nothing is recorded or exported.
    /// </summary>
    public static void EnableTraceContext()
    {
        traceContext ??= new ActivityListener
        {
            ShouldListenTo = source => source.Name == "Microsoft.AspNetCore",
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.PropagationData,
            SampleUsingParentId = static (ref ActivityCreationOptions<string> _) => ActivitySamplingResult.PropagationData,
        };
        ActivitySource.AddActivityListener(traceContext);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        long started = Stopwatch.GetTimestamp();
        // A canonical client Request-ID is kept so one ID joins every hop; otherwise a new one is assigned.
        context.Response.Headers[Pipeline.RequestIdHeader] =
            context.Request.Headers[Pipeline.RequestIdHeader] is { Count: 1 } supplied && Guid.TryParseExact(supplied[0], "D", out Guid id)
                ? id.ToString("D")
                : Guid.NewGuid().ToString("D");
        bool failed = false;
        try
        {
            await next(context);
        }
        catch (Exception)
        {
            failed = true;
            throw;
        }
        finally
        {
            Record(context, started, failed);
        }
    }

    private void Record(HttpContext context, long started, bool failed)
    {
        failed |= context.Features.Get<IExceptionHandlerFeature>() is not null;
        int status = failed && !context.Response.HasStarted ? StatusCodes.Status500InternalServerError : context.Response.StatusCode;
        string route = Route(context, out string? routeId);
        if (status < StatusCodes.Status400BadRequest && !failed && route is "/health/live" or "/health/ready")
        {
            return;
        }

        string? proxyError = null;
        if (context.Features.Get<IForwarderErrorFeature>() is { Error: not ForwarderError.None } forwarderError)
        {
            proxyError = Enum.GetName(forwarderError.Error) ?? "Unknown";
            SetOutcome(context, UpstreamError);
        }
        if (failed)
        {
            SetOutcome(context, Unhandled);
        }

        LogLevel level = failed || status >= StatusCodes.Status500InternalServerError ? LogLevel.Error
            : status >= StatusCodes.Status400BadRequest ? LogLevel.Warning : LogLevel.Information;
        if (!logger.IsEnabled(level))
        {
            return;
        }

        string outcome = context.Items.TryGetValue(OutcomeKey, out object? set) && set is string reason ? reason
            : status switch
            {
                StatusCodes.Status401Unauthorized => AuthUnauthenticated,
                StatusCodes.Status403Forbidden => AuthForbidden,
                _ => routeId is null ? Local : Proxied,
            };
        output.WriteLine(Format(
            gateway.ServiceName, DateTimeOffset.UtcNow, level, context.Response.Headers[Pipeline.RequestIdHeader].ToString(),
            Activity.Current, context.Request.Method, route, routeId, status,
            (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds, outcome, proxyError));
    }

    internal static string Format(
        string service, DateTimeOffset time, LogLevel level, string requestId, Activity? activity, string method,
        string route, string? routeId, int status, long durationMs, string outcome, string? proxyError)
    {
        using MemoryStream buffer = new();
        using (Utf8JsonWriter json = new(buffer))
        {
            json.WriteStartObject();
            json.WriteString("time", time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture));
            json.WriteString("level", level switch { LogLevel.Error => "ERROR", LogLevel.Warning => "WARN", _ => "INFO" });
            json.WriteString("msg", "http request");
            json.WriteString("service", service);
            json.WriteString("request_id", requestId);
            if (activity is not null && activity.TraceId != default)
            {
                json.WriteString("trace_id", activity.TraceId.ToHexString());
                json.WriteString("span_id", activity.SpanId.ToHexString());
            }
            json.WriteString("method", Array.Find(Methods, known => known.Equals(method, StringComparison.OrdinalIgnoreCase)) ?? "OTHER");
            json.WriteString("route", route);
            if (routeId is not null)
            {
                json.WriteString("route_id", routeId);
            }
            json.WriteNumber("status", status);
            json.WriteNumber("duration_ms", durationMs);
            json.WriteString("outcome", outcome);
            if (proxyError is not null)
            {
                json.WriteString("proxy_error", proxyError);
            }
            json.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    // The matched route template, never the raw path.
    private static string Route(HttpContext context, out string? routeId)
    {
        routeId = null;
        Endpoint? endpoint = context.GetEndpoint();
        if (Pipeline.Route(context) is { } proxyRoute)
        {
            routeId = proxyRoute.Config.RouteId;
            if (proxyRoute.Config.Match?.Path is { Length: > 0 } path)
            {
                return path;
            }
        }
        return endpoint is RouteEndpoint { RoutePattern.RawText: { Length: > 0 } pattern }
            ? pattern.StartsWith('/') ? pattern : "/" + pattern
            : "/unmatched";
    }
}
