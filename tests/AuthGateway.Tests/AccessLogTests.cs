using System.Diagnostics;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using static AuthGateway.Tests.Requests;

namespace AuthGateway.Tests;

public sealed class AccessLogTests
{
    private static readonly Gateway gateway = Gateway.Shared;
    private readonly HttpClient client = gateway.Client();

    [Fact]
    public void FormatWritesTheContractFieldsInOrder()
    {
        using Activity activity = new Activity("test").Start();
        JsonElement full = JsonDocument.Parse(AccessLog.Format("svc", new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), LogLevel.Warning,
            "rid", activity, "patch", "/api/{**rest}", "api", 502, 7, "upstream_error", "Request")).RootElement;

        Assert.Equal(
            ["time", "level", "msg", "service", "request_id", "trace_id", "span_id", "method", "route", "route_id", "status", "duration_ms", "outcome", "proxy_error"],
            full.EnumerateObject().Select(p => p.Name));
        Assert.Equal("2026-01-02T03:04:05Z", full.GetProperty("time").GetString());
        Assert.Equal("WARN", full.GetProperty("level").GetString());
        Assert.Equal("http request", full.GetProperty("msg").GetString());
        Assert.Equal("PATCH", full.GetProperty("method").GetString());
        Assert.Equal(activity.TraceId.ToHexString(), full.GetProperty("trace_id").GetString());
        Assert.Equal(502, full.GetProperty("status").GetInt32());

        JsonElement minimal = JsonDocument.Parse(AccessLog.Format("svc", DateTimeOffset.UtcNow, LogLevel.Information,
            "rid", null, "BREW", "/unmatched", null, 404, 0, "local", null)).RootElement;
        Assert.Equal(["time", "level", "msg", "service", "request_id", "method", "route", "status", "duration_ms", "outcome"],
            minimal.EnumerateObject().Select(p => p.Name));
        Assert.Equal("OTHER", minimal.GetProperty("method").GetString());
        Assert.Equal("INFO", minimal.GetProperty("level").GetString());
        Assert.Equal("ERROR", JsonDocument.Parse(AccessLog.Format("s", DateTimeOffset.UtcNow, LogLevel.Error, "r", null, "GET", "/", null, 500, 0, "x", null))
            .RootElement.GetProperty("level").GetString());
    }

    [Fact]
    public async Task OneRecordPerRequestWithTheTemplateAndNoSecrets()
    {
        string id = Id();
        HttpRequestMessage request = Make(HttpMethod.Get, "/api/PATHSECRET?token=QUERYSECRET", new("Bearer", "BEARERSECRET-without-dots-0123456789"), id);
        request.Headers.Add("Cookie", "session=COOKIESECRET");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(request)).StatusCode);
        JsonElement record = await gateway.Log.RecordAsync(id);

        string marker = Id();
        await client.SendAsync(Make(HttpMethod.Get, "/auth/me", requestId: marker));
        await gateway.Log.RecordAsync(marker);

        Assert.Single(gateway.Log.Records(id));
        Assert.Equal("/api/{**rest}", record.GetProperty("route").GetString());
        Assert.Equal("api", record.GetProperty("route_id").GetString());
        Assert.Equal("WARN", record.GetProperty("level").GetString());
        Assert.Equal(32, record.GetProperty("trace_id").GetString()!.Length);
        string all = gateway.Log.All();
        foreach (string secret in new[] { "PATHSECRET", "QUERYSECRET", "BEARERSECRET", "COOKIESECRET" })
        {
            Assert.DoesNotContain(secret, all);
        }
    }

    [Fact]
    public async Task SuccessfulProxyAndLocalRequestsAreRecorded()
    {
        string id = Id();
        await client.SendAsync(Make(HttpMethod.Get, "/api/ok", Gateway.Basic, id));
        JsonElement proxied = await gateway.Log.RecordAsync(id);
        Assert.Equal(("proxied", 200, "INFO"), (proxied.GetProperty("outcome").GetString(), proxied.GetProperty("status").GetInt32(), proxied.GetProperty("level").GetString()));

        string local = Id();
        await client.SendAsync(Make(HttpMethod.Get, "/auth/me", Gateway.Basic, local));
        JsonElement me = await gateway.Log.RecordAsync(local);
        Assert.Equal("local", me.GetProperty("outcome").GetString());
        Assert.Equal("/auth/me", me.GetProperty("route").GetString());
        Assert.False(me.TryGetProperty("route_id", out _));
    }

    [Fact]
    public async Task HealthSuccessIsSkippedButFailureIsLogged()
    {
        string id = Id();
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Make(HttpMethod.Get, "/health/live", requestId: id))).StatusCode);
        string marker = Id();
        await client.SendAsync(Make(HttpMethod.Get, "/auth/me", requestId: marker));
        await gateway.Log.RecordAsync(marker);
        Assert.Empty(gateway.Log.Records(id));

        using Gateway failing = new(services: s => s.AddHealthChecks().AddCheck("down", () => HealthCheckResult.Unhealthy()));
        string down = Id();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await failing.Client().SendAsync(Make(HttpMethod.Get, "/health/ready", requestId: down))).StatusCode);
        JsonElement record = await failing.Log.RecordAsync(down);
        Assert.Equal("/health/ready", record.GetProperty("route").GetString());
        Assert.Equal("ERROR", record.GetProperty("level").GetString());
    }

    [Fact]
    public async Task UnhandledExceptionIsRecordedAsAnError()
    {
        using Gateway broken = new(services: s => s.AddSingleton<IAntiforgery, ThrowingAntiforgery>());
        string id = Id();

        await Record.ExceptionAsync(() => broken.Client().SendAsync(Make(HttpMethod.Get, "/auth/csrf", Gateway.Basic, id)));

        JsonElement record = await broken.Log.RecordAsync(id);
        Assert.Equal(("unhandled_exception", 500, "ERROR"), (record.GetProperty("outcome").GetString(), record.GetProperty("status").GetInt32(), record.GetProperty("level").GetString()));
        Assert.DoesNotContain("BOOM", broken.Log.All());
    }

    private sealed class ThrowingAntiforgery : IAntiforgery
    {
        public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext) => throw new InvalidOperationException("BOOM");
        public AntiforgeryTokenSet GetTokens(HttpContext httpContext) => throw new InvalidOperationException("BOOM");
        public Task<bool> IsRequestValidAsync(HttpContext httpContext) => throw new InvalidOperationException("BOOM");
        public void SetCookieTokenAndHeader(HttpContext httpContext) => throw new InvalidOperationException("BOOM");
        public Task ValidateRequestAsync(HttpContext httpContext) => throw new InvalidOperationException("BOOM");
    }
}
