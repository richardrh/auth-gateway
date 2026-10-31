global using System.Net;
global using System.Net.Http.Json;
global using System.Text.Json;
global using Microsoft.AspNetCore.Builder;
global using Microsoft.AspNetCore.Http;
global using Microsoft.Extensions.Configuration;
global using Microsoft.Extensions.DependencyInjection;
global using Microsoft.Extensions.Hosting;
global using Microsoft.Extensions.Logging;
global using Xunit;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthGateway.Tests;

/// <summary>An in-process backend that echoes the method, path, headers and body it received as JSON.</summary>
public static class Echo
{
    private static readonly Lazy<Task<string>> address = new(StartAsync);
    public static readonly ConcurrentBag<string> Paths = [];

    public static Task<string> Address => address.Value;

    private static async Task<string> StartAsync()
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        WebApplication app = builder.Build();
        app.Run(async context =>
        {
            Paths.Add(context.Request.Path + context.Request.QueryString);
            string body = await new StreamReader(context.Request.Body).ReadToEndAsync();
            context.Response.Headers["Request-ID"] = "backend-value";
            await context.Response.WriteAsJsonAsync(new
            {
                method = context.Request.Method,
                path = context.Request.Path + context.Request.QueryString,
                body,
                headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
            });
        });
        await app.StartAsync();
        return app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
    }
}

public sealed record Echoed(string Method, string Path, string Body, Dictionary<string, string[]> Headers)
{
    public string? Header(string name) =>
        Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value is { } v ? string.Join(",", v) : null;
}

/// <summary>Collects access records; tests find theirs by request_id.</summary>
public sealed class LogSink : TextWriter
{
    private readonly List<string> lines = [];
    private readonly SemaphoreSlim written = new(0);

    public override Encoding Encoding => Encoding.UTF8;

    public override void WriteLine(string? value)
    {
        lock (lines)
        {
            lines.Add(value!);
        }
        written.Release();
    }

    public JsonElement[] Records(string requestId)
    {
        lock (lines)
        {
            return [.. lines.Select(line => JsonDocument.Parse(line).RootElement)
                .Where(r => r.GetProperty("request_id").GetString() == requestId)];
        }
    }

    public string All()
    {
        lock (lines)
        {
            return string.Join("\n", lines);
        }
    }

    /// <summary>The record for a request; records are written after the response may already have reached the client.</summary>
    public async Task<JsonElement> RecordAsync(string requestId)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
        while (true)
        {
            if (Records(requestId) is [var record, ..])
            {
                return record;
            }
            await written.WaitAsync(timeout.Token);
        }
    }
}

public sealed class Gateway : WebApplicationFactory<Program>
{
    public const string KeyId = "test-key";
    public const string Password = "development-password";
    public const string DevToken = "development-token-0123456789abcdefghijklmnop";
    public const string Scope = "access_as_user";
    public static readonly string TenantId = Guid.NewGuid().ToString("D");
    public static readonly string ObjectId = Guid.NewGuid().ToString("D");
    public static readonly byte[] Key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
    public static readonly AuthenticationHeaderValue Basic =
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"development-user:{Password}")));
    public static readonly AuthenticationHeaderValue Bearer = new("Bearer", DevToken);

    private static readonly Lazy<Gateway> shared = new(() => new Gateway());
    private static readonly Lazy<string> tokenFile = new(() =>
    {
        string path = Path.Combine(Path.GetTempPath(), $"auth-gateway-test-{Guid.NewGuid():N}");
        File.WriteAllText(path, DevToken);
        return path;
    });

    private readonly Dictionary<string, string?> settings;
    private readonly Action<IServiceCollection>? services;
    private readonly string environment;

    public Gateway(Action<Dictionary<string, string?>>? configure = null, Action<IServiceCollection>? services = null, string environment = "Development")
    {
        string backend = Echo.Address.GetAwaiter().GetResult();
        settings = new()
        {
            ["DevelopmentAuth:Enabled"] = "true",
            ["DevelopmentAuth:Password"] = Password,
            ["DevelopmentAuth:TokenFile"] = tokenFile.Value,
            ["DevelopmentAuth:TenantId"] = TenantId,
            ["DevelopmentAuth:ObjectId"] = ObjectId,
            ["AzureAdApi:RequiredScope"] = Scope,
            ["IdentityAssertion:Issuer"] = "test-issuer",
            ["IdentityAssertion:Audience"] = "test-audience",
            ["IdentityAssertion:CurrentKeyId"] = KeyId,
            ["IdentityAssertion:LifetimeSeconds"] = "20",
            [$"IdentityAssertion:Keys:{KeyId}"] = Convert.ToBase64String(Key),
            ["Gateway:AssertionHeader"] = "Test-Assertion",
            ["Gateway:CsrfHeader"] = "Test-CSRF",
            ["Gateway:Home"] = "/app/home",
            ["Gateway:StripHeaders:0"] = "X-Internal-Secret",
            ["Gateway:AllowedRoles:0"] = "admin",
            ["Gateway:AllowedRoles:1"] = "user",
            ["Gateway:DefaultRole"] = "user",
            ["Gateway:CookieHeaders:theme"] = "Test-Theme",
            ["ServiceTokens:Search"] = "service-secret-token",
            ["ReverseProxy:Clusters:echo:Destinations:one:Address"] = backend,
        };
        Route("anon", "/anon/{**rest}", Policies.Anonymous);
        Route("browser", "/app/{**rest}", Policies.BrowserUser);
        Route("api", "/api/{**rest}", Policies.AuthenticatedProxy);
        Route("svc", "/svc/{**rest}", Policies.AuthenticatedProxy);
        settings["ReverseProxy:Routes:svc:Metadata:ServiceToken"] = "Search";
        Route("svc-missing", "/svc-missing/{**rest}", Policies.AuthenticatedProxy);
        settings["ReverseProxy:Routes:svc-missing:Metadata:ServiceToken"] = "Missing";
        configure?.Invoke(settings);
        this.services = services;
        this.environment = environment;
    }

    public static Gateway Shared => shared.Value;

    public LogSink Log { get; } = new();

    public HttpClient Client() => CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    private void Route(string id, string path, string policy)
    {
        settings[$"ReverseProxy:Routes:{id}:ClusterId"] = "echo";
        settings[$"ReverseProxy:Routes:{id}:AuthorizationPolicy"] = policy;
        settings[$"ReverseProxy:Routes:{id}:Match:Path"] = path;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(environment);
        foreach ((string key, string? value) in settings)
        {
            if (value is not null)
            {
                builder.UseSetting(key, value);
            }
        }
        builder.ConfigureTestServices(collection =>
        {
            collection.AddSingleton<TextWriter>(Log);
            services?.Invoke(collection);
        });
    }

    public static async Task<Echoed> EchoedAsync(HttpResponseMessage response)
    {
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<Echoed>(new JsonSerializerOptions(JsonSerializerDefaults.Web)))!;
    }

    public static async Task<JsonWebToken> ValidateAssertionAsync(string token, string issuer = "test-issuer")
    {
        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = "test-audience",
            IssuerSigningKey = new SymmetricSecurityKey(Key) { KeyId = KeyId },
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }
}

public static class Requests
{
    public static HttpRequestMessage Make(HttpMethod method, string path, AuthenticationHeaderValue? auth = null, string? requestId = null, HttpContent? content = null)
    {
        HttpRequestMessage request = new(method, path) { Content = content };
        request.Headers.Authorization = auth;
        if (requestId is not null)
        {
            request.Headers.TryAddWithoutValidation("Request-ID", requestId);
        }
        return request;
    }

    public static string Id() => Guid.NewGuid().ToString("D");

    public static string Rid(this HttpResponseMessage response) => response.Headers.GetValues("Request-ID").Single();
}
