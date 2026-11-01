using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthGateway.E2E;

/// <summary>A request as the backend behind the gateway received it.</summary>
public sealed record Received(string Method, string Path, IReadOnlyDictionary<string, string> Headers);

/// <summary>A plain-HTTP backend that answers 200 to everything and remembers what the gateway forwarded.</summary>
public sealed class EchoBackend : IAsyncDisposable
{
    private readonly ConcurrentQueue<Received> received = new();
    private WebApplication? app;

    public string Url { get; private set; } = string.Empty;

    public async Task StartAsync()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        _ = builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0));
        app = builder.Build();
        app.Run(async context =>
        {
            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues> header in context.Request.Headers)
            {
                headers[header.Key] = header.Value.ToString();
            }
            received.Enqueue(new(context.Request.Method, context.Request.Path.Value ?? string.Empty, headers));
            await context.Response.WriteAsync("backend reached");
        });
        await app.StartAsync();
        Url = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().TrimEnd('/');
    }

    /// <summary>The one request that arrived for <paramref name="path"/>; tests use a path of their own.</summary>
    public Received Request(string path) => received.Single(request => request.Path == path);

    public bool Saw(string path) => received.Any(request => request.Path == path);

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
        {
            await app.DisposeAsync();
        }
    }
}
