using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace AuthGateway.E2E;

/// <summary>What a gateway instance is configured with; everything else is the same Production setup.</summary>
public sealed record GatewaySettings(
    FakeEntra Entra,
    EchoBackend Backend,
    string KeysPath,
    string? KeyCertificateFile,
    string? KeyCertificatePassword)
{
    public const string AssertionIssuer = "e2e-gateway";
    public const string AssertionAudience = "e2e-backend";
    public const string AssertionKeyId = "primary";

    /// <summary>The 32-byte HS256 key the gateway signs the identity assertion with, base64.</summary>
    public static readonly string AssertionKey = Convert.ToBase64String("0123456789abcdef0123456789abcdef"u8.ToArray());
}

/// <summary>
/// The gateway as a real process in the Production environment: real Kestrel, real configuration binding, real
/// OpenID Connect over HTTPS against <see cref="FakeEntra"/>. Only the routes come from <c>examples/quickstart.json</c>.
/// </summary>
public sealed class GatewayProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly ConcurrentQueue<string> output = new();

    private GatewayProcess(GatewaySettings settings, int port)
    {
        Url = $"http://127.0.0.1:{port}";
        process = new() { StartInfo = StartInfo(settings, port) };
        process.OutputDataReceived += (_, line) => Capture(line.Data);
        process.ErrorDataReceived += (_, line) => Capture(line.Data);
        _ = process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
    }

    public string Url { get; }

    /// <summary>Everything the process wrote so far: the access log and the console log.</summary>
    public string Output => string.Join('\n', output);

    /// <summary>Starts the gateway and waits until it answers its health check.</summary>
    public static async Task<GatewayProcess> StartAsync(GatewaySettings settings)
    {
        GatewayProcess gateway = new(settings, FreePort());
        using HttpClient probe = new();
        DateTime giveUp = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < giveUp)
        {
            if (gateway.process.HasExited)
            {
                break;
            }
            try
            {
                if ((await probe.GetAsync($"{gateway.Url}/health/live")).IsSuccessStatusCode)
                {
                    return gateway;
                }
            }
            catch (HttpRequestException)
            {
                // Not listening yet.
            }
            await Task.Delay(100);
        }

        string log = gateway.Output;
        await gateway.DisposeAsync();
        throw new InvalidOperationException($"The gateway did not become healthy. Its output:\n{log}");
    }

    /// <summary>Starts a gateway that is expected to refuse its configuration, and returns how it exited.</summary>
    public static async Task<(int ExitCode, string Output)> StartExpectingFailureAsync(GatewaySettings settings)
    {
        await using GatewayProcess gateway = new(settings, FreePort());
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));
        await gateway.process.WaitForExitAsync(timeout.Token);
        // The last lines can still be in flight after the process has exited.
        await Task.Delay(200, CancellationToken.None);
        return (gateway.process.ExitCode, gateway.Output);
    }

    public async Task StopAsync()
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        await process.WaitForExitAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        process.Dispose();
    }

    private static ProcessStartInfo StartInfo(GatewaySettings settings, int port)
    {
        ProcessStartInfo info = new("dotnet")
        {
            WorkingDirectory = AppContext.BaseDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "AuthGateway.dll"));

        // Nothing from the developer's shell may change the gateway's configuration.
        foreach (string name in info.Environment.Keys.Where(key => key.Contains("__", StringComparison.Ordinal)).ToArray())
        {
            _ = info.Environment.Remove(name);
        }
        _ = info.Environment.Remove("ASPNETCORE_URLS");
        _ = info.Environment.Remove("DOTNET_URLS");

        string idp = $"{settings.Entra.BaseUrl}/";
        Dictionary<string, string?> environment = new()
        {
            ["DOTNET_ENVIRONMENT"] = "Production",
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["GATEWAY_CONFIG_FILE"] = Path.Combine(RepositoryRoot(), "examples", "quickstart.json"),
            ["SSL_CERT_FILE"] = settings.Entra.CertificateFile,
            ["Kestrel__Endpoints__Http__Url"] = $"http://127.0.0.1:{port}",
            ["AzureAdWeb__Instance"] = idp,
            ["AzureAdWeb__TenantId"] = FakeEntra.TenantId,
            ["AzureAdWeb__ClientId"] = FakeEntra.WebClientId,
            ["AzureAdWeb__ClientSecret"] = FakeEntra.WebClientSecret,
            ["AzureAdApi__Instance"] = idp,
            ["AzureAdApi__TenantId"] = FakeEntra.TenantId,
            ["AzureAdApi__ClientId"] = FakeEntra.WebClientId,
            ["AzureAdApi__Audience"] = FakeEntra.ApiAudience,
            ["AzureAdApi__RequiredScope"] = FakeEntra.RequiredScope,
            ["IdentityAssertion__Issuer"] = GatewaySettings.AssertionIssuer,
            ["IdentityAssertion__Audience"] = GatewaySettings.AssertionAudience,
            ["IdentityAssertion__CurrentKeyId"] = GatewaySettings.AssertionKeyId,
            ["IdentityAssertion__Keys__" + GatewaySettings.AssertionKeyId] = GatewaySettings.AssertionKey,
            ["ReverseProxy__Clusters__backend__Destinations__main__Address"] = $"{settings.Backend.Url}/",
            // The test browser reaches the gateway over plain HTTP while pretending to be behind a TLS proxy.
            ["ForwardedHeaders__Enabled"] = "true",
            ["ForwardedHeaders__KnownNetworks__0"] = "127.0.0.0/8",
            ["DataProtection__KeysPath"] = settings.KeysPath,
            ["DataProtection__CertificateFile"] = settings.KeyCertificateFile,
            ["DataProtection__CertificatePassword"] = settings.KeyCertificatePassword,
            // Why a token or cookie was rejected; the default level hides it, and a failing test shows this output.
            ["Logging__LogLevel__Microsoft.AspNetCore.Authentication"] = "Information",
        };
        foreach ((string name, string? value) in environment.Where(pair => pair.Value is not null))
        {
            info.Environment[name] = value;
        }

        return info;
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "AuthGateway.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException("AuthGateway.slnx was not found above the test output.");
    }

    private static int FreePort()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private void Capture(string? line)
    {
        if (line is not null)
        {
            output.Enqueue(line);
        }
    }
}
