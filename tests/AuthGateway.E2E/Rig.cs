using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthGateway.E2E;

[CollectionDefinition(Name)]
public sealed class RigGroup : ICollectionFixture<Rig>
{
    public const string Name = "rig";
}

/// <summary>The fake Entra, a backend, and one gateway process wired together; shared by every test in the collection.</summary>
public sealed class Rig : IAsyncLifetime
{
    public const string KeyCertificatePassword = "key-ring-password";

    private readonly string directory = Directory.CreateTempSubdirectory("gateway-e2e-").FullName;
    private GatewayProcess? gateway;

    public Rig() => Entra = new(directory);

    public FakeEntra Entra { get; }

    public EchoBackend Backend { get; } = new();

    public GatewayProcess Gateway => gateway ?? throw new InvalidOperationException("The rig has not started.");

    public async Task InitializeAsync()
    {
        await Entra.StartAsync();
        await Backend.StartAsync();
        gateway = await GatewayProcess.StartAsync(Settings(NewKeyRing()));
    }

    public async Task DisposeAsync()
    {
        if (gateway is not null)
        {
            await gateway.DisposeAsync();
        }
        await Backend.DisposeAsync();
        await Entra.DisposeAsync();
        Directory.Delete(directory, recursive: true);
    }

    /// <summary>A new key-ring directory and the certificate that encrypts it.</summary>
    public (string KeysPath, string Certificate) NewKeyRing()
    {
        string folder = Directory.CreateDirectory(Path.Combine(directory, Guid.NewGuid().ToString("N"))).FullName;
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=auth-gateway-keys", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        string file = Path.Combine(folder, "keys.pfx");
        File.WriteAllBytes(file, certificate.Export(X509ContentType.Pfx, KeyCertificatePassword));
        return (Directory.CreateDirectory(Path.Combine(folder, "keys")).FullName, file);
    }

    public GatewaySettings Settings((string KeysPath, string Certificate) ring) =>
        new(Entra, Backend, ring.KeysPath, ring.Certificate, KeyCertificatePassword);

    public Browser NewBrowser() => new(Gateway.Url, Entra.Thumbprint);

    /// <summary>Asserts the status, and on a mismatch fails with the gateway's own log so the cause is in the report.</summary>
    public void Expect(HttpStatusCode expected, HttpResponseMessage response) =>
        Assert.True(response.StatusCode == expected, $"Expected {expected} but got {response.StatusCode}. Gateway output:\n{Gateway.Output}");

    /// <summary>Checks the identity assertion a backend received: signed by the gateway and still fresh.</summary>
    public static async Task<JsonWebToken> ValidateAssertionAsync(string assertion)
    {
        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(assertion, new()
        {
            ValidIssuer = GatewaySettings.AssertionIssuer,
            ValidAudience = GatewaySettings.AssertionAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(GatewaySettings.AssertionKey)) { KeyId = GatewaySettings.AssertionKeyId },
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }
}
