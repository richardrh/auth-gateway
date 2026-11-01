using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGateway.Tests;

public sealed class KeyRingTests : IDisposable
{
    private const string Password = "test-password";
    private readonly string directory = Directory.CreateTempSubdirectory("key-ring-").FullName;

    public void Dispose() => Directory.Delete(directory, recursive: true);

    private string Keys => Path.Combine(directory, "keys");

    private string Certificate(string name, bool withPrivateKey = true)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        string path = Path.Combine(directory, $"{name}.pfx");
        File.WriteAllBytes(path, withPrivateKey ? certificate.Export(X509ContentType.Pfx, Password) : certificate.Export(X509ContentType.Cert));
        return path;
    }

    private static (IDataProtectionProvider Provider, bool Encrypted) Open(Dictionary<string, string?> settings)
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        ServiceCollection services = new();
        IDataProtectionBuilder builder = services.AddDataProtection().SetApplicationName("key-ring-tests");
        bool encrypted = KeyRing.Configure(builder, configuration);
        return (services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>(), encrypted);
    }

    private Dictionary<string, string?> Settings(string? certificate, params string[] previous)
    {
        Dictionary<string, string?> settings = new() { ["DataProtection:KeysPath"] = Keys, ["DataProtection:CertificatePassword"] = Password };
        if (certificate is not null)
        {
            settings["DataProtection:CertificateFile"] = certificate;
        }
        for (int index = 0; index < previous.Length; index++)
        {
            settings[$"DataProtection:PreviousCertificateFiles:{index}"] = previous[index];
        }
        return settings;
    }

    private string[] KeyFiles() => [.. Directory.GetFiles(Keys, "*.xml").Select(File.ReadAllText)];

    [Fact]
    public void KeysAreEncryptedAtRestAndStillReadableByTheNextProcess()
    {
        string certificate = Certificate("current");
        (IDataProtectionProvider first, bool encrypted) = Open(Settings(certificate));
        string protectedValue = first.CreateProtector("cookie").Protect("session");

        Assert.True(encrypted);
        string[] files = KeyFiles();
        Assert.NotEmpty(files);
        // Plain keys hold their material in a <value> element; encrypted ones replace it with EncryptedData.
        Assert.All(files, xml =>
        {
            Assert.Contains("EncryptedData", xml);
            Assert.DoesNotContain("<value>", xml);
        });
        Assert.Equal("session", Open(Settings(certificate)).Provider.CreateProtector("cookie").Unprotect(protectedValue));
    }

    [Fact]
    public void AnotherCertificateCannotReadTheKeys()
    {
        string protectedValue = Open(Settings(Certificate("owner"))).Provider.CreateProtector("cookie").Protect("session");

        IDataProtector stranger = Open(Settings(Certificate("stranger"))).Provider.CreateProtector("cookie");

        _ = Assert.ThrowsAny<CryptographicException>(() => stranger.Unprotect(protectedValue));
    }

    // After a rotation the old certificate is listed as previous so sessions signed under it keep working.
    [Fact]
    public void PreviousCertificatesStillReadEarlierKeys()
    {
        string old = Certificate("old");
        string protectedValue = Open(Settings(old)).Provider.CreateProtector("cookie").Protect("session");

        IDataProtector rotated = Open(Settings(Certificate("new"), old)).Provider.CreateProtector("cookie");

        Assert.Equal("session", rotated.Unprotect(protectedValue));
    }

    [Theory]
    [InlineData("unset")]
    [InlineData("missing")]
    [InlineData("relative")]
    [InlineData("no-private-key")]
    [InlineData("wrong-password")]
    public void UnusableCertificatesFailStartupNamingTheSettingButNotTheSecret(string problem)
    {
        Dictionary<string, string?> settings = Settings(problem switch
        {
            "unset" => null,
            "missing" => Path.Combine(directory, "absent.pfx"),
            "relative" => "keys.pfx",
            "no-private-key" => Certificate("public-only", withPrivateKey: false),
            _ => Certificate("locked"),
        });
        if (problem == "wrong-password")
        {
            settings["DataProtection:CertificatePassword"] = "not-the-password";
        }

        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => Open(settings));

        Assert.Equal("Invalid configuration: DataProtection:CertificateFile.", error.Message);
        Assert.False(Directory.Exists(Keys), "no key directory is created for a gateway that cannot encrypt its keys");
    }

    [Fact]
    public void AnUnusablePreviousCertificateIsNamed()
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(
            () => Open(Settings(Certificate("current"), Path.Combine(directory, "absent.pfx"))));

        Assert.Equal("Invalid configuration: DataProtection:PreviousCertificateFiles:0.", error.Message);
    }

    // Turning encryption on leaves the old plaintext key on disk, and it stays in use, so the ring is not yet
    // encrypted at rest even though new keys would be.
    [Fact]
    public void PlaintextKeysLeftFromBeforeEncryptionAreReportedAndStillWork()
    {
        ServiceCollection plain = new();
        _ = plain.AddDataProtection().SetApplicationName("key-ring-tests").PersistKeysToFileSystem(Directory.CreateDirectory(Keys));
        string protectedValue = plain.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>().CreateProtector("cookie").Protect("session");

        (IDataProtectionProvider upgraded, bool encrypted) = Open(Settings(Certificate("owner")));

        Assert.False(encrypted);
        Assert.Equal("session", upgraded.CreateProtector("cookie").Unprotect(protectedValue));
    }
}
