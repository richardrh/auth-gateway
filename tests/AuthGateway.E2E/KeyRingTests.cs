using System.Net;
using Xunit;

namespace AuthGateway.E2E;

[Collection(RigGroup.Name)]
public sealed class KeyRingTests(Rig rig)
{
    [Fact]
    public async Task ASessionSurvivesARestartOnTheSameKeyRingAndTheKeysAreEncryptedOnDisk()
    {
        (string KeysPath, string Certificate) ring = rig.NewKeyRing();
        GatewayProcess first = await GatewayProcess.StartAsync(rig.Settings(ring));
        using Browser browser = new(first.Url, rig.Entra.Thumbprint);
        using (HttpResponseMessage landed = await browser.SignInAsync("/app/before-restart"))
        {
            Assert.Equal(HttpStatusCode.OK, landed.StatusCode);
        }
        await first.DisposeAsync();

        await using GatewayProcess second = await GatewayProcess.StartAsync(rig.Settings(ring));
        browser.Gateway = new(second.Url);
        using HttpResponseMessage me = await browser.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        string[] keys = [.. Directory.GetFiles(ring.KeysPath, "*.xml").Select(File.ReadAllText)];
        Assert.NotEmpty(keys);
        Assert.All(keys, xml =>
        {
            Assert.Contains("EncryptedData", xml, StringComparison.Ordinal);
            Assert.DoesNotContain("<value>", xml, StringComparison.Ordinal);
        });
        Assert.DoesNotContain("key-ring-password", first.Output + second.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASessionIsRejectedByAGatewayWithADifferentKeyRing()
    {
        GatewayProcess first = await GatewayProcess.StartAsync(rig.Settings(rig.NewKeyRing()));
        using Browser browser = new(first.Url, rig.Entra.Thumbprint);
        using (HttpResponseMessage landed = await browser.SignInAsync("/app/other-ring"))
        {
            Assert.Equal(HttpStatusCode.OK, landed.StatusCode);
        }
        await first.DisposeAsync();

        await using GatewayProcess stranger = await GatewayProcess.StartAsync(rig.Settings(rig.NewKeyRing()));
        browser.Gateway = new(stranger.Url);
        using HttpResponseMessage me = await browser.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task TheGatewayRefusesToStartWithoutTheKeyCertificate()
    {
        (string KeysPath, string Certificate) ring = rig.NewKeyRing();

        (int exitCode, string output) = await GatewayProcess.StartExpectingFailureAsync(rig.Settings(ring) with { KeyCertificateFile = null });

        Assert.NotEqual(0, exitCode);
        Assert.Contains("Invalid configuration: DataProtection:CertificateFile.", output, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(ring.KeysPath));
    }

    [Fact]
    public async Task AWrongKeyCertificatePasswordStopsStartupWithoutPrintingIt()
    {
        (string KeysPath, string Certificate) ring = rig.NewKeyRing();

        (int exitCode, string output) = await GatewayProcess.StartExpectingFailureAsync(rig.Settings(ring) with { KeyCertificatePassword = "wrong-password-value" });

        Assert.NotEqual(0, exitCode);
        Assert.Contains("DataProtection:CertificateFile", output, StringComparison.Ordinal);
        Assert.DoesNotContain("wrong-password-value", output, StringComparison.Ordinal);
        Assert.DoesNotContain(Rig.KeyCertificatePassword, output, StringComparison.Ordinal);
    }
}
