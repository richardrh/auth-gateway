using static AuthGateway.Tests.Requests;

namespace AuthGateway.Tests;

[CollectionDefinition(nameof(ProcessEnvironment), DisableParallelization = true)]
public sealed class ProcessEnvironment;

public sealed class StartupTests
{
    private static string Failure(Gateway gateway)
    {
        using (gateway)
        {
            Exception exception = Assert.ThrowsAny<Exception>(() => gateway.Client());
            return exception.ToString();
        }
    }

    [Fact]
    public void OutsideDevelopmentEveryMissingEntraSettingIsNamed()
    {
        string message = Failure(new Gateway(s => s["DevelopmentAuth:Enabled"] = null, environment: "Production"));

        foreach (string key in GatewayAuth.RequiredEntraSettings.Where(k => k != "AzureAdApi:RequiredScope"))
        {
            Assert.Contains(key, message);
        }
    }

    [Fact]
    public void OutsideDevelopmentKeysPathMustBeAbsolute()
    {
        string message = Failure(new Gateway(s =>
        {
            s["DevelopmentAuth:Enabled"] = null;
            foreach (string key in GatewayAuth.RequiredEntraSettings)
            {
                s[key] = key.EndsWith("TenantId", StringComparison.Ordinal) ? Guid.NewGuid().ToString() : "value";
            }
            s["DataProtection:KeysPath"] = "relative/keys";
        }, environment: "Production"));

        Assert.Contains("DataProtection:KeysPath", message);
    }

    [Fact]
    public void OutsideDevelopmentTheKeyCertificateIsRequired()
    {
        string keys = Directory.CreateTempSubdirectory("startup-keys-").FullName;
        try
        {
            string message = Failure(new Gateway(s =>
            {
                s["DevelopmentAuth:Enabled"] = null;
                foreach (string key in GatewayAuth.RequiredEntraSettings)
                {
                    s[key] = key.EndsWith("TenantId", StringComparison.Ordinal) ? Guid.NewGuid().ToString() : "value";
                }
                s["DataProtection:KeysPath"] = keys;
            }, environment: "Production"));

            Assert.Contains("Invalid configuration: DataProtection:CertificateFile.", message);
        }
        finally
        {
            Directory.Delete(keys, recursive: true);
        }
    }

    [Fact]
    public void DevelopmentAuthIsRefusedOutsideDevelopment()
    {
        Assert.Contains("DevelopmentAuth", Failure(new Gateway(environment: "Production")));
    }

    [Fact]
    public async Task ConfiguredDocumentIsServedAnonymouslyWithoutCaching()
    {
        const string json = """{"schemaVersion":1,"clientIds":{"tui":"a"}}""";
        using Gateway gateway = new(s =>
        {
            s["Gateway:Documents:0:Path"] = "/.well-known/test";
            s["Gateway:Documents:0:Json"] = json;
        });

        HttpResponseMessage response = await gateway.Client().GetAsync("/.well-known/test");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
        Assert.Equal(json, await response.Content.ReadAsStringAsync());
    }

    // A profile can name the path while an environment variable supplies (or withholds) the content.
    [Fact]
    public async Task DocumentWithoutJsonIsNotServed()
    {
        using Gateway gateway = new(s =>
        {
            s["Gateway:Documents:0:Path"] = "/.well-known/test";
            s["Gateway:Documents:0:Json"] = "";
        });

        Assert.Equal(HttpStatusCode.NotFound,
            (await gateway.Client().SendAsync(Make(HttpMethod.Get, "/.well-known/test", Gateway.Basic))).StatusCode);
    }

    [Theory]
    [InlineData("no-leading-slash", "{}")]
    [InlineData("//host/path", "{}")]
    [InlineData("/.well-known/test", "{not json")]
    public void InvalidDocumentFailsStartupNamingThePathNotTheContent(string path, string json)
    {
        string message = Failure(new Gateway(s =>
        {
            s["Gateway:Documents:0:Path"] = path;
            s["Gateway:Documents:0:Json"] = json;
        }));

        Assert.Contains("Gateway:Documents", message);
        Assert.DoesNotContain("not json", message);
    }

    internal static IConfiguration Config(IEnumerable<KeyValuePair<string, string?>> settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
}

[Collection(nameof(ProcessEnvironment))]
public sealed class ProfileTests
{
    [Fact]
    public async Task ProfileOverridesAppSettingsAndEnvironmentOverridesProfile()
    {
        string profile = Path.Combine(Path.GetTempPath(), $"auth-gateway-profile-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(profile, """{ "IdentityAssertion": { "Issuer": "profile-issuer" } }""");
        try
        {
            Assert.Equal("profile-issuer", await IssuerAsync(profile));
            Environment.SetEnvironmentVariable("IdentityAssertion__Issuer", "environment-issuer");
            Assert.Equal("environment-issuer", await IssuerAsync(profile));
        }
        finally
        {
            Environment.SetEnvironmentVariable("IdentityAssertion__Issuer", null);
            File.Delete(profile);
        }
    }

    private static async Task<string> IssuerAsync(string profile)
    {
        using Gateway gateway = new(s =>
        {
            s["IdentityAssertion:Issuer"] = null;
            s["GATEWAY_CONFIG_FILE"] = profile;
        });
        Echoed echoed = await Gateway.EchoedAsync(await gateway.Client().SendAsync(Make(HttpMethod.Get, "/api/x", Gateway.Basic, Id())));
        return new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(echoed.Header("Test-Assertion")).Issuer;
    }
}
