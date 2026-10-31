using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using static AuthGateway.Tests.Requests;

namespace AuthGateway.Tests;

public sealed class ProxyTests
{
    private static readonly Gateway gateway = Gateway.Shared;
    private readonly HttpClient client = gateway.Client();

    [Fact]
    public async Task AuthenticatedRequestCarriesAVerifiableAssertion()
    {
        string id = Id();
        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(Make(HttpMethod.Get, "/api/items?x=1", Gateway.Basic, id)));

        Assert.Equal("/api/items?x=1", echoed.Path);
        Assert.Null(echoed.Header("Authorization"));
        JsonWebToken token = await Gateway.ValidateAssertionAsync(echoed.Header("Test-Assertion")!);
        Assert.Equal("HS256", token.Alg);
        Assert.Equal("JWT", token.Typ);
        Assert.Equal(Gateway.KeyId, token.Kid);
        Assert.Equal(["test-audience"], token.Audiences);
        Assert.Equal(20, token.GetPayloadValue<long>("exp") - token.GetPayloadValue<long>("iat"));
        Assert.False(token.TryGetPayloadValue("nbf", out object _));
        Assert.True(Guid.TryParseExact(token.Id, "D", out _));
        Assert.Equal(Gateway.TenantId, token.GetClaim("tid").Value);
        Assert.Equal(Gateway.ObjectId, token.GetClaim("oid").Value);
        Assert.Equal(id, token.GetClaim("request_id").Value);
        Assert.Equal(["user"], token.Claims.Where(c => c.Type == "roles").Select(c => c.Value));
        Assert.False(token.TryGetPayloadValue("sid", out object _));
    }

    [Fact]
    public async Task CallerSuppliedCredentialsAndReservedHeadersNeverReachTheBackend()
    {
        HttpRequestMessage request = Make(HttpMethod.Get, "/api/spoof", Gateway.Basic, Id());
        Spoof(request);

        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(request));

        AssertStripped(echoed);
        await Gateway.ValidateAssertionAsync(echoed.Header("Test-Assertion")!);
    }

    public static TheoryData<string, string> Mutations => new()
    {
        { "POST", "/api/body" }, { "PUT", "/api/body" }, { "POST", "/app/body" }, { "PUT", "/app/body" },
    };

    [Theory]
    [MemberData(nameof(Mutations))]
    public async Task RequestBodiesAreProxiedWithCredentialsStripped(string method, string path)
    {
        (string cookie, string token) = await CsrfAsync(client);
        HttpRequestMessage request = Make(new HttpMethod(method), path, Gateway.Basic, Id(),
            new StringContent("{\"name\":\"value\"}", Encoding.UTF8, "application/json"));
        Spoof(request);
        request.Headers.Remove("Cookie");
        request.Headers.Remove("CSRF-Token");
        request.Headers.Add("Cookie", $"{cookie}; session=stolen");
        request.Headers.Add("CSRF-Token", token);

        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(request));

        Assert.Equal(method, echoed.Method);
        Assert.Equal("{\"name\":\"value\"}", echoed.Body);
        Assert.StartsWith("application/json", echoed.Header("Content-Type"));
        AssertStripped(echoed);
        await Gateway.ValidateAssertionAsync(echoed.Header("Test-Assertion")!);
    }

    [Fact]
    public async Task AnonymousRouteStripsCredentialsAndAddsNoAssertion()
    {
        HttpRequestMessage request = Make(HttpMethod.Get, "/anon/page", Gateway.Basic);
        Spoof(request);

        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(request));

        Assert.Null(echoed.Header("Authorization"));
        Assert.Null(echoed.Header("Cookie"));
        Assert.Null(echoed.Header("Test-Assertion"));
    }

    [Fact]
    public async Task UnauthenticatedProgramGetsABare401AndTheBackendIsNotCalled()
    {
        string id = Id();
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, $"/api/{id}", requestId: id));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("auth_unauthenticated", (await gateway.Log.RecordAsync(id)).GetProperty("outcome").GetString());
        Assert.DoesNotContain(Echo.Paths, path => path.Contains(id));
    }

    [Fact]
    public async Task WrongDevelopmentCredentialsAreRejected()
    {
        HttpRequestMessage twice = Make(HttpMethod.Get, "/auth/me");
        twice.Headers.TryAddWithoutValidation("Authorization", [Gateway.Basic.ToString(), Gateway.Basic.ToString()]);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Make(HttpMethod.Get, "/auth/me", new("Basic", "ZGV2ZWxvcG1lbnQtdXNlcjp3cm9uZw==")))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Make(HttpMethod.Get, "/auth/me", new("Bearer", "wrong-token-without-any-dots-0123456789")))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(twice)).StatusCode);
    }

    [Fact]
    public async Task DevelopmentBasicAndBearerSignInTheConfiguredIdentity()
    {
        foreach (var auth in new[] { Gateway.Basic, Gateway.Bearer })
        {
            JsonElement me = await (await client.SendAsync(Make(HttpMethod.Get, "/auth/me", auth))).Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(Gateway.TenantId, me.GetProperty("tenantId").GetString());
            Assert.Equal(Gateway.ObjectId, me.GetProperty("objectId").GetString());
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-uuid")]
    [InlineData("{6f9619ff-8b86-d011-b42d-00c04fc964ff}")]
    public async Task ProgramsMustSendOneCanonicalRequestId(string? requestId)
    {
        string path = $"/api/{Guid.NewGuid()}";
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, path, Gateway.Basic, requestId));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True(Guid.TryParseExact(response.Rid(), "D", out _));
        Assert.Equal("request_id_invalid", (await gateway.Log.RecordAsync(response.Rid())).GetProperty("outcome").GetString());
        Assert.DoesNotContain(path, Echo.Paths);
    }

    [Fact]
    public async Task MultipleRequestIdsAreRejected()
    {
        HttpRequestMessage request = Make(HttpMethod.Get, "/api/multi", Gateway.Basic);
        request.Headers.TryAddWithoutValidation("Request-ID", [Id(), Id()]);

        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task UppercaseRequestIdIsCanonicalizedEverywhere()
    {
        string id = Id();
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, "/api/upper", Gateway.Basic, id.ToUpperInvariant()));
        Echoed echoed = await Gateway.EchoedAsync(response);

        Assert.Equal(id, response.Rid());
        Assert.Equal(id, echoed.Header("Request-ID"));
        Assert.Equal(id, (await Gateway.ValidateAssertionAsync(echoed.Header("Test-Assertion")!)).GetClaim("request_id").Value);
    }

    [Theory]
    [InlineData("/app/page")]
    [InlineData("/anon/page")]
    public async Task BrowserAndAnonymousRoutesGetAGeneratedRequestIdOrKeepAValidOne(string path)
    {
        HttpResponseMessage generated = await client.SendAsync(Make(HttpMethod.Get, path, Gateway.Basic, "invalid"));
        Echoed echoed = await Gateway.EchoedAsync(generated);
        Assert.True(Guid.TryParseExact(generated.Rid(), "D", out _));
        Assert.Equal(generated.Rid(), echoed.Header("Request-ID"));

        string id = Id();
        HttpResponseMessage kept = await client.SendAsync(Make(HttpMethod.Get, path, Gateway.Basic, id));
        Assert.Equal(id, (await Gateway.EchoedAsync(kept)).Header("Request-ID"));
        Assert.Equal(id, kept.Rid());
    }

    [Theory]
    [InlineData("/app/page")]
    [InlineData("/auth/me")]
    [InlineData("/auth/login")]
    public async Task UnauthenticatedBrowserIsChallengedWithBasic(string path)
    {
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, path));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Basic", response.Headers.WwwAuthenticate.Single().Scheme);
    }

    [Theory]
    [InlineData("/app/next", "/app/next")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("//evil.example/", "/")]
    public async Task LoginRedirectsOnlyToLocalUrls(string returnUrl, string expected)
    {
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, $"/auth/login?returnUrl={Uri.EscapeDataString(returnUrl)}", Gateway.Basic));

        Assert.Equal(expected, response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task BrowserRoutesReceiveTheCsrfTokenAndSafeCookieValuesOnly()
    {
        HttpRequestMessage browser = Make(HttpMethod.Get, "/app/page", Gateway.Basic);
        browser.Headers.Add("Cookie", "theme=dark-2.x");
        Echoed page = await Gateway.EchoedAsync(await client.SendAsync(browser));
        Assert.False(string.IsNullOrEmpty(page.Header("Test-CSRF")));
        Assert.Equal("dark-2.x", page.Header("Test-Theme"));
        Assert.Null(page.Header("Cookie"));

        HttpRequestMessage hostile = Make(HttpMethod.Get, "/app/page", Gateway.Basic);
        hostile.Headers.Add("Cookie", $"theme={new string('a', 65)}");
        Assert.Null((await Gateway.EchoedAsync(await client.SendAsync(hostile))).Header("Test-Theme"));

        HttpRequestMessage program = Make(HttpMethod.Get, "/api/page", Gateway.Basic, Id());
        program.Headers.Add("Cookie", "theme=dark");
        Echoed api = await Gateway.EchoedAsync(await client.SendAsync(program));
        Assert.Null(api.Header("Test-CSRF"));
        Assert.Null(api.Header("Test-Theme"));
    }

    [Fact]
    public async Task BackendCannotReplaceTheResponseRequestId()
    {
        string id = Id();
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, "/api/rid", Gateway.Basic, id));

        Assert.Equal(id, response.Rid());
    }

    [Fact]
    public async Task ServiceTokenRouteSendsOnlyTheServiceToken()
    {
        HttpRequestMessage request = Make(HttpMethod.Get, "/svc/search", Gateway.Basic, Id());
        request.Headers.Add("Test-Assertion", "spoofed");
        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(request));

        Assert.Equal("Bearer service-secret-token", echoed.Header("Authorization"));
        Assert.Null(echoed.Header("Test-Assertion"));

        string id = Id();
        HttpResponseMessage missing = await client.SendAsync(Make(HttpMethod.Get, "/svc-missing/search", Gateway.Basic, id));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, missing.StatusCode);
        Assert.Equal("unavailable", (await gateway.Log.RecordAsync(id)).GetProperty("outcome").GetString());
    }

    [Fact]
    public async Task HomeRedirectIsServedOnlyWhenConfigured()
    {
        HttpResponseMessage home = await client.SendAsync(Make(HttpMethod.Get, "/"));
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
        Assert.Equal("/app/home", home.Headers.Location!.OriginalString);

        using Gateway bare = new(s => s["Gateway:Home"] = null);
        Assert.Equal(HttpStatusCode.NotFound, (await bare.Client().SendAsync(Make(HttpMethod.Get, "/", Gateway.Basic))).StatusCode);
    }

    internal static async Task<(string Cookie, string Token)> CsrfAsync(HttpClient client)
    {
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Get, "/auth/csrf", Gateway.Basic));
        string cookie = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("auth-gateway-csrf=", StringComparison.Ordinal)).Split(';')[0];
        string token = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestToken").GetString()!;
        return (cookie, token);
    }

    private static void Spoof(HttpRequestMessage request)
    {
        request.Headers.Add("Test-Assertion", "spoofed");
        request.Headers.Add("Cookie", "session=stolen");
        request.Headers.Add("CSRF-Token", "spoofed");
        request.Headers.Add("Test-CSRF", "spoofed");
        request.Headers.Add("Test-Theme", "spoofed");
        request.Headers.Add("X-Internal-Secret", "spoofed");
    }

    private static void AssertStripped(Echoed echoed)
    {
        Assert.Null(echoed.Header("Authorization"));
        Assert.Null(echoed.Header("Cookie"));
        Assert.Null(echoed.Header("CSRF-Token"));
        Assert.Null(echoed.Header("X-Internal-Secret"));
        Assert.Null(echoed.Header("Test-Theme"));
        Assert.DoesNotContain("spoofed", echoed.Header("Test-CSRF") ?? "");
        Assert.DoesNotContain("spoofed", echoed.Header("Test-Assertion"));
    }
}
