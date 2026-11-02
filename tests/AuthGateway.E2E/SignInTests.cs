using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace AuthGateway.E2E;

[Collection(RigGroup.Name)]
public sealed class SignInTests(Rig rig)
{
    [Fact]
    public async Task AnUnauthenticatedBrowserIsSentToEntraWithAPkceCodeRequest()
    {
        using Browser browser = rig.NewBrowser();

        using HttpResponseMessage first = await browser.GetAsync("/app/unauthenticated-browser");

        // A browser route sends the visitor to the gateway's own sign-in endpoint, which redirects to Entra.
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.StartsWith("/auth/login?returnUrl=%2Fapp%2Funauthenticated-browser", first.Headers.Location!.ToString(), StringComparison.Ordinal);
        using HttpResponseMessage response = await browser.GetAsync(first.Headers.Location.ToString());

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Uri location = response.Headers.Location!;
        Assert.StartsWith($"{rig.Entra.BaseUrl}/{FakeEntra.TenantId}/oauth2/v2.0/authorize", location.ToString(), StringComparison.Ordinal);
        Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal(FakeEntra.WebClientId, query["client_id"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Contains("openid", query["scope"].ToString(), StringComparison.Ordinal);
        Assert.False(rig.Backend.Saw("/app/unauthenticated-browser"));
    }

    [Fact]
    public async Task SigningInReachesTheBackendWithASignedAssertionAndNoCredentials()
    {
        using Browser browser = rig.NewBrowser();

        using HttpResponseMessage landed = await browser.SignInAsync("/app/after-sign-in");

        Assert.Equal(HttpStatusCode.OK, landed.StatusCode);
        Assert.Equal("backend reached", await landed.Content.ReadAsStringAsync());
        Received request = rig.Backend.Request("/app/after-sign-in");
        Assert.DoesNotContain("Cookie", request.Headers.Keys);
        Assert.DoesNotContain("Authorization", request.Headers.Keys);
        JsonWebToken assertion = await Rig.ValidateAssertionAsync(request.Headers["Identity-Assertion"]);
        Assert.Equal(FakeEntra.TenantId, assertion.GetPayloadValue<string>("tid"));
        Assert.Equal(FakeEntra.UserObjectId, assertion.GetPayloadValue<string>("oid"));
        Assert.Equal(["admin"], assertion.Claims.Where(claim => claim.Type == "roles").Select(claim => claim.Value));
        Assert.True(Guid.TryParse(request.Headers["Request-ID"], out _), "the backend gets a Request-ID for browser routes");
    }

    [Fact]
    public async Task TheSessionNamesTheCallerAndSurvivesFurtherRequests()
    {
        using Browser browser = rig.NewBrowser();
        using HttpResponseMessage anonymous = await browser.GetAsync("/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        using HttpResponseMessage landed = await browser.SignInAsync("/app/session-check");
        Assert.Equal(HttpStatusCode.OK, landed.StatusCode);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            using HttpResponseMessage me = await browser.GetAsync("/auth/me");
            Assert.Equal(HttpStatusCode.OK, me.StatusCode);
            JsonElement body = JsonDocument.Parse(await me.Content.ReadAsStringAsync()).RootElement;
            Assert.True(body.GetProperty("isAuthenticated").GetBoolean());
            Assert.Equal(FakeEntra.TenantId, body.GetProperty("tenantId").GetString());
            Assert.Equal(FakeEntra.UserObjectId, body.GetProperty("objectId").GetString());
            Assert.Equal("admin", Assert.Single(body.GetProperty("roles").EnumerateArray()).GetString());
        }
    }

    [Fact]
    public async Task ACookieFromAnotherSessionKeyIsNotAccepted()
    {
        using Browser browser = rig.NewBrowser();
        _ = await browser.SignInAsync("/app/tamper");
        Assert.True(browser.CookieCount > 0);

        using Browser forger = rig.NewBrowser();
        using HttpResponseMessage response = await forger.GetAsync("/auth/me", configure: request =>
            request.Headers.Add("Cookie", "__Host-auth-gateway=CfDJ8" + new string('A', 200)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ASessionCookieDoesNotLetACallerPastACsrfCheck()
    {
        using Browser browser = rig.NewBrowser();
        _ = await browser.SignInAsync("/app/csrf");

        using HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, new(browser.Gateway, "/app/csrf-post"));

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.False(rig.Backend.Saw("/app/csrf-post"));
    }

    // A BrowserUser route authenticates the cookie whatever else the request carries, so a stray bearer header
    // must not exempt the session from the CSRF check.
    [Fact]
    public async Task ABearerHeaderBesideTheSessionCookieDoesNotSkipTheCsrfCheck()
    {
        using Browser browser = rig.NewBrowser();
        _ = await browser.SignInAsync("/app/csrf-bearer");

        using HttpResponseMessage response = await browser.SendAsync(HttpMethod.Post, new(browser.Gateway, "/app/csrf-bearer-post"), configure: request =>
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer a.b.c"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(rig.Backend.Saw("/app/csrf-bearer-post"));
    }
}
