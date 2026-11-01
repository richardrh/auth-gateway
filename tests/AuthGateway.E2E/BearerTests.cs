using System.Net;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace AuthGateway.E2E;

[Collection(RigGroup.Name)]
public sealed class BearerTests(Rig rig)
{
    [Fact]
    public async Task AnEntraAccessTokenWithTheRequiredScopeReachesTheBackendAsAnAssertion()
    {
        using Browser program = rig.NewBrowser();
        Guid requestId = Guid.NewGuid();

        using HttpResponseMessage response = await program.WithBearerAsync("/api/valid-token", rig.Entra.Mint(), requestId);

        rig.Expect(HttpStatusCode.OK, response);
        Received request = rig.Backend.Request("/api/valid-token");
        Assert.DoesNotContain("Authorization", request.Headers.Keys);
        Assert.Equal(requestId.ToString(), request.Headers["Request-ID"]);
        JsonWebToken assertion = await Rig.ValidateAssertionAsync(request.Headers["Identity-Assertion"]);
        Assert.Equal(FakeEntra.TenantId, assertion.GetPayloadValue<string>("tid"));
        Assert.Equal(FakeEntra.UserObjectId, assertion.GetPayloadValue<string>("oid"));
        Assert.Equal(requestId.ToString(), assertion.GetPayloadValue<string>("request_id"));
    }

    [Fact]
    public async Task ATokenWithoutARequestIdIsRefused()
    {
        using Browser program = rig.NewBrowser();

        using HttpResponseMessage response = await program.GetAsync("/api/no-request-id", configure: request =>
            request.Headers.Authorization = new("Bearer", rig.Entra.Mint()));

        Assert.False(response.IsSuccessStatusCode);
        Assert.False(rig.Backend.Saw("/api/no-request-id"));
    }

    [Fact]
    public async Task ATokenForAnotherScopeIsForbiddenNotUnauthenticated()
    {
        using Browser program = rig.NewBrowser();

        using HttpResponseMessage response = await program.WithBearerAsync("/api/wrong-scope", rig.Entra.Mint(claims => claims["scp"] = "something_else"));

        rig.Expect(HttpStatusCode.Forbidden, response);
        Assert.False(rig.Backend.Saw("/api/wrong-scope"));
        Assert.Contains("\"outcome\":\"auth_forbidden\"", rig.Gateway.Output, StringComparison.Ordinal);
    }

    // Microsoft.Identity.Web refuses a token with neither a scope nor a role before the gateway looks at the scope.
    [Fact]
    public async Task ATokenWithNeitherScopeNorRolesIsUnauthenticated()
    {
        using Browser program = rig.NewBrowser();

        using HttpResponseMessage response = await program.WithBearerAsync("/api/no-scope", rig.Entra.Mint(claims => claims.Remove("scp")));

        rig.Expect(HttpStatusCode.Unauthorized, response);
    }

    // An application token (roles, no delegated scope) is a valid Entra token but is not allowed through.
    [Fact]
    public async Task AnApplicationTokenWithoutTheScopeIsForbidden()
    {
        using Browser program = rig.NewBrowser();
        string token = rig.Entra.Mint(claims =>
        {
            _ = claims.Remove("scp");
            claims["roles"] = new[] { "Some.Application.Role" };
        });

        using HttpResponseMessage response = await program.WithBearerAsync("/api/app-token", token);

        rig.Expect(HttpStatusCode.Forbidden, response);
        Assert.False(rig.Backend.Saw("/api/app-token"));
    }

    public static TheoryData<string> BadTokens() => new() { "expired", "wrong-audience", "wrong-issuer", "unknown-signing-key", "not-a-jwt" };

    [Theory]
    [MemberData(nameof(BadTokens))]
    public async Task ATokenEntraDidNotIssueForThisApiIsUnauthenticated(string problem)
    {
        using Browser program = rig.NewBrowser();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string token = problem switch
        {
            "expired" => rig.Entra.Mint(claims =>
            {
                claims["iat"] = now - 7200;
                claims["nbf"] = now - 7200;
                claims["exp"] = now - 3600;
            }),
            "wrong-audience" => rig.Entra.Mint(claims => claims["aud"] = "api://someone-elses-api"),
            "wrong-issuer" => rig.Entra.Mint(claims => claims["iss"] = "https://evil.example/tenant/v2.0"),
            "unknown-signing-key" => rig.Entra.Mint(signedByAnUnknownKey: true),
            _ => "definitely.not.ajwt",
        };

        using HttpResponseMessage response = await program.WithBearerAsync($"/api/bad-{problem}", token);

        rig.Expect(HttpStatusCode.Unauthorized, response);
        Assert.False(rig.Backend.Saw($"/api/bad-{problem}"));
    }

    [Fact]
    public async Task ACallerCannotSmuggleAnIdentityAssertionPastTheGateway()
    {
        using Browser program = rig.NewBrowser();

        using HttpResponseMessage response = await program.GetAsync("/api/smuggle", configure: request =>
        {
            request.Headers.Authorization = new("Bearer", rig.Entra.Mint());
            request.Headers.Add("Request-ID", Guid.NewGuid().ToString());
            request.Headers.Add("Identity-Assertion", "forged-by-the-caller");
        });

        rig.Expect(HttpStatusCode.OK, response);
        Assert.NotEqual("forged-by-the-caller", rig.Backend.Request("/api/smuggle").Headers["Identity-Assertion"]);
    }
}
