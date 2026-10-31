using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Hosting.Internal;

namespace AuthGateway.Tests;

public sealed class IdentityAssertionTests
{
    private static Dictionary<string, string?> Valid() => new()
    {
        ["IdentityAssertion:Issuer"] = "issuer",
        ["IdentityAssertion:Audience"] = "audience",
        ["IdentityAssertion:CurrentKeyId"] = "k",
        ["IdentityAssertion:Keys:k"] = Convert.ToBase64String(new byte[32]),
    };

    [Theory]
    [InlineData("Issuer", null, "IdentityAssertion:Issuer")]
    [InlineData("Audience", " ", "IdentityAssertion:Audience")]
    [InlineData("CurrentKeyId", null, "IdentityAssertion:CurrentKeyId")]
    [InlineData("Keys:k", null, "IdentityAssertion:Keys:k")]
    [InlineData("Keys:k", "SECRET-not-base64!", "IdentityAssertion:Keys:k")]
    [InlineData("Keys:k", "U0VDUkVULXNob3J0LWtleQ==", "IdentityAssertion:Keys:k")]
    [InlineData("LifetimeSeconds", "0", "IdentityAssertion:LifetimeSeconds")]
    [InlineData("LifetimeSeconds", "61", "IdentityAssertion:LifetimeSeconds")]
    public void InvalidSettingIsNamedWithoutItsValue(string key, string? value, string named)
    {
        Dictionary<string, string?> settings = Valid();
        settings[$"IdentityAssertion:{key}"] = value;

        var error = Assert.Throws<InvalidOperationException>(() => new IdentityAssertion(StartupTests.Config(settings), TimeProvider.System));

        Assert.Equal($"Invalid configuration: {named}.", error.Message);
        Assert.DoesNotContain("SECRET", error.Message);
    }

    [Fact]
    public void SessionIdIsIncludedWhenPresent()
    {
        IdentityAssertion assertion = new(StartupTests.Config(Valid()), TimeProvider.System);
        string token = assertion.Create(new Caller(Guid.NewGuid(), Guid.NewGuid(), "session", []), Guid.NewGuid().ToString());

        Assert.Equal("session", new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token).GetClaim("sid").Value);
    }
}

public sealed class CallerTests
{
    private static readonly string tenant = Guid.NewGuid().ToString();
    private static readonly string obj = Guid.NewGuid().ToString();

    private static ClaimsPrincipal User(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "test"));

    [Fact]
    public void TenantAndObjectIdsMustBeGuids()
    {
        Assert.Null(Caller.From(User(("tid", tenant)), new GatewayOptions()));
        Assert.Null(Caller.From(User(("tid", "not-a-guid"), ("oid", obj)), new GatewayOptions()));
        Assert.Equal(Guid.Parse(obj), Caller.From(User(("tid", tenant), ("oid", obj)), new GatewayOptions())!.Value.ObjectId);
    }

    [Theory]
    [InlineData("", null)]
    [InlineData("session", "session")]
    [InlineData(null, null)]
    public void SessionIdIsTakenOnlyWhenOneTo255Characters(string? sid, string? expected)
    {
        sid ??= new string('s', 256);
        Assert.Equal(expected, Caller.From(User(("tid", tenant), ("oid", obj), ("sid", sid)), new GatewayOptions())!.Value.SessionId);
    }

    [Fact]
    public void RolesAreFilteredWithDefault()
    {
        GatewayOptions options = new() { AllowedRoles = ["admin", "user"], DefaultRole = "user" };
        Assert.Equal(["admin"], Caller.From(User(("tid", tenant), ("oid", obj), ("roles", "admin"), (ClaimTypes.Role, "root")), options)!.Value.Roles);
        Assert.Equal(["user"], Caller.From(User(("tid", tenant), ("oid", obj), ("roles", "root")), options)!.Value.Roles);
        Assert.Empty(Caller.From(User(("tid", tenant), ("oid", obj), ("roles", "root")), new GatewayOptions { AllowedRoles = ["admin"] })!.Value.Roles);
        Assert.Equal(["a", "b"], Caller.From(User(("tid", tenant), ("oid", obj), ("roles", "b"), ("roles", "a")), new GatewayOptions())!.Value.Roles);
    }
}

public sealed class AuthenticationTests
{
    private static Dictionary<string, string?> Dev(string? password = "pw", string? tokenFile = null) => new()
    {
        ["DevelopmentAuth:Enabled"] = "true",
        ["DevelopmentAuth:Password"] = password,
        ["DevelopmentAuth:TokenFile"] = tokenFile,
        ["DevelopmentAuth:TenantId"] = Guid.NewGuid().ToString(),
        ["DevelopmentAuth:ObjectId"] = Guid.NewGuid().ToString(),
    };

    private static HostingEnvironment Env(string name) => new() { EnvironmentName = name };

    [Fact]
    public void DevelopmentUserLoadingRules()
    {
        Assert.Throws<InvalidOperationException>(() => DevelopmentUser.Load(StartupTests.Config(Dev()), Env("Production")));
        Assert.Contains("Password or TokenFile", Assert.Throws<InvalidOperationException>(() => DevelopmentUser.Load(StartupTests.Config(Dev(null)), Env("Development"))).Message);
        Assert.Null(DevelopmentUser.Load(StartupTests.Config(new Dictionary<string, string?>()), Env("Production")));

        string file = Path.Combine(Path.GetTempPath(), $"auth-gateway-short-{Guid.NewGuid():N}");
        File.WriteAllText(file, "short-token");
        try
        {
            Assert.Contains("TokenFile", Assert.Throws<InvalidOperationException>(() => DevelopmentUser.Load(StartupTests.Config(Dev(null, file)), Env("Development"))).Message);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData("Bearer a.b.c", true, JwtBearerDefaults.AuthenticationScheme)]
    [InlineData("Bearer development-token", true, DevelopmentUser.Scheme)]
    [InlineData("Bearer development-token", false, JwtBearerDefaults.AuthenticationScheme)]
    [InlineData("Basic dXNlcjpwdw==", true, DevelopmentUser.Scheme)]
    [InlineData(null, true, DevelopmentUser.Scheme)]
    [InlineData(null, false, CookieAuthenticationDefaults.AuthenticationScheme)]
    [InlineData("Bearerish token", false, CookieAuthenticationDefaults.AuthenticationScheme)]
    public void SelectScheme(string? authorization, bool development, string expected)
    {
        DefaultHttpContext context = new();
        if (authorization is not null)
        {
            context.Request.Headers.Authorization = authorization;
        }

        Assert.Equal(expected, GatewayAuth.SelectScheme(context, development));
    }

    [Fact]
    public void HasScopeMatchesWholeSpaceSeparatedScopes()
    {
        ClaimsPrincipal user = new(new ClaimsIdentity([new Claim("scp", "read  access_as_user")]));

        Assert.True(GatewayAuth.HasScope(user, "access_as_user"));
        Assert.False(GatewayAuth.HasScope(user, "access"));
        Assert.False(GatewayAuth.HasScope(new ClaimsPrincipal(new ClaimsIdentity()), "access_as_user"));
    }
}
