using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using static AuthGateway.Tests.Requests;

namespace AuthGateway.Tests;

// Bearer tokens validated by the real JwtBearer handler with its default inbound claim mapping, as Entra tokens
// are in production. The handler renames the token's `scp` claim, so the scope check must not depend on the
// raw claim name. Development auth emits `scp` directly and cannot catch this.
public sealed class BearerTests
{
    private static readonly SymmetricSecurityKey SigningKey = new(RandomNumberGenerator.GetBytes(32));

    private static Gateway EntraStyleGateway() => new(
        configure: settings =>
        {
            settings["DevelopmentAuth:Enabled"] = "false";
            settings["ReverseProxy:Routes:grpc:ClusterId"] = "echo";
            settings["ReverseProxy:Routes:grpc:AuthorizationPolicy"] = Policies.AuthenticatedGrpcProxy;
            settings["ReverseProxy:Routes:grpc:Match:Path"] = "/svc.Service/{**rest}";
        },
        services: services => services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            // Trust a local key instead of discovering Entra metadata. Claim mapping stays at the handler default.
            OpenIdConnectConfiguration metadata = new();
            options.Configuration = metadata;
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata);
            options.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = SigningKey,
                ValidateIssuer = false,
                ValidateAudience = false,
            };
        }));

    private static AuthenticationHeaderValue Token(string scope) => new("Bearer", new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Expires = DateTime.UtcNow.AddMinutes(5),
        SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256),
        Claims = new Dictionary<string, object>
        {
            ["scp"] = scope,
            ["tid"] = Gateway.TenantId,
            ["oid"] = Gateway.ObjectId,
            ["roles"] = new[] { "admin" },
        },
    }));

    [Fact]
    public async Task TokenCarryingTheRequiredScopeIsProxiedWithAnAssertion()
    {
        using Gateway gateway = EntraStyleGateway();
        string id = Id();

        Echoed echoed = await Gateway.EchoedAsync(await gateway.Client().SendAsync(Make(HttpMethod.Get, "/api/items", Token($"other {Gateway.Scope}"), id)));

        JsonWebToken assertion = await Gateway.ValidateAssertionAsync(echoed.Header("Test-Assertion")!);
        Assert.Equal(Gateway.TenantId, assertion.GetClaim("tid").Value);
        Assert.Equal(Gateway.ObjectId, assertion.GetClaim("oid").Value);
        Assert.Equal(id, assertion.GetClaim("request_id").Value);
    }

    // Outside Development no development scheme is registered, so the gRPC policy must not name one.
    [Fact]
    public async Task GrpcRouteAuthenticatesABearerTokenWithoutDevelopmentAuth()
    {
        using Gateway gateway = EntraStyleGateway();
        HttpClient client = gateway.Client();

        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(Make(HttpMethod.Post, "/svc.Service/Call", Token(Gateway.Scope), Id())));
        HttpResponseMessage anonymous = await client.SendAsync(Make(HttpMethod.Post, "/svc.Service/Call", requestId: Id()));

        Assert.NotNull(echoed.Header("Test-Assertion"));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task TokenWithoutTheRequiredScopeIsForbidden()
    {
        using Gateway gateway = EntraStyleGateway();

        HttpResponseMessage response = await gateway.Client().SendAsync(Make(HttpMethod.Get, "/api/items", Token("other"), Id()));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
