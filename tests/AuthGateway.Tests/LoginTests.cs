using System.Net;
using System.Web;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthGateway.Tests;

public class LoginTests
{
    // The Entra setup guide tells admins to leave implicit and ID-token grants disabled. A sign-in that asks for
    // response_type=id_token is rejected by such a registration, so browser login must use the authorization-code
    // flow with PKCE.
    [Fact]
    public async Task BrowserSignInUsesTheAuthorizationCodeFlowWithPkce()
    {
        OpenIdConnectConfiguration idp = new()
        {
            Issuer = "https://idp.example/tenant/v2.0",
            AuthorizationEndpoint = "https://idp.example/tenant/authorize",
            TokenEndpoint = "https://idp.example/tenant/token",
        };
        using Gateway gateway = new(
            configure: settings => settings["DevelopmentAuth:Enabled"] = "false",
            services: services => services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Configuration = idp;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(idp);
            }));

        HttpResponseMessage response = await gateway.Client().GetAsync("/auth/login?returnUrl=%2Fapp%2Fhome");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Uri location = response.Headers.Location!;
        Assert.Equal("idp.example", location.Host);
        System.Collections.Specialized.NameValueCollection query = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.False(string.IsNullOrEmpty(query["code_challenge"]));
    }
}
