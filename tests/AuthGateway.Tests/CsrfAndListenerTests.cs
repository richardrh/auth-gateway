using Microsoft.AspNetCore.Routing;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using static AuthGateway.Tests.Requests;

namespace AuthGateway.Tests;

public sealed class CsrfTests
{
    private static readonly Gateway gateway = Gateway.Shared;
    private readonly HttpClient client = gateway.Client();

    [Fact]
    public async Task SessionMutationWithoutATokenIsRejectedBeforeTheBackend()
    {
        string id = Id();
        HttpResponseMessage response = await client.SendAsync(Make(HttpMethod.Post, $"/api/{id}", Gateway.Basic, id));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("csrf_invalid", (await gateway.Log.RecordAsync(id)).GetProperty("outcome").GetString());
        Assert.DoesNotContain(Echo.Paths, path => path.Contains(id));
    }

    [Fact]
    public async Task HtmxCsrfFailureRedirectsHome()
    {
        HttpRequestMessage request = Make(HttpMethod.Post, "/app/form", Gateway.Basic);
        request.Headers.Add("HX-Request", "true");
        HttpResponseMessage response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("/app/home", response.Headers.GetValues("HX-Redirect").Single());
    }

    [Fact]
    public async Task MutationWithAValidTokenIsProxied()
    {
        (string cookie, string token) = await ProxyTests.CsrfAsync(client);
        HttpRequestMessage request = Make(HttpMethod.Delete, "/api/thing", Gateway.Basic, Id());
        request.Headers.Add("Cookie", cookie);
        request.Headers.Add("CSRF-Token", token);

        Echoed echoed = await Gateway.EchoedAsync(await client.SendAsync(request));

        Assert.Equal("DELETE", echoed.Method);
        Assert.Null(echoed.Header("CSRF-Token"));
    }

    [Fact]
    public async Task BearerMutationsAndAnonymousRoutesAreExempt()
    {
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Make(HttpMethod.Post, "/api/bearer", Gateway.Bearer, Id()))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Make(HttpMethod.Post, "/anon/form", Gateway.Basic))).StatusCode);
    }

    [Fact]
    public async Task LogoutRequiresCsrfAndIsRefusedInDevelopment()
    {
        HttpResponseMessage noToken = await client.SendAsync(Make(HttpMethod.Post, "/auth/logout", Gateway.Basic));
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        Assert.Equal("csrf_invalid", (await gateway.Log.RecordAsync(noToken.Rid())).GetProperty("outcome").GetString());

        (string cookie, string token) = await ProxyTests.CsrfAsync(client);
        HttpRequestMessage request = Make(HttpMethod.Post, "/auth/logout", Gateway.Basic);
        request.Headers.Add("Cookie", cookie);
        request.Headers.Add("CSRF-Token", token);
        HttpResponseMessage withToken = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, withToken.StatusCode);
        Assert.Equal("local", (await gateway.Log.RecordAsync(withToken.Rid())).GetProperty("outcome").GetString());
    }
}

public sealed class ListenerTests
{
    [Theory]
    [InlineData(Policies.AuthenticatedGrpcProxy, 8080, false)]
    [InlineData(Policies.AuthenticatedProxy, 8082, false)]
    [InlineData(Policies.AuthenticatedGrpcProxy, 8082, true)]
    [InlineData(Policies.AuthenticatedProxy, 8080, true)]
    public async Task GrpcPortServesOnlyGrpcRoutes(string policy, int port, bool allowed)
    {
        DefaultHttpContext context = new();
        context.Connection.LocalPort = port;
        RouteModel route = new(new RouteConfig { RouteId = "r", AuthorizationPolicy = policy }, null!, HttpTransformer.Default);
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(route), "r"));
        bool called = false;

        await Pipeline.Listener(context, _ => { called = true; return Task.CompletedTask; }, new GatewayOptions { GrpcPort = 8082 });

        Assert.Equal(allowed, called);
        if (!allowed)
        {
            Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
            Assert.Contains(AccessLog.ListenerRejected, context.Items.Values);
        }
    }
}
