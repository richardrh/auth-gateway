using System.Net;
using AuthGateway;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
ConfigurationManager config = builder.Configuration;
bool isDevelopment = builder.Environment.IsDevelopment();

// GATEWAY_CONFIG_FILE names a deployment profile (routes, headers). It sits under environment variables and
// the command line, which are added again so they still win.
if (config["GATEWAY_CONFIG_FILE"] is { Length: > 0 } profile)
{
    _ = config.AddJsonFile(profile, optional: false).AddEnvironmentVariables().AddCommandLine(args);
}

GatewayOptions gateway = config.GetSection(GatewayOptions.Section).Get<GatewayOptions>() ?? new();
DevelopmentUser? development = DevelopmentUser.Load(config, builder.Environment);
IConfigurationSection web = config.GetSection("AzureAdWeb");
IConfigurationSection api = config.GetSection("AzureAdApi");
string requiredScope = api["RequiredScope"] ?? string.Empty;

IDataProtectionBuilder dataProtection = builder.Services.AddDataProtection().SetApplicationName("auth-gateway");
bool keysEncrypted = false;
if (!isDevelopment)
{
    string[] missing = [.. GatewayAuth.RequiredEntraSettings.Where(key => string.IsNullOrWhiteSpace(config[key]))];
    if (missing.Length > 0)
    {
        throw new InvalidOperationException($"Invalid Azure AD configuration: {string.Join(", ", missing)}.");
    }

    keysEncrypted = KeyRing.Configure(dataProtection, config);
}

bool forwarded = config.GetValue<bool>("ForwardedHeaders:Enabled");
_ = builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.ForwardLimit = config.GetValue("ForwardedHeaders:ForwardLimit", 1);
    foreach (IConfigurationSection proxy in config.GetSection("ForwardedHeaders:KnownProxies").GetChildren())
    {
        options.KnownProxies.Add(IPAddress.Parse(proxy.Value!));
    }
    foreach (IConfigurationSection network in config.GetSection("ForwardedHeaders:KnownNetworks").GetChildren())
    {
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network.Value!));
    }
});

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "CSRF-Token";
    options.Cookie.Name = development is null ? "__Host-auth-gateway-csrf" : "auth-gateway-csrf";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = development is null ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
});
builder.Services.AddSingleton(gateway);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IdentityAssertion>();
builder.Services.AddSingleton(Console.Out);
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
builder.Services.AddReverseProxy()
    .LoadFromConfig(config.GetSection("ReverseProxy"))
    .AddTransforms(context => Proxy.Configure(context, gateway, config));

// Access records are written by AccessLog; everything else uses the plain console logger.
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.SingleLine = true;
    options.UseUtcTimestamp = true;
});
AccessLog.EnableTraceContext();

AuthenticationBuilder authentication = builder.Services.AddAuthentication(options =>
    options.DefaultScheme = options.DefaultAuthenticateScheme = options.DefaultChallengeScheme = GatewayAuth.Scheme);
authentication.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, GatewayAuth.ConfigureCookie);
authentication.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = $"{web["Instance"]?.TrimEnd('/')}/{web["TenantId"]}/v2.0";
    options.ClientId = web["ClientId"];
    options.ClientSecret = web["ClientSecret"] ?? string.Empty;
    // Authorization code with PKCE (UsePkce defaults to true). The setup guide forbids implicit/ID-token grants.
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.CallbackPath = web["CallbackPath"];
    options.SignedOutCallbackPath = web["SignedOutCallbackPath"];
    options.TokenValidationParameters.ValidateIssuer = true;
    options.TokenValidationParameters.ValidateIssuerSigningKey = true;
    options.TokenValidationParameters.ValidateLifetime = true;
});
authentication.AddMicrosoftIdentityWebApiAot(
    options =>
    {
        options.Instance = api["Instance"];
        options.TenantId = api["TenantId"];
        options.ClientId = api["ClientId"];
        options.Audience = api["Audience"];
    },
    JwtBearerDefaults.AuthenticationScheme,
    configureJwtBearerOptions: options => options.TokenValidationParameters.ValidAudiences = GatewayAuth.ValidAudiences(api));
authentication.AddPolicyScheme(GatewayAuth.Scheme, null, options =>
    options.ForwardDefaultSelector = context => GatewayAuth.SelectScheme(context, development is not null));
if (development is not null)
{
    builder.Services.AddSingleton(development);
    authentication.AddScheme<AuthenticationSchemeOptions, DevelopmentAuthHandler>(DevelopmentUser.Scheme, _ => { });
}

builder.Services.AddAuthorization(options =>
{
    string browserScheme = development is null ? CookieAuthenticationDefaults.AuthenticationScheme : DevelopmentUser.Scheme;
    options.FallbackPolicy = new AuthorizationPolicyBuilder(GatewayAuth.Scheme).RequireAuthenticatedUser().Build();
    options.AddPolicy(Policies.BrowserUser, policy => policy.AddAuthenticationSchemes(browserScheme).RequireAuthenticatedUser());
    // A caller with an Authorization header must hold the scope. Cookie sessions are not scoped.
    options.AddPolicy(Policies.AuthenticatedProxy, policy => policy
        .AddAuthenticationSchemes(GatewayAuth.Scheme)
        .RequireAuthenticatedUser()
        .RequireAssertion(context => context.Resource is not HttpContext { Request.Headers.Authorization.Count: > 0 }
            || GatewayAuth.HasScope(context.User, requiredScope)));
    // The development scheme exists only when development auth is enabled; naming an unregistered scheme throws.
    string[] grpcSchemes = development is null ? [JwtBearerDefaults.AuthenticationScheme] : [JwtBearerDefaults.AuthenticationScheme, DevelopmentUser.Scheme];
    options.AddPolicy(Policies.AuthenticatedGrpcProxy, policy => policy
        .AddAuthenticationSchemes(grpcSchemes)
        .RequireAuthenticatedUser()
        .RequireAssertion(context => GatewayAuth.HasScope(context.User, requiredScope)));
});

WebApplication app = builder.Build();
if (!isDevelopment && !keysEncrypted)
{
    KeyRing.LogUnencrypted(app.Logger);
}

app.UseMiddleware<AccessLog>();
if (forwarded)
{
    app.UseForwardedHeaders();
}
app.UseRouting();
app.Use((context, next) => Pipeline.Listener(context, next, gateway));
app.Use(Pipeline.RequestId);
if (!isDevelopment)
{
    _ = app.UseExceptionHandler();
}
app.UseAuthentication();
app.Use((context, next) => Pipeline.Csrf(context, next, context.RequestServices.GetRequiredService<IAntiforgery>(), gateway));
app.UseAuthorization();
app.MapReverseProxy();

app.MapHealthChecks("/health/live").AllowAnonymous();
app.MapHealthChecks("/health/ready").AllowAnonymous();
if (gateway.Home is { } home)
{
    app.MapGet("/", () => Results.Redirect(home)).AllowAnonymous();
}
foreach (GatewayDocument document in gateway.Documents.Where(document => !string.IsNullOrWhiteSpace(document.Json)))
{
    document.Validate();
    app.MapGet(document.Path, (HttpContext context) =>
    {
        context.Response.Headers.CacheControl = "no-store";
        return Results.Text(document.Json, "application/json");
    }).AllowAnonymous();
}

app.MapGet("/auth/login", (HttpContext context, string? returnUrl) =>
{
    string destination = GatewayAuth.IsLocalReturnUrl(returnUrl) ? returnUrl! : "/";
    if (development is not null)
    {
        return context.User.Identity?.IsAuthenticated is true
            ? Results.LocalRedirect(destination)
            : Results.Challenge(authenticationSchemes: [DevelopmentUser.Scheme]);
    }
    return Results.Challenge(new AuthenticationProperties { RedirectUri = destination }, [OpenIdConnectDefaults.AuthenticationScheme]);
}).AllowAnonymous();
app.MapPost("/auth/logout", () => development is not null
    ? Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Development credentials cannot sign out. Close the private browser session.")
    : Results.SignOut(
        new AuthenticationProperties { RedirectUri = "/" },
        [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]))
    .RequireAuthorization(Policies.BrowserUser);
app.MapGet("/auth/csrf", (HttpContext context, IAntiforgery antiforgery) =>
    Results.Ok(new { requestToken = antiforgery.GetAndStoreTokens(context).RequestToken }))
    .RequireAuthorization(Policies.BrowserUser);
app.MapGet("/auth/me", (HttpContext context) => Results.Ok(new
{
    name = context.User.Identity?.Name,
    isAuthenticated = context.User.Identity?.IsAuthenticated,
    tenantId = context.User.GetTenantId(),
    objectId = context.User.GetObjectId(),
    roles = Caller.From(context.User, gateway)?.Roles ?? [],
})).RequireAuthorization(Policies.BrowserUser);

app.Run();

public partial class Program;
