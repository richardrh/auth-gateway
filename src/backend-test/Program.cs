WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

const int ServiceAPort = 5013;
const int ServiceBPort = 5014;

app.MapGet("/a", HandleServiceA);
app.MapGet("/b", HandleServiceB);

app.Run();

static IResult HandleServiceA(HttpContext context)
{
    return Respond(context, ServiceAPort, "service-a");
}

static IResult HandleServiceB(HttpContext context)
{
    return Respond(context, ServiceBPort, "service-b");
}

static IResult Respond(HttpContext context, int expectedPort, string service)
{
    if (context.Connection.LocalPort != expectedPort)
    {
        return Results.NotFound();
    }

    string requestId = context.Request.Headers["Request-ID"].ToString();
    return Results.Ok(
        new
        {
            service,
            localPort = context.Connection.LocalPort,
            method = context.Request.Method,
            path = context.Request.Path.Value,
            host = context.Request.Host.Value,
            requestId = string.IsNullOrWhiteSpace(requestId) ? null : requestId,
        }
    );
}
