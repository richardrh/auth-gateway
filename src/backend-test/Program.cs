// Demo backend for the quick start. It answers every method and path with the request as it arrived, so you can
// see what the gateway forwards: the signed identity assertion is added and the caller's credentials are gone.
WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
WebApplication app = builder.Build();

app.Map(
    "/{**path}",
    (HttpContext context) => Results.Ok(
        new
        {
            service = context.Connection.LocalPort == 5014 ? "service-b" : "service-a",
            localPort = context.Connection.LocalPort,
            method = context.Request.Method,
            path = context.Request.Path.Value,
            headers = context.Request.Headers.ToDictionary(header => header.Key, header => header.Value.ToString()),
        }
    )
);

app.Run();
