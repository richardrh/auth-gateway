using System.Net;
using System.Net.Http.Headers;

namespace AuthGateway.E2E;

/// <summary>
/// An HTTP client that behaves like a browser behind a TLS-terminating proxy: it keeps the gateway's cookies, follows
/// redirects one hop at a time (to the identity provider and back), and tells the gateway the original scheme was https.
/// </summary>
public sealed class Browser : IDisposable
{
    private readonly HttpClient client;
    private readonly Dictionary<string, string> cookies = new(StringComparer.Ordinal);

    public Browser(string gatewayUrl, string trustedCertificateThumbprint)
    {
        Gateway = new(gatewayUrl);
        SocketsHttpHandler handler = new() { AllowAutoRedirect = false, UseCookies = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            certificate?.GetCertHashString() == trustedCertificateThumbprint;
        client = new(handler);
    }

    /// <summary>Where the gateway is now. A restarted gateway listens elsewhere; the cookies move with the browser.</summary>
    public Uri Gateway { get; set; }

    public int CookieCount => cookies.Count;

    public void Dispose() => client.Dispose();

    public Task<HttpResponseMessage> GetAsync(string pathAndQuery, bool follow = false, Action<HttpRequestMessage>? configure = null) =>
        SendAsync(HttpMethod.Get, new(Gateway, pathAndQuery), follow, configure);

    /// <summary>Sends the request to the gateway, and to whatever it redirects to when <paramref name="follow"/> is set.</summary>
    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, Uri uri, bool follow = false, Action<HttpRequestMessage>? configure = null)
    {
        for (int hop = 0; hop < 10; hop++)
        {
            using HttpRequestMessage request = new(method, uri);
            bool toGateway = IsGateway(uri);
            if (toGateway)
            {
                request.Headers.Add("X-Forwarded-Proto", "https");
                if (cookies.Count > 0)
                {
                    request.Headers.Add("Cookie", string.Join("; ", cookies.Select(cookie => $"{cookie.Key}={cookie.Value}")));
                }
            }
            if (hop == 0)
            {
                configure?.Invoke(request);
            }

            HttpResponseMessage response = await client.SendAsync(request);
            if (toGateway)
            {
                Remember(response);
            }
            if (!follow || (int)response.StatusCode is < 300 or >= 400 || response.Headers.Location is null)
            {
                return response;
            }

            Uri next = new(uri, response.Headers.Location);
            // The gateway builds its callback URL with the forwarded scheme (https); it really listens on plain HTTP.
            uri = IsGateway(next) ? new UriBuilder(next) { Scheme = "http", Port = Gateway.Port }.Uri : next;
            response.Dispose();
        }

        throw new InvalidOperationException("Too many redirects.");
    }

    /// <summary>Signs in through the identity provider and returns the page the gateway sent the browser back to.</summary>
    public Task<HttpResponseMessage> SignInAsync(string returnUrl) =>
        GetAsync($"/auth/login?returnUrl={Uri.EscapeDataString(returnUrl)}", follow: true);

    public Task<HttpResponseMessage> WithBearerAsync(string pathAndQuery, string token, Guid? requestId = null) =>
        GetAsync(pathAndQuery, configure: request =>
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("Request-ID", (requestId ?? Guid.NewGuid()).ToString());
        });

    private bool IsGateway(Uri uri) => uri.Host == Gateway.Host && uri.Port == Gateway.Port;

    private void Remember(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? headers))
        {
            return;
        }

        foreach (string header in headers)
        {
            string[] parts = header.Split(';', StringSplitOptions.TrimEntries);
            int equals = parts[0].IndexOf('=', StringComparison.Ordinal);
            string name = parts[0][..equals];
            string value = parts[0][(equals + 1)..];
            bool deleted = value.Length == 0
                || parts.Skip(1).Any(part => part.Equals("max-age=0", StringComparison.OrdinalIgnoreCase)
                    || (part.StartsWith("expires=", StringComparison.OrdinalIgnoreCase)
                        && DateTimeOffset.TryParse(part["expires=".Length..], out DateTimeOffset until)
                        && until < DateTimeOffset.UtcNow));
            if (deleted)
            {
                _ = cookies.Remove(name);
            }
            else
            {
                cookies[name] = value;
            }
        }
    }
}
