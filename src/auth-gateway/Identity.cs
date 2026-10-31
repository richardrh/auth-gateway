using System.Security.Claims;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthGateway;

/// <summary>The authenticated caller as a backend sees it.</summary>
public readonly record struct Caller(Guid TenantId, Guid ObjectId, string? SessionId, string[] Roles)
{
    /// <summary>The caller's Entra identity, or null when the token has no tenant or object ID.</summary>
    public static Caller? From(ClaimsPrincipal user, GatewayOptions options)
    {
        if (!Guid.TryParse(user.GetTenantId(), out Guid tenantId) || !Guid.TryParse(user.GetObjectId(), out Guid objectId))
        {
            return null;
        }

        string? sessionId = user.FindAll("sid").Concat(user.FindAll(ClaimTypes.Sid))
            .Select(claim => claim.Value.Trim())
            .FirstOrDefault(value => value.Length is > 0 and <= 255);

        SortedSet<string> roles = new(
            user.FindAll("roles").Concat(user.FindAll(ClaimTypes.Role))
                .Select(claim => claim.Value.Trim())
                .Where(role => role.Length > 0 && (options.AllowedRoles.Length == 0 || options.AllowedRoles.Contains(role))),
            StringComparer.Ordinal);
        if (roles.Count == 0 && options.DefaultRole is not null)
        {
            _ = roles.Add(options.DefaultRole);
        }

        return new Caller(tenantId, objectId, sessionId, [.. roles]);
    }
}

/// <summary>
/// Signs the short-lived HS256 JWT that tells a backend who the caller is. Claims: iss, aud, iat, exp, jti,
/// tid, oid, request_id, roles and, when the token has one, sid. Backends select the key by <c>kid</c>.
/// </summary>
public sealed class IdentityAssertion
{
    public const int MaximumLifetimeSeconds = 60;

    private readonly JsonWebTokenHandler handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly TimeProvider time;
    private readonly string issuer;
    private readonly string audience;
    private readonly int lifetimeSeconds;
    private readonly SigningCredentials credentials;

    public IdentityAssertion(IConfiguration configuration, TimeProvider time)
    {
        IConfigurationSection section = configuration.GetSection("IdentityAssertion");
        issuer = Required(section, "Issuer");
        audience = Required(section, "Audience");
        string keyId = Required(section, "CurrentKeyId");
        lifetimeSeconds = section.GetValue("LifetimeSeconds", 30);
        if (lifetimeSeconds is < 1 or > MaximumLifetimeSeconds)
        {
            throw Invalid("LifetimeSeconds");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(Required(section, $"Keys:{keyId}"));
        }
        catch (FormatException)
        {
            throw Invalid($"Keys:{keyId}");
        }
        if (key.Length < 32)
        {
            throw Invalid($"Keys:{keyId}");
        }

        credentials = new SigningCredentials(new SymmetricSecurityKey(key) { KeyId = keyId }, SecurityAlgorithms.HmacSha256);
        this.time = time;
    }

    public string Create(Caller caller, string requestId)
    {
        DateTime now = time.GetUtcNow().UtcDateTime;
        Dictionary<string, object> claims = new()
        {
            ["jti"] = Guid.NewGuid().ToString("D"),
            ["tid"] = caller.TenantId.ToString("D"),
            ["oid"] = caller.ObjectId.ToString("D"),
            ["roles"] = caller.Roles,
            ["request_id"] = requestId,
        };
        if (caller.SessionId is not null)
        {
            claims["sid"] = caller.SessionId;
        }

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now,
            Expires = now.AddSeconds(lifetimeSeconds),
            SigningCredentials = credentials,
            Claims = claims,
        });
    }

    // Messages name the setting and never its value.
    private static string Required(IConfigurationSection section, string key) =>
        section[key] is { Length: > 0 } value && !string.IsNullOrWhiteSpace(value) ? value : throw Invalid(key);

    private static InvalidOperationException Invalid(string key) => new($"Invalid configuration: IdentityAssertion:{key}.");
}
