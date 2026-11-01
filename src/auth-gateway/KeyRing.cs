using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;

namespace AuthGateway;

/// <summary>
/// The Data Protection key ring, which encrypts and signs the session cookie and antiforgery tokens. Anyone who can
/// read it can forge a session for any user, so outside Development it is always encrypted at rest with the
/// certificate in <c>DataProtection:CertificateFile</c> (a PKCS#12 file with an RSA private key).
/// </summary>
internal static partial class KeyRing
{
    public const string Section = "DataProtection";

    [LoggerMessage(Level = LogLevel.Warning, Message = "DataProtection:KeysPath still holds plaintext keys from before encryption was enabled, and they stay in use until they expire; delete those key files so every key is encrypted at rest (this signs everyone out).")]
    public static partial void LogUnencrypted(ILogger logger);

    /// <summary>
    /// Persists the key ring to <c>KeysPath</c>, encrypted with the certificate. Returns whether every key file is
    /// encrypted: false while plaintext keys written before encryption was enabled are still on disk.
    /// </summary>
    public static bool Configure(IDataProtectionBuilder builder, IConfiguration configuration)
    {
        string keys = configuration[$"{Section}:KeysPath"] ?? string.Empty;
        if (!Path.IsPathFullyQualified(keys))
        {
            throw Invalid("KeysPath");
        }

        // Every certificate file shares CertificatePassword. Previous certificates only decrypt keys written
        // before a rotation; new keys always use the current one.
        string? password = configuration[$"{Section}:CertificatePassword"];
        X509Certificate2 current = Load(configuration[$"{Section}:CertificateFile"], password, "CertificateFile");
        X509Certificate2[] previous =
        [
            .. configuration.GetSection($"{Section}:PreviousCertificateFiles").GetChildren()
                .Select(file => Load(file.Value, password, $"PreviousCertificateFiles:{file.Key}")),
        ];
        _ = builder.PersistKeysToFileSystem(Directory.CreateDirectory(keys));
        _ = builder.ProtectKeysWithCertificate(current);
        if (previous.Length > 0)
        {
            _ = builder.UnprotectKeysWithAnyCertificate([current, .. previous]);
        }

        return Directory.EnumerateFiles(keys, "*.xml")
            .All(file => File.ReadAllText(file).Contains("<encryptedSecret", StringComparison.Ordinal));
    }

    // Messages name the setting and never the path or the password.
    private static X509Certificate2 Load(string? file, string? password, string key)
    {
        if (string.IsNullOrWhiteSpace(file) || !Path.IsPathFullyQualified(file) || !File.Exists(file))
        {
            throw Invalid(key);
        }

        try
        {
            X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile(file, password);
            return certificate.HasPrivateKey ? certificate : throw Invalid(key);
        }
        catch (CryptographicException)
        {
            throw Invalid(key);
        }
    }

    private static InvalidOperationException Invalid(string key) => new($"Invalid configuration: {Section}:{key}.");
}
