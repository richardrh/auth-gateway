using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;

namespace AuthGateway;

/// <summary>
/// The Data Protection key ring, which encrypts and signs the session cookie and antiforgery tokens. Anyone who can
/// read it can forge a session for any user, so with <c>DataProtection:CertificateFile</c> set it is encrypted at
/// rest with that certificate (a PKCS#12 file with an RSA private key). Without one the keys are plain XML.
/// </summary>
internal static partial class KeyRing
{
    public const string Section = "DataProtection";

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session keys are stored unencrypted in DataProtection:KeysPath; set DataProtection:CertificateFile to encrypt them at rest, and delete plaintext key files left from before (this signs everyone out).")]
    public static partial void LogUnencrypted(ILogger logger);

    /// <summary>
    /// Persists the key ring to <c>KeysPath</c>. Returns whether every key is encrypted at rest: false without a
    /// certificate, and also while plaintext keys written before encryption was enabled are still on disk.
    /// </summary>
    public static bool Configure(IDataProtectionBuilder builder, IConfiguration configuration)
    {
        string keys = configuration[$"{Section}:KeysPath"] ?? string.Empty;
        if (!Path.IsPathFullyQualified(keys))
        {
            throw Invalid("KeysPath");
        }
        _ = builder.PersistKeysToFileSystem(Directory.CreateDirectory(keys));

        // A gateway without the certificate cannot read an encrypted key ring. Left to itself it would ignore those
        // keys and write a new plaintext one into the same directory, so it refuses to start instead.
        string[] keyFiles = [.. Directory.EnumerateFiles(keys, "*.xml")];
        string[] plainFiles = [.. keyFiles.Where(file => !File.ReadAllText(file).Contains("<encryptedSecret", StringComparison.Ordinal))];
        if (string.IsNullOrWhiteSpace(configuration[$"{Section}:CertificateFile"]))
        {
            return keyFiles.Length > plainFiles.Length
                ? throw new InvalidOperationException($"Invalid configuration: {Section}:CertificateFile is required because {Section}:KeysPath holds encrypted keys.")
                : false;
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
        _ = builder.ProtectKeysWithCertificate(current);
        if (previous.Length > 0)
        {
            _ = builder.UnprotectKeysWithAnyCertificate([current, .. previous]);
        }

        return plainFiles.Length == 0;
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
