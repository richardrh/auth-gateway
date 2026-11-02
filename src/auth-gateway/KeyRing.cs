using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace AuthGateway;

/// <summary>
/// The Data Protection key ring, which encrypts and signs the session cookie and antiforgery tokens. Anyone who can
/// read it can forge a session for any user, so outside Development it is always encrypted at rest with the
/// certificate in <c>DataProtection:CertificateFile</c> (a PKCS#12 file with an RSA private key). Development
/// keeps the ring in memory and never writes it.
/// </summary>
internal static partial class KeyRing
{
    public const string Section = "DataProtection";

    [LoggerMessage(Level = LogLevel.Warning, Message = "DataProtection:KeysPath still holds plaintext keys from before encryption was enabled, and they stay in use until they expire; delete those key files so every key is encrypted at rest (this signs everyone out).")]
    public static partial void LogUnencrypted(ILogger logger);

    /// <summary>
    /// Keeps every key in memory, so nothing reaches the default key directory under the home directory. The
    /// framework still preloads the ring at startup, which would otherwise create a plaintext key file there.
    /// </summary>
    public static void InMemory(IDataProtectionBuilder builder) =>
        builder.Services.Configure<KeyManagementOptions>(options =>
        {
            options.XmlRepository = new MemoryRepository();
            options.XmlEncryptor = new NoEncryption();
        });

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
        // Owner-only when the directory is created here; a mounted volume keeps the mode its mount gave it.
        _ = builder.PersistKeysToFileSystem(OperatingSystem.IsWindows()
            ? Directory.CreateDirectory(keys)
            : Directory.CreateDirectory(keys, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute));
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

    private sealed class MemoryRepository : IXmlRepository
    {
        private readonly List<XElement> elements = [];

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            lock (elements)
            {
                return [.. elements.Select(element => new XElement(element))];
            }
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            lock (elements)
            {
                elements.Add(new XElement(element));
            }
        }
    }

    // Keys never leave memory, so there is nothing to encrypt; a configured encryptor also keeps the key manager
    // from warning that keys may be persisted unencrypted.
    private sealed class NoEncryption : IXmlEncryptor, IXmlDecryptor
    {
        public EncryptedXmlInfo Encrypt(XElement plaintextElement) => new(new XElement(plaintextElement), typeof(NoEncryption));

        public XElement Decrypt(XElement encryptedElement) => new(encryptedElement);
    }
}
