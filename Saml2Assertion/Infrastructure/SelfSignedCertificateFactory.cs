using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Saml2Assertion.Infrastructure;

/// <summary>
/// Simplistic helper to generate throw-away self-signed certificates for demo purposes.
/// </summary>
public static class SelfSignedCertificateFactory
{
    public static X509Certificate2 Create(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment,
            true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.2"), // Client Authentication
                new Oid("1.3.6.1.5.5.7.3.1"), // Server Authentication
            },
            false));

    return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
