using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Saml2Assertion.Adapters;

/// <summary>
/// Defines how SAML Authn responses should be generated so that different SAML libraries can be used interchangeably.
/// </summary>
public interface ISamlAssertionAdapter
{
    SamlAssertionResult BuildAuthnResponse(SamlAssertionRequest request);
}

/// <summary>
/// Canonical request contract understood by every <see cref="ISamlAssertionAdapter"/> implementation.
/// </summary>
public sealed record SamlAssertionRequest
{
    public required string Issuer { get; init; }

    public required Uri SingleSignOnDestination { get; init; }

    public required SamlAuthnResponseSignType AuthnResponseSignType { get; init; }

    public required X509Certificate2 SigningCertificate { get; init; }

    public required X509Certificate2 EncryptionCertificate { get; init; }

    public required string NameId { get; init; }

    public string NameIdFormat { get; init; } = DefaultNameIdFormat;

    public string RelayState { get; init; } = string.Empty;

    public string? InResponseTo { get; init; }

    public string? SessionIndex { get; init; }

    public SamlClaimsRoute ClaimsRoute { get; init; } = SamlClaimsRoute.ClaimsIdentity;

    public Uri AuthnContext { get; init; } = new("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

    public int SubjectConfirmationLifetimeMinutes { get; init; } = 10;

    public int IssuedTokenLifetimeMinutes { get; init; } = 60;

    public IReadOnlyCollection<SamlAttribute> Attributes { get; init; } = Array.Empty<SamlAttribute>();

    public ClaimsIdentity? ClaimsIdentity { get; init; }

    public const string DefaultNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
}

/// <summary>
/// Indicates which construction route an adapter should use when building the SAML response.
/// </summary>
public enum SamlClaimsRoute
{
    ClaimsIdentity,
    DirectAssertion
}

/// <summary>
/// Normalized adapter result that callers can forward to the relying party regardless of the underlying SAML stack.
/// </summary>
public sealed record SamlAssertionResult(
    string DestinationUrl,
    string RelayState,
    string PostContent,
    SecurityToken SecurityToken,
    IReadOnlyCollection<SamlAttribute> Attributes
);

/// <summary>
/// Represents a multi-valued SAML attribute.
/// </summary>
public sealed record SamlAttribute(string Name, IReadOnlyCollection<string> Values)
{
    public static SamlAttribute FromSingleValue(string name, string value) => new(name, new ReadOnlyCollection<string>(new[] { value }));
}

/// <summary>
/// Library-agnostic representation of signing strategies for Authn responses.
/// </summary>
public enum SamlAuthnResponseSignType
{
    ResponseOnly,
    AssertionOnly,
    ResponseAndAssertion
}
