using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Saml2Assertion.Adapters;

namespace Saml2Assertion.Adapters.Itfoxtec;

/// <summary>
/// ITfoxtec-specific implementation of <see cref="ISamlAssertionAdapter"/>.
/// </summary>
public sealed class ItfoxtecSamlAssertionAdapter : ISamlAssertionAdapter
{
    public SamlAssertionResult BuildAuthnResponse(SamlAssertionRequest request)
    {
        var configuration = CreateConfiguration(request);
        var effectiveRoute = request.ClaimsIdentity is not null
            ? SamlClaimsRoute.ClaimsIdentity
            : request.ClaimsRoute;

        return effectiveRoute switch
        {
            SamlClaimsRoute.DirectAssertion => BuildDirectAssertionResponse(request, configuration),
            _ => BuildClaimsIdentityResponse(request, configuration),
        };
    }

    private static SamlAssertionResult BuildClaimsIdentityResponse(SamlAssertionRequest request, Saml2Configuration configuration)
    {
        var identity = ResolveClaimsIdentity(request);
        var response = CreateAuthnResponse(request, configuration, identity);

        var securityToken = response.CreateSecurityToken(
            request.SingleSignOnDestination.ToString(),
            request.AuthnContext,
            request.SubjectConfirmationLifetimeMinutes,
            request.IssuedTokenLifetimeMinutes);
        EnsureAttributes(securityToken, request.Attributes);

        var binding = new Saml2PostBinding
        {
            RelayState = request.RelayState,
        };

        binding.Bind(response);

        return FinalizeResponse(binding, securityToken, request);
    }

    private static SamlAssertionResult BuildDirectAssertionResponse(SamlAssertionRequest request, Saml2Configuration configuration)
    {
        // The ITfoxtec pipeline fundamentally relies on ClaimsIdentity to populate the assertion model,
        // so we reuse the claims-based flow for now to ensure consistent output.
        return BuildClaimsIdentityResponse(request, configuration);
    }

    private static Saml2Configuration CreateConfiguration(SamlAssertionRequest request)
    {
        return new Saml2Configuration
        {
            Issuer = request.Issuer,
            SingleSignOnDestination = request.SingleSignOnDestination,
            AuthnResponseSignType = MapSignType(request.AuthnResponseSignType),
            SigningCertificate = request.SigningCertificate,
            EncryptionCertificate = request.EncryptionCertificate,
        };
    }

    private static Saml2AuthnResponse CreateAuthnResponse(SamlAssertionRequest request, Saml2Configuration configuration, ClaimsIdentity identity)
    {
        var response = new Saml2AuthnResponse(configuration)
        {
            Destination = configuration.SingleSignOnDestination,
            Status = Saml2StatusCodes.Success,
        };

        if (!string.IsNullOrEmpty(request.InResponseTo))
        {
            response.InResponseTo = new Saml2Id(request.InResponseTo);
        }

        if (!string.IsNullOrEmpty(request.SessionIndex))
        {
            response.SessionIndex = request.SessionIndex;
        }

        response.NameId = new Saml2NameIdentifier(request.NameId, new Uri(request.NameIdFormat));
        response.ClaimsIdentity = identity;

        return response;
    }

    private static ClaimsIdentity ResolveClaimsIdentity(SamlAssertionRequest request)
    {
        if (request.ClaimsIdentity is { } provided)
        {
            return NormalizeClaimsIdentity(provided, request.NameId);
        }

        var identity = new ClaimsIdentity("Federation", ClaimTypes.Name, ClaimTypes.Role);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, request.NameId));
        return identity;
    }

    private static ClaimsIdentity NormalizeClaimsIdentity(ClaimsIdentity provided, string nameId)
    {
        var clone = new ClaimsIdentity(provided);

        foreach (var claim in clone.FindAll(ClaimTypes.NameIdentifier).ToList())
        {
            clone.RemoveClaim(claim);
        }

        clone.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameId));

        if (string.IsNullOrEmpty(clone.AuthenticationType))
        {
            var claims = clone.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer)).ToList();
            clone = new ClaimsIdentity(claims, "Federation", clone.NameClaimType, clone.RoleClaimType);
        }

        return clone;
    }

    private static void EnsureAttributes(Saml2SecurityToken token, IReadOnlyCollection<SamlAttribute> attributes)
    {
        if (attributes.Count == 0)
        {
            return;
        }

        var attributeStatement = token.Assertion.Statements
            .OfType<Saml2AttributeStatement>()
            .FirstOrDefault();

        attributeStatement ??= new Saml2AttributeStatement();

        foreach (var attribute in attributes)
        {
            attributeStatement.Attributes.Add(new Saml2Attribute(attribute.Name, attribute.Values.ToArray()));
        }

        if (!token.Assertion.Statements.Contains(attributeStatement))
        {
            token.Assertion.Statements.Add(attributeStatement);
        }
    }

    private static SamlAssertionResult FinalizeResponse(Saml2PostBinding binding, Saml2SecurityToken token, SamlAssertionRequest request)
    {
        var postContent = binding.PostContent;

        return new SamlAssertionResult(
            request.SingleSignOnDestination.ToString(),
            binding.RelayState ?? string.Empty,
            postContent,
            token,
            request.Attributes
        );
    }

    private static Saml2AuthnResponseSignTypes MapSignType(SamlAuthnResponseSignType signType)
    {
        return signType switch
        {
            SamlAuthnResponseSignType.ResponseOnly => Saml2AuthnResponseSignTypes.SignResponse,
            SamlAuthnResponseSignType.AssertionOnly => Saml2AuthnResponseSignTypes.SignAssertion,
            SamlAuthnResponseSignType.ResponseAndAssertion => Saml2AuthnResponseSignTypes.SignAssertionAndResponse,
            _ => Saml2AuthnResponseSignTypes.SignResponse,
        };
    }
}
