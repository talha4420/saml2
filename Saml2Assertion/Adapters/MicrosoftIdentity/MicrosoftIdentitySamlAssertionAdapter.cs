using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.IdentityModel.Tokens;
using Saml2 = Microsoft.IdentityModel.Tokens.Saml2;

namespace Saml2Assertion.Adapters.MicrosoftIdentity;

/// <summary>
/// Implementation of <see cref="ISamlAssertionAdapter"/> backed by Microsoft.IdentityModel.* SAML 2.0 primitives.
/// </summary>
public sealed class MicrosoftIdentitySamlAssertionAdapter : ISamlAssertionAdapter
{
    public SamlAssertionResult BuildAuthnResponse(SamlAssertionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var utcNow = DateTime.UtcNow;

        var assertion = CreateAssertion(request, utcNow);
        var securityToken = CreateSecurityToken(assertion, request);
        var responseXml = CreateResponseXml(request, securityToken, utcNow);
        var base64Response = Convert.ToBase64String(Encoding.UTF8.GetBytes(responseXml));
        var postContent = BuildPostContent(request.SingleSignOnDestination, base64Response, request.RelayState);

        return new SamlAssertionResult(
            request.SingleSignOnDestination.ToString(),
            request.RelayState,
            postContent,
            securityToken,
            request.Attributes);
    }

    private static Saml2.Saml2Assertion CreateAssertion(SamlAssertionRequest request, DateTime utcNow)
    {
        var assertion = new Saml2.Saml2Assertion(new Saml2.Saml2NameIdentifier(request.Issuer))
        {
            IssueInstant = utcNow,
            Subject = CreateSubject(request, utcNow),
            Conditions = CreateConditions(request, utcNow),
        };

        assertion.Statements.Add(CreateAuthnStatement(request, utcNow));

        var attributeStatement = CreateAttributeStatement(request.Attributes);
        if (attributeStatement is not null)
        {
            assertion.Statements.Add(attributeStatement);
        }

        if (ShouldSignAssertion(request.AuthnResponseSignType))
        {
            assertion.SigningCredentials = CreateSigningCredentials(request.SigningCertificate);
        }

        return assertion;
    }

    private static Saml2.Saml2Subject CreateSubject(SamlAssertionRequest request, DateTime utcNow)
    {
        var subject = new Saml2.Saml2Subject(new Saml2.Saml2NameIdentifier(request.NameId, new Uri(request.NameIdFormat)));

        var confirmationData = new Saml2.Saml2SubjectConfirmationData
        {
            Recipient = request.SingleSignOnDestination,
            NotOnOrAfter = utcNow.AddMinutes(request.SubjectConfirmationLifetimeMinutes),
        };

        if (!string.IsNullOrEmpty(request.InResponseTo))
        {
            confirmationData.InResponseTo = new Saml2.Saml2Id(request.InResponseTo);
        }

        subject.SubjectConfirmations.Add(new Saml2.Saml2SubjectConfirmation(Saml2.Saml2Constants.ConfirmationMethods.Bearer)
        {
            SubjectConfirmationData = confirmationData,
        });

        return subject;
    }

    private static Saml2.Saml2Conditions CreateConditions(SamlAssertionRequest request, DateTime utcNow)
    {
        var conditions = new Saml2.Saml2Conditions
        {
            NotBefore = utcNow,
            NotOnOrAfter = utcNow.AddMinutes(request.IssuedTokenLifetimeMinutes),
        };

        var audiences = new[] { request.SingleSignOnDestination.ToString() };
        conditions.AudienceRestrictions.Add(new Saml2.Saml2AudienceRestriction(audiences));

        return conditions;
    }

    private static Saml2.Saml2AuthenticationStatement CreateAuthnStatement(SamlAssertionRequest request, DateTime utcNow)
    {
        var statement = new Saml2.Saml2AuthenticationStatement(new Saml2.Saml2AuthenticationContext(request.AuthnContext))
        {
            AuthenticationInstant = utcNow,
        };

        if (!string.IsNullOrEmpty(request.SessionIndex))
        {
            statement.SessionIndex = request.SessionIndex;
        }

        return statement;
    }

    private static Saml2.Saml2AttributeStatement? CreateAttributeStatement(IReadOnlyCollection<SamlAttribute> attributes)
    {
        if (attributes.Count == 0)
        {
            return null;
        }

        var statement = new Saml2.Saml2AttributeStatement();
        foreach (var attribute in attributes)
        {
            statement.Attributes.Add(new Saml2.Saml2Attribute(attribute.Name, attribute.Values.ToArray()));
        }

        return statement;
    }

    private static Saml2.Saml2SecurityToken CreateSecurityToken(Saml2.Saml2Assertion assertion, SamlAssertionRequest request)
    {
        return new Saml2.Saml2SecurityToken(assertion);
    }

    private static string CreateResponseXml(SamlAssertionRequest request, Saml2.Saml2SecurityToken securityToken, DateTime utcNow)
    {
        var responseId = new Saml2.Saml2Id();
        var assertionXml = WriteAssertion(securityToken);

        var responseElement = new XElement(SamlNamespaces.Protocol + "Response",
            new XAttribute(XNamespace.Xmlns + "samlp", SamlNamespaces.Protocol),
            new XAttribute(XNamespace.Xmlns + "saml", SamlNamespaces.Assertion),
            new XAttribute("ID", responseId.Value),
            new XAttribute("Version", "2.0"),
            new XAttribute("IssueInstant", utcNow.ToString("o", CultureInfo.InvariantCulture)),
            new XAttribute("Destination", request.SingleSignOnDestination.ToString()));

        if (!string.IsNullOrEmpty(request.InResponseTo))
        {
            responseElement.Add(new XAttribute("InResponseTo", request.InResponseTo));
        }

        responseElement.Add(new XElement(SamlNamespaces.Assertion + "Issuer", request.Issuer));

        var statusElement = new XElement(SamlNamespaces.Protocol + "Status",
            new XElement(SamlNamespaces.Protocol + "StatusCode",
                new XAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")));
        responseElement.Add(statusElement);
        responseElement.Add(XElement.Parse(assertionXml));

        var responseXml = responseElement.ToString(SaveOptions.DisableFormatting);

        if (ShouldSignResponse(request.AuthnResponseSignType))
        {
            responseXml = SignResponseXml(responseXml, request.SigningCertificate);
        }

        return responseXml;
    }

    private static string WriteAssertion(Saml2.Saml2SecurityToken securityToken)
    {
        var handler = new Saml2.Saml2SecurityTokenHandler();
        var settings = new XmlWriterSettings
        {
            OmitXmlDeclaration = true,
        };

        var builder = new StringBuilder();

        using (var writer = XmlWriter.Create(builder, settings))
        {
            handler.WriteToken(writer, securityToken);
        }

        return builder.ToString();
    }

    private static string SignResponseXml(string responseXml, X509Certificate2 signingCertificate)
    {
        var document = new XmlDocument
        {
            PreserveWhitespace = true,
        };
        document.LoadXml(responseXml);

        var signedXml = new SignedXml(document)
        {
            SigningKey = signingCertificate.GetRSAPrivateKey(),
        };

        var reference = new Reference(string.Empty)
        {
            DigestMethod = SignedXml.XmlDsigSHA256Url,
        };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();
        var signatureElement = signedXml.GetXml();
        document.DocumentElement!.AppendChild(document.ImportNode(signatureElement, true));

        using var stringWriter = new StringWriter(CultureInfo.InvariantCulture);
        using var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { OmitXmlDeclaration = true });
        document.WriteTo(xmlWriter);
        xmlWriter.Flush();
        return stringWriter.ToString();
    }

    private static string BuildPostContent(Uri destination, string samlResponse, string relayState)
    {
        var destinationValue = WebUtility.HtmlEncode(destination.ToString());
        var samlResponseValue = WebUtility.HtmlEncode(samlResponse);
        var relayStateValue = WebUtility.HtmlEncode(relayState);

        var builder = new StringBuilder();
        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html lang=\"en\">");
        builder.AppendLine("<head>");
        builder.AppendLine("    <meta charset=\"utf-8\" />");
        builder.AppendLine("    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\" />");
        builder.AppendLine("    <title>SAML 2.0</title>");
        builder.AppendLine("</head>");
        builder.AppendLine("<body onload=\"document.forms[0].submit()\">");
        builder.AppendLine("    <noscript>");
        builder.AppendLine("        <p>");
        builder.AppendLine("            <strong>Note:</strong> Since your browser does not support JavaScript,");
        builder.AppendLine("            you must press the Continue button once to proceed.");
        builder.AppendLine("        </p>");
        builder.AppendLine("    </noscript>");
        builder.AppendLine($"    <form action=\"{destinationValue}\" method=\"post\">");
        builder.Append("        <div><input type=\"hidden\" name=\"SAMLResponse\" value=\"");
        builder.Append(samlResponseValue);
        builder.Append("\"/>");

        if (!string.IsNullOrEmpty(relayState))
        {
            builder.Append("<input type=\"hidden\" name=\"RelayState\" value=\"");
            builder.Append(relayStateValue);
            builder.Append("\"/>");
        }

        builder.AppendLine("</div>");
        builder.AppendLine("        <noscript>");
        builder.AppendLine("            <div>");
        builder.AppendLine("                <input type=\"submit\" value=\"Continue\"/>");
        builder.AppendLine("            </div>");
        builder.AppendLine("        </noscript>");
        builder.AppendLine("    </form>");
        builder.AppendLine("</body>");
        builder.AppendLine("</html>");

        return builder.ToString();
    }

    private static SigningCredentials CreateSigningCredentials(X509Certificate2 certificate) =>
        new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);

    private static bool ShouldSignAssertion(SamlAuthnResponseSignType signType) =>
        signType is SamlAuthnResponseSignType.AssertionOnly or SamlAuthnResponseSignType.ResponseAndAssertion;

    private static bool ShouldSignResponse(SamlAuthnResponseSignType signType) =>
        signType is SamlAuthnResponseSignType.ResponseOnly or SamlAuthnResponseSignType.ResponseAndAssertion;

    private static class SamlNamespaces
    {
        public static readonly XNamespace Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        public static readonly XNamespace Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
    }
}
