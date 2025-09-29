using System.Security.Claims;
using Saml2Assertion.Adapters;
using Saml2Assertion.Adapters.Itfoxtec;
using Saml2Assertion.Adapters.MicrosoftIdentity;
using Saml2Assertion.Infrastructure;

var signingCertificate = SelfSignedCertificateFactory.Create("CN=DemoSigning");
var encryptionCertificate = SelfSignedCertificateFactory.Create("CN=DemoEncryption");

var baseRequest = new SamlAssertionRequest
{
	Issuer = "https://sp.example.com",
	SingleSignOnDestination = new Uri("https://idp.example.com/sso"),
	AuthnResponseSignType = SamlAuthnResponseSignType.ResponseAndAssertion,
	SigningCertificate = signingCertificate,
	EncryptionCertificate = encryptionCertificate,
	NameId = "user@example.com",
	Attributes = new[]
	{
		SamlAttribute.FromSingleValue("givenName", "Alicia"),
		SamlAttribute.FromSingleValue("surname", "Keys"),
		new SamlAttribute("role", new[]{"Admin", "Editor"})
	}
};

var adapters = new (string Label, ISamlAssertionAdapter Adapter)[]
{
	("ITfoxtec", new ItfoxtecSamlAssertionAdapter()),
	("Microsoft.IdentityModel", new MicrosoftIdentitySamlAssertionAdapter()),
};

var scenarios = new (string Label, SamlClaimsRoute Route, bool ProvideIdentity)[]
{
	("Claims route (ClaimsIdentity provided)", SamlClaimsRoute.ClaimsIdentity, true),
	("Direct route", SamlClaimsRoute.DirectAssertion, false),
	("Direct route with ClaimsIdentity override", SamlClaimsRoute.DirectAssertion, true),
};

foreach (var (adapterLabel, adapter) in adapters)
{
	foreach (var (scenarioLabel, route, provideIdentity) in scenarios)
	{
		Console.WriteLine($"Creating SAML 2.0 Authn response using {adapterLabel} adapter via {scenarioLabel}...\n");

		var response = adapter.BuildAuthnResponse(baseRequest with
		{
			RelayState = Guid.NewGuid().ToString("N"),
			ClaimsRoute = route,
			ClaimsIdentity = provideIdentity ? CreateDemoClaimsIdentity() : null,
		});

		ForwardToAcs($"{adapterLabel} - {scenarioLabel}", response);
		Console.WriteLine(new string('-', 80));
	}
}

static void ForwardToAcs(string label, SamlAssertionResult result)
{
	Console.WriteLine($"[{label}] Destination: {result.DestinationUrl}");
	Console.WriteLine($"[{label}] RelayState: {result.RelayState}");
	Console.WriteLine();
	Console.WriteLine(result.PostContent);
	Console.WriteLine();

	Console.WriteLine($"[{label}] Attributes included in the assertion:");
	foreach (var attribute in result.Attributes)
	{
		Console.WriteLine($" - {attribute.Name}: {string.Join(", ", attribute.Values)}");
	}
	Console.WriteLine();
}

ClaimsIdentity CreateDemoClaimsIdentity()
{
	var identity = new ClaimsIdentity("CustomClaims", ClaimTypes.Name, ClaimTypes.Role);
	identity.AddClaim(new Claim(ClaimTypes.GivenName, "Alicia"));
	identity.AddClaim(new Claim(ClaimTypes.Surname, "Keys"));
	identity.AddClaim(new Claim(ClaimTypes.Email, "user@example.com"));
	identity.AddClaim(new Claim("role", "Producer"));
	identity.AddClaim(new Claim("department", "Music"));
	return identity;
}
