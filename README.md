# SAML2 Assertion Playground

This repository demonstrates how to emit a SAML 2.0 authentication response using the [ITfoxtec.Identity.Saml2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2) library while keeping the code adaptable for other SAML stacks, including Microsoft.IdentityModel.

## Highlights

- `ISamlAssertionAdapter` defines a library-agnostic contract for building SAML responses.
- `ItfoxtecSamlAssertionAdapter` creates an authn response, issues a security token, hydrates attributes, and binds it using HTTP POST with relay state support.
- `MicrosoftIdentitySamlAssertionAdapter` produces an equivalent response using `Microsoft.IdentityModel.Tokens.Saml2` primitives, including response-level signatures (assertion encryption is a future enhancement).
- `Program.cs` wires everything together, relying on a throw-away self-signed certificate for the demo and writing the generated POST payload for both adapters to the console.

## Running the sample

```bash
cd Saml2Assertion
dotnet run
```

The console prints the destination ACS URL, relay state, HTML form post (containing the SAMLResponse), and the attribute bag applied to the `Saml2SecurityToken`.

> ❗ **Security warnings**: ITfoxtec currently depends on a few Microsoft.IdentityModel packages that report known CVEs. Investigate upgrading when a patched release becomes available, especially before using the code in production.
>
> 🔐 **Encryption note**: The Microsoft adapter signs assertions and responses but currently skips encrypting the assertion payload; wire in `EncryptingCredentials` when you need encrypted assertions.

## Extending the adapter pattern

To add another SAML library:

1. Implement `ISamlAssertionAdapter` in a new class (see `Adapters/Itfoxtec/ItfoxtecSamlAssertionAdapter.cs` for reference).
2. Update application wiring to resolve the desired adapter (dependency injection, factory, configuration switch, etc.).
3. Keep the shared `SamlAssertionRequest`/`Result` models stable so callers remain unaffected.

For production usage remember to:

- Load real signing/encryption certificates (HSM, Azure Key Vault, etc.).
- Populate accurate NameID formats, audiences, and attribute statements.
- Persist or transport the generated HTML post to the relying party (web response, API payload, etc.).
