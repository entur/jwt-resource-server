# Test support (`jwt-test`)

Applies to `jwt-junit5-core` (non-Spring), `jwt-junit5-spring` and `jwt-junit5-entur`. Back to the [overview](README.md).

## Package renamed
`org.entur.jwt.junit5.extention` is now `org.entur.jwt.junit5.extension`. Update the imports of `AuthorizationServerExtension`, `AuthorizationServerTestContext` and `AuthorizationServerTestManager`.

## Removed enrichers
`SystemPropertiesResourceServerConfigurationEnricher` and `ExtensionContextStoreResourceServerConfigurationEnricher` are removed. Neither was used by this library; if you registered one, implement `ResourceServerConfigurationEnricher` yourself.

## Generic claim annotations are written as given
 * `@IntegerClaim`, `@JsonClaim`, `@MapClaim` and so on for `exp` or `iat` are absolute times in seconds, no longer relative to the current time. For relative times use `@ExpiresAt` / `@IssuedAt`, or `@AccessToken(expiresAt = .., issuedAt = ..)`.
 * The standard claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) are no longer converted by the JWT library. Numeric or ISO-8601 strings in `exp`, `nbf` and `iat` are written as strings (use a numeric claim), and empty values (for example `@Subject("")`) are written instead of omitted (use `@MissingClaim`). This makes it possible to create tokens with malformed standard claims for negative tests.

## Audiences in tests
Because `entur.jwt.claims.audiences` is required, configure it in the test configuration as well, and give test tokens a matching audience:

```java
@AccessToken(audience = "https://my.api.audience") String token
```

## Spring tests and `JwtDecoder` beans
Test configurations with a mocked `JwtDecoder` bean now fail at startup (see [server-programmatic.md](server-programmatic.md#your-own-jwtdecoder-beans)). Remove the mock (use `@AuthorizationServer` and `@AccessToken` instead), or set `entur.jwt.decode.fail-on-jwt-decoder-bean=false` in the test.

## Spring tests without `@AuthorizationServer`
Test classes without `@AuthorizationServer` no longer disable the tenants configured in `entur.jwt.tenants.*`. Previously such a context failed with "No configured tenants" when JWT was enabled. Test classes with the same authorization servers now also share the Spring application context, so check tests which relied on getting a fresh context.

## Token contents
 * `@AccessToken(expiresAt = .., issuedAt = ..)` relative times are in seconds, as documented. They used to be multiplied by 1000, so the default token lived for about 6.9 days; it now expires after 10 minutes. Tests which keep tokens for a long time, or assert on `exp` / `iat`, may fail.
 * `@AccessToken(scope = ..)` is written as a space-delimited string, like `@Scope`, instead of an array.
 * Repeated `@Audience` and `@Scope` annotations are combined; previously only one was used.
 * `@NullClaim` writes the claim with a `null` value. Previously the claim was omitted, as with `@MissingClaim`.
 * `@MissingClaim` and `@NullClaim` on `exp` or `iat` no longer throw `NullPointerException`, and `@MapClaim` with an empty path adds its entries to the root of the claims.
 * `@JsonClaim` values are parsed to plain maps and lists.
 * Tokens are signed with a key which matches `@AlgorithmHeader`, so RS384, RS512, PS* and ES256/ES384/ES512 tokens are now accepted by the resource server modules. The JWKs have an RSA key without `alg`, plus an elliptic curve key per ES algorithm. EdDSA is not supported.

## Entur module
`jwt-junit5-entur` (`@PartnerAuth0AuthorizationServer`, `@PartnerAuth0Token`) is kept.

 * Partner Auth0 tokens no longer namespace the `scope` and `azp` claims.
 * Tokens from `@ExpiredPartnerAuth0Token` are expired; previously their expiry overflowed to the current time.

## Authorization servers in composed annotations and `@Nested` classes
 * Claims of a `@PartnerAuth0AuthorizationServer` inside a composed annotation are now namespaced (`https://entur.io/organisationID`), as for a directly annotated class.
 * An authorization server on a `@Nested` test class overrides the one with the same id on an enclosing class. Different authorization servers with the same id on the same class are rejected with an error.
 * Static nested (non-`@Nested`) test classes no longer inherit the authorization servers of the enclosing class, as in JUnit and Spring.
 * Tokens for `@BeforeAll` methods and per-class test instance constructors get the correct issuer.
 * `PropertiesFileResourceServerConfigurationEnricher` and `PropertiesFileAuthorizationServerConfigurationResolver` now work together.
 * Test classes using the properties file enricher get a JUnit resource lock, so they do not run in parallel with each other.
 * Subclasses of `AuthorizationServerExtension`: the field-based hooks `getAuthorizationServerImplementation(String)` and `getProperty(String, String)` are deprecated (not removed in 8.0.0); override `getAuthorizationServerImplementation(ExtensionContext, String)` and `getConfiguration(ExtensionContext)` instead.
