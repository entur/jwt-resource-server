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
Test configurations with a mocked `JwtDecoder` bean now fail at startup. Remove the mock (use `@AuthorizationServer` and `@AccessToken` instead), or set `entur.jwt.decode.fail-on-jwt-decoder-bean=false` in the test.

## Entur module
`jwt-junit5-entur` (`@PartnerAuth0AuthorizationServer`, `@PartnerAuth0Token`) is kept.

## Authorization servers in composed annotations and `@Nested` classes
 * Claims of a `@PartnerAuth0AuthorizationServer` inside a composed annotation are now namespaced (`https://entur.io/organisationID`), as for a directly annotated class.
 * An authorization server on a `@Nested` test class overrides the one with the same id on an enclosing class. Different authorization servers with the same id on the same class are rejected with an error.
 * Static nested (non-`@Nested`) test classes no longer inherit the authorization servers of the enclosing class, as in JUnit and Spring.
 * Tokens for `@BeforeAll` methods and per-class test instance constructors get the correct issuer.
 * `PropertiesFileResourceServerConfigurationEnricher` and `PropertiesFileAuthorizationServerConfigurationResolver` now work together.
 * Test classes using the properties file enricher get a JUnit resource lock, so they do not run in parallel with each other.
 * Test classes using the system-properties enricher lock system properties, and the previous system property values are restored after tests.
 * Subclasses of `AuthorizationServerExtension`: the field-based hooks `getAuthorizationServerImplementation(String)` and `getProperty(String, String)` are deprecated (not removed in 8.0.0); override `getAuthorizationServerImplementation(ExtensionContext, String)` and `getConfiguration(ExtensionContext)` instead.
