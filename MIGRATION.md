# Migrating from 7.x to 8.0.0

Version 8.0.0 removes code deprecated in 7.2.x and fixes several unsafe defaults. Spring Boot stays at 4.1.x. See also the [CHANGELOG](CHANGELOG.md).

Contents:

 * [Backend](#backend) - `jwt-server` (web, WebFlux, gRPC)
 * [Client](#client) - `jwt-client` (generic, Auth0, Keycloak)
 * [Test](#test) - `jwt-test` (non-Spring and Spring)

## Backend
Applies to `jwt-spring-web`, `jwt-spring-webflux` and `jwt-spring-grpc-native` unless noted.

### Audiences are required
Startup now fails if JWT is enabled, at least one tenant is enabled and `entur.jwt.claims.audiences` is empty. Previously audience validation was silently skipped, so tokens issued for other APIs were accepted.

```yaml
entur:
  jwt:
    claims:
      audiences:
        - https://my.api.audience
```

 * Use the value your authorization server puts in the `aud` claim (Auth0: the API identifier; Keycloak: the client id or audience mapper value). Tokens without a matching `aud` are rejected with 401, so check that your clients request tokens for this audience.
 * Not required with `entur.jwt.enabled=false`, or if you provide your own `EnturJwtValidators` bean (which must then validate the audience).

### `JwtDecoder` beans fail startup by default
`entur.jwt.decode.fail-on-jwt-decoder-bean` now defaults to `true`. Startup fails if there is a `JwtDecoder` (or, for WebFlux, `ReactiveJwtDecoder`) bean, as such a bean is ignored by this library. This includes the bean Spring Boot creates from `spring.security.oauth2.resourceserver.jwt.*` properties, and mocked decoder beans in tests.

 * Preferably remove the bean / properties. To customize decoding in web and gRPC, provide a `ClosableJwtDecoders` bean.
 * To keep the old behaviour, set `entur.jwt.decode.fail-on-jwt-decoder-bean=false`.

### Keycloak client roles
The `resource_access` roles are now only mapped to `ROLE_*` authorities for the client configured in `entur.jwt.flavours.keycloak.client-id`. Previously the roles of all clients except `account` were mapped. Without a client id, no client roles are mapped (so `hasRole(..)` checks fail).

```yaml
entur:
  jwt:
    flavours:
      keycloak:
        client-id: booking-api
```

Roles from other clients must be granted on the configured client in Keycloak, or mapped by your own `JwtAuthorityEnricher` bean. The no-argument `KeycloakJwtAuthorityEnricher` constructor is removed; use `new KeycloakJwtAuthorityEnricher(clientId)`.

### Removed API
| Removed | Use instead |
|---|---|
| `org.entur.jwt.spring.grpc.netty.IssuerJwtDecoder` / `FastIssuerJwtDecoder` and `IssuerJwtDecoder.newBuilder()` (gRPC) | `ClosableJwtDecodersBuilder` and `IssuerJwtDecoderFactory` in `org.entur.jwt.spring.decode`, or inject the `ClosableJwtDecoders` bean |
| `EnturOauth2ResourceServerCustomizer` constructors taking JWK sources and validators (web) | the constructor taking `ClosableJwtDecoders` |
| `JwkSourceMap(Map)` | `JwkSourceMap(Map, Map)` |
| bean `claimConstraints` | inject `EnturJwtValidators` and any `OAuth2TokenValidator` beans |
| `ReactiveEnturOauth2ResourceServerCustomizer` constructor with four arguments (WebFlux) | the six-argument constructor (pass `null` for the header-to-issuer mapper and decider to disable it) |
| metadata for `entur.jwt.jwk.health-indicator.enabled` | `management.health.jwks.enabled` (the old property had no effect) |

The package `org.entur.jwt.spring.grpc.netty` keeps its name. The deprecated entry points did not support the decoded JWT cache.

### WebFlux: custom JWT processors are rejected
The public `ReactiveJwtMonoConverter` constructors throw `IllegalArgumentException` for a subclass of `JWSVerificationKeySelector` or `DefaultJWTProcessor`, a different JWS key selector on the processor, or a claims-aware key selector. The converter selects keys from keys looked up in advance, so custom key selection (an allowlist, a revocation check) would have been bypassed silently. Applications using the auto-configuration are unaffected.

JWK lookups now run on a dedicated `jwtProcessingScheduler` bean (daemon threads, not a default `Scheduler` candidate) instead of on the request thread. Define a bean with that name to replace it, or pass a `Scheduler` to the new seven-argument `ReactiveEnturOauth2ResourceServerCustomizer` constructor. See the [server README](jwt-server/README.md).

### Behaviour changes (not breaking, but visible)
 * Startup fails if two enabled tenants have the same issuer.
 * Web: error dispatches are permitted, so errors from permit-all endpoints keep their status (400, 404, 415, 500, ...) for requests without a token, instead of 401 (403 with `entur.jwt.enabled=false`). Requests rejected by the Spring Security firewall now get 400 instead of 401.
 * Required claims of type `double` accept any number, and type `integer` any whole number.
 * `OAuth2TokenValidator` beans are added to the default validators instead of replacing them.

## Client
Applies to `jwt-client-core` and the Spring modules (RestClient, WebClient, RestTemplate). The RestTemplate module is kept.

### Keycloak: context path defaults to `/`
Token requests now go to `/realms/<realm>/protocol/openid-connect/token`, the default of Keycloak 17 and later. For Keycloak before 17, or installations with `http-relative-path` set to `/auth`:

```yaml
entur:
  jwt:
    clients:
      keycloak:
        myClient:
          context-path: /auth
```

or `KeycloakClientCredentialsBuilder.withContextPath("/auth")` (`KeycloakClientCredentialsBuilder.LEGACY_CONTEXT_PATH`).

### Generic
`GenericClientCredentialsBuilder.build()` no longer throws a `NullPointerException` without `withAuthorizationHeader(..)`. The default is to send client credentials as request parameters, like the Spring default (`client-credentials-request-format: URL_PARAMETERS`). Call `withAuthorizationHeader(true)` if your server needs the `Authorization` header.

### Auth0
No API changes. The fixes below apply.

### All flavours
 * RestTemplate: HTTP 4xx/5xx are no longer all reported (and retried) as `AccessTokenUnavailableException`. Only 429 and 503 are, other codes throw `AccessTokenException` and are not retried, like the other clients. Handle exceptions accordingly.
 * HttpURLConnection: connections are always disconnected, so keep-alive is no longer used between token requests.
 * Any 2xx response to a revoke request is accepted (Keycloak answers 204).

### Backoff after failed token requests
Built-in HTTP providers (HttpURLConnection, RestClient, WebClient, RestTemplate) now back off after a failed token request, also without a cache:

 * On HTTP 429/503 the `Retry-After` header decides the wait (seconds or HTTP-date); without it, the `X-RateLimit-Reset` (Auth0) or `X-Rate-Limit-Reset` (Okta) timestamp is converted to the equivalent delay. Delays taken from a response are capped at one hour.
 * Other failures, and headers which are missing or malformed, wait 15 seconds (`retry-after.fallback-delay`, or `retryAfter(fallback, unit)` on the builders). Set it to `0` to keep the old behavior of retrying immediately.
 * Until then, calls which need a new token throw `AccessTokenRetryAfterException` (an `AccessTokenUnavailableException`) without calling the server; `getHeaders()` exposes the rate limit headers, including Auth0's `Auth0-Client-Quota-Limit` and `Auth0-Organization-Quota-Limit`, for logging. Handle it like other `AccessTokenUnavailableException`s. Cached tokens remain usable.
 * A failure with a server error (HTTP 5xx) while refreshing keeps the refresh token.
 * Concurrent uncached token requests no longer queue up: the second one fails fast with `AccessTokenUnavailableException`, as `ExclusiveAccessTokenProvider` now sits above every built-in HTTP provider. Wrap providers which you compose by hand in it too.
 * Failed background refreshes with a cache now wait before trying again, by `cache.preemptive-refresh.error-cooldown` (15 seconds) and `cache.preemptive-refresh.eager.error-cooldown` (60 seconds, scheduled refreshes, which now recover on their own). The builders have `preemptiveErrorCooldown(..)` and `eagerErrorCooldown(..)`.

See the [client README](jwt-client/README.md#http-failure-backoff-and-authorization-server-protection).

## Test
Applies to `jwt-junit5-core` (non-Spring), `jwt-junit5-spring` and `jwt-junit5-entur`.

### Package renamed
`org.entur.jwt.junit5.extention` is now `org.entur.jwt.junit5.extension`. Update the imports of `AuthorizationServerExtension`, `AuthorizationServerTestContext` and `AuthorizationServerTestManager`.

### Generic claim annotations are written as given
 * `@IntegerClaim`, `@JsonClaim`, `@MapClaim` and so on for `exp` or `iat` are absolute times in seconds, no longer relative to the current time. For relative times use `@ExpiresAt` / `@IssuedAt`, or `@AccessToken(expiresAt = .., issuedAt = ..)`.
 * The standard claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) are no longer converted by the JWT library. Numeric or ISO-8601 strings in `exp`, `nbf` and `iat` are written as strings (use a numeric claim), and empty values (for example `@Subject("")`) are written instead of omitted (use `@MissingClaim`). This makes it possible to create tokens with malformed standard claims for negative tests.

### Audiences in tests
Because `entur.jwt.claims.audiences` is required, configure it in the test configuration as well, and give test tokens a matching audience:

```java
@AccessToken(audience = "https://my.api.audience") String token
```

### Spring tests and `JwtDecoder` beans
Test configurations with a mocked `JwtDecoder` bean now fail at startup. Remove the mock (use `@AuthorizationServer` and `@AccessToken` instead), or set `entur.jwt.decode.fail-on-jwt-decoder-bean=false` in the test.

### Entur module
`jwt-junit5-entur` (`@PartnerAuth0AuthorizationServer`, `@PartnerAuth0Token`) is kept.

### Authorization servers in composed annotations and `@Nested` classes
 * Claims of a `@PartnerAuth0AuthorizationServer` inside a composed annotation are now namespaced (`https://entur.io/organisationID`), as for a directly annotated class.
 * An authorization server on a `@Nested` test class overrides the one with the same id on an enclosing class. Different authorization servers with the same id on the same class are rejected with an error.
 * Static nested (non-`@Nested`) test classes no longer inherit the authorization servers of the enclosing class, as in JUnit and Spring.
 * Tokens for `@BeforeAll` methods and per-class test instance constructors get the correct issuer.
 * `PropertiesFileResourceServerConfigurationEnricher` and `PropertiesFileAuthorizationServerConfigurationResolver` now work together.
 * Test classes using the properties file enricher get a JUnit resource lock, so they do not run in parallel with each other.
 * Subclasses of `AuthorizationServerExtension`: the field-based hooks `getAuthorizationServerImplementation(String)` and `getProperty(String, String)` are deprecated (they are not removed in 8.0.0); override `getAuthorizationServerImplementation(ExtensionContext, String)` and `getConfiguration(ExtensionContext)` instead.
