# Server: applications with custom beans or code

Applies to `jwt-spring-web`, `jwt-spring-webflux` and `jwt-spring-grpc-native` when the application defines beans, or uses library classes directly. Also read [server-properties.md](server-properties.md), which covers everything configured via properties. Back to the [overview](README.md).

## `JwtDecoder` beans fail startup by default
`entur.jwt.decode.fail-on-jwt-decoder-bean` now defaults to `true`; a `JwtDecoder` (or WebFlux `ReactiveJwtDecoder`) bean fails startup, as it is ignored by this library. This includes mocked decoder beans in tests.

 * Preferably remove the bean. To customize decoding in web and gRPC, provide a `ClosableJwtDecoders` bean.
 * To keep the old behaviour, set `entur.jwt.decode.fail-on-jwt-decoder-bean=false`.

## Audiences and your own validators
 * `entur.jwt.claims.audiences` is required, unless you provide your own `EnturJwtValidators` bean, which must then validate the audience.
 * `OAuth2TokenValidator` beans are now added to the default validators instead of replacing them. A validator which relied on replacing the defaults now runs alongside them.

## Keycloak authority enricher
The no-argument `KeycloakJwtAuthorityEnricher` constructor is removed; use `new KeycloakJwtAuthorityEnricher(clientId)`. Only the roles of that client are mapped. Roles from other clients must be granted on the configured client in Keycloak, or mapped by your own `JwtAuthorityEnricher` bean.

## Removed API
| Removed | Use instead |
|---|---|
| `org.entur.jwt.spring.grpc.netty.IssuerJwtDecoder` / `FastIssuerJwtDecoder` and `IssuerJwtDecoder.newBuilder()` (gRPC) | `ClosableJwtDecodersBuilder` and `IssuerJwtDecoderFactory` in `org.entur.jwt.spring.decode`, or inject the `ClosableJwtDecoders` bean |
| `EnturOauth2ResourceServerCustomizer` constructors taking JWK sources and validators (web) | the constructor taking `ClosableJwtDecoders` |
| `JwkSourceMap(Map)` | `JwkSourceMap(Map, Map)` |
| bean `claimConstraints` | inject `EnturJwtValidators` and any `OAuth2TokenValidator` beans |
| `ReactiveEnturOauth2ResourceServerCustomizer` constructor with four arguments (WebFlux) | the six-argument constructor (pass `null` for the header-to-issuer mapper and decider to disable it) |

The package `org.entur.jwt.spring.grpc.netty` keeps its name. The deprecated entry points did not support the decoded JWT cache.

## WebFlux: custom JWT processors are rejected
The public `ReactiveJwtMonoConverter` constructors throw `IllegalArgumentException` for a subclass of `JWSVerificationKeySelector` or `DefaultJWTProcessor`, a different JWS key selector on the processor, or a claims-aware key selector. The converter selects keys from keys looked up in advance, so custom key selection (an allowlist, a revocation check) would have been bypassed silently. Applications using the auto-configuration are unaffected.

JWK lookups now run on a dedicated `jwtProcessingScheduler` bean (daemon threads, not a default `Scheduler` candidate) instead of on the request thread. Define a bean with that name to replace it, or pass a `Scheduler` to the new seven-argument `ReactiveEnturOauth2ResourceServerCustomizer` constructor. See the [server README](../../jwt-server/README.md).

## Security configuration
 * Web: error dispatches are permitted, so errors from permit-all endpoints keep their status. Custom security filter chains are detected, and WebFlux starts with default MDC settings.
 * gRPC: the MDC interceptor runs after authentication by default. If you register interceptors with explicit orders, review them.
