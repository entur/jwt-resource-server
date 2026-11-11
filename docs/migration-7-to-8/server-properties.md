# Server: properties-only applications

Applies to `jwt-spring-web`, `jwt-spring-webflux` and `jwt-spring-grpc-native` when the application is configured with properties only. For applications with custom beans or code, also read [server-programmatic.md](server-programmatic.md). Back to the [overview](README.md).

## Startup fails unless you change the properties

### Audiences are required
Startup fails if JWT is enabled, at least one tenant is enabled and `entur.jwt.claims.audiences` is empty. Previously audience validation was silently skipped, so tokens issued for other APIs were accepted.

```yaml
entur:
  jwt:
    claims:
      audiences:
        - https://my.api.audience
```

 * Use the value your authorization server puts in the `aud` claim (Auth0: the API identifier; Keycloak: the client id or audience mapper value). Tokens without a matching `aud` are rejected with 401, so check that your clients request tokens for this audience.
 * Not required with `entur.jwt.enabled=false`. For gRPC, this no longer opens all methods; see [gRPC: access with JWT or authorization disabled](#grpc-access-with-jwt-or-authorization-disabled).

### `JwtDecoder` beans fail startup
`entur.jwt.decode.fail-on-jwt-decoder-bean` now defaults to `true`. Startup fails if there is a `JwtDecoder` (or, for WebFlux, `ReactiveJwtDecoder`) bean, as such a bean is ignored by this library. Spring Boot creates one from `spring.security.oauth2.resourceserver.jwt.*`, so remove those properties.

To keep the old behaviour, set `entur.jwt.decode.fail-on-jwt-decoder-bean=false`.

### Servlet gRPC
Startup fails if Spring Boot enables servlet gRPC, which it does by default when `grpc-servlet-jakarta` is on the classpath of a servlet web application. Only the native gRPC server is supported. The check existed before, but never matched, so such applications used to start. Remove the gRPC servlet dependency, or use the native gRPC server:

```yaml
spring:
  grpc:
    server:
      servlet:
        enabled: false
```

### Other startup checks
 * Two enabled tenants with the same issuer.
 * MDC mappings without `from` or `to`.

## Properties with a changed meaning

### Keycloak client roles
The `resource_access` roles are now only mapped to `ROLE_*` authorities for the client configured in `entur.jwt.flavours.keycloak.client-id`. Previously the roles of all clients except `account` were mapped. Without a client id, no client roles are mapped (so `hasRole(..)` checks fail).

```yaml
entur:
  jwt:
    flavours:
      keycloak:
        client-id: booking-api
```

Roles from other clients must be granted on the configured client in Keycloak.

### gRPC: access with JWT or authorization disabled
gRPC now treats `entur.jwt.enabled` and `entur.authorization.enabled` like the web and WebFlux modules do. Both properties used to be ignored by gRPC in ways which changed access:

| Properties | 7.x | 8.0.0 |
|---|---|---|
| `entur.jwt.enabled=false` | all methods open | only permit-all methods are open; other calls are rejected with `UNAUTHENTICATED` |
| `entur.authorization.enabled=false` | a valid token required for every method | all methods are open to anonymous callers; tokens which are present are still validated |
| both `false` | all methods open | all methods open |

 * If you set `entur.jwt.enabled=false` and rely on gRPC being open, also set `entur.authorization.enabled=false`, or add the methods to `entur.authorization.permit-all.grpc`.
 * If you set `entur.authorization.enabled=false` (for example to open the web endpoints) and rely on gRPC still requiring a token, remove the property, or enforce authorization in the services with `GrpcAuthorization`. The property applies to the web and WebFlux modules too.

See the [gRPC README](../../jwt-server/spring/jwt-spring-grpc-native/README.md#disabling-authorization).

### gRPC permit-all entries with the same service name are merged
Previously, the last `entur.authorization.permit-all.grpc.services` entry for a service replaced the methods of earlier entries with the same name. Now the methods of all such entries are permit-all. If you have more than one entry for a service, check that all of the listed methods should be open to anonymous callers.

### Properties which are now honoured
 * `entur.authorization.permit-all.grpc.enabled=false`.
 * JWT leeways above one minute (web and gRPC).
 * Wildcard CORS origins.
 * `entur.jwt.enabled` unset, or the JWK cache disabled: the application now starts.
 * gRPC: the application now starts with `spring.grpc.server.enabled=false`, or without gRPC services.
 * WebFlux: the application now starts with the default `entur.jwt.mdc.*` settings. Only MDC mappings fail startup, as MDC is not supported for WebFlux.

If any of these were set but silently ignored before, access rules and timing now change.

### Other property changes
 * `entur.jwt.jwk.health-indicator.enabled` is obsolete (it had no effect). Use `management.health.jwks.enabled`.
 * `entur.jwt.mdc.grpc.interceptor-order` now defaults to after authentication (previously `0`, before authentication).
 * The unsupported `ant` matcher type is removed.

## Behaviour changes (no property involved)
 * Web: error dispatches are permitted, so errors from permit-all endpoints keep their status (400, 404, 415, 500, ...) for requests without a token, instead of 401 (403 with `entur.jwt.enabled=false`). Requests rejected by the Spring Security firewall now get 400 instead of 401. Check monitoring which keys on 401.
 * Encrypted (JWE) tokens and tokens which are not JWS are rejected as invalid.
 * Required claims of type `double` accept any number, and type `integer` any whole number.
 * WebFlux: JWK lookups run on a dedicated scheduler instead of the request thread, and CORS is handled before Spring Security. Watch latency after the upgrade.
 * JWKs and access-token health recover or report correctly after failures, so alerts may behave differently.

## Checklist
 1. Add `entur.jwt.claims.audiences`, and the Keycloak `client-id` if you use Keycloak roles.
 2. Remove `spring.security.oauth2.resourceserver.jwt.*`.
 3. Fix duplicate tenant issuers and incomplete MDC mappings.
 4. gRPC: disable servlet gRPC if it is on the classpath. Review `entur.jwt.enabled`, `entur.authorization.*` and permit-all entries with the same service name.
 5. If the application also uses `jwt-client-spring`, read [client-properties.md](client-properties.md#dependencies-spring-security-is-no-longer-included).
 6. Deploy to a test environment; check the startup log, 401/403 rates and statuses on permit-all endpoints.
