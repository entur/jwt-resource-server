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
 * Not required with `entur.jwt.enabled=false`.

### `spring.security.oauth2.resourceserver.jwt.*` properties
`entur.jwt.decode.fail-on-jwt-decoder-bean` now defaults to `true`. Startup fails if there is a `JwtDecoder` (or, for WebFlux, `ReactiveJwtDecoder`) bean, as such a bean is ignored by this library. Spring Boot creates one from `spring.security.oauth2.resourceserver.jwt.*`, so remove those properties.

To keep the old behaviour, set `entur.jwt.decode.fail-on-jwt-decoder-bean=false`.

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

### Properties which are now honoured
 * `entur.authorization.enabled=false` (gRPC).
 * `entur.authorization.permit-all.grpc.enabled=false`.
 * JWT leeways above one minute (web and gRPC).
 * Wildcard CORS origins.
 * `entur.jwt.enabled` unset, or the JWK cache disabled: the application now starts.

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
 4. Review `entur.authorization.*` and gRPC property overrides.
 5. Deploy to a test environment; check the startup log, 401/403 rates and statuses on permit-all endpoints.
