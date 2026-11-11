# Client: applications using builders or providers directly

Applies to code which builds token providers with the builders in `jwt-client-core`, composes providers by hand or handles token exceptions. Also read [client-properties.md](client-properties.md), which covers everything configured via properties. Back to the [overview](README.md).

## Builders
 * `KeycloakClientCredentialsBuilder`: the context path now defaults to `/` (Keycloak 17 and later). For older versions use `withContextPath("/auth")` (`KeycloakClientCredentialsBuilder.LEGACY_CONTEXT_PATH`).
 * `GenericClientCredentialsBuilder.build()` no longer throws a `NullPointerException` without `withAuthorizationHeader(..)`. The default is to send client credentials as request parameters; call `withAuthorizationHeader(true)` if your server needs the `Authorization` header.
 * New builder methods for the backoff: `retryAfter(fallback, unit)` (use `0` to retry header-less failures immediately), `preemptiveErrorCooldown(..)` and `eagerErrorCooldown(..)`.

## Handling failures
 * Calls which need a new token during a backoff throw `AccessTokenRetryAfterException`, which is an `AccessTokenUnavailableException`. Handle it like the other `AccessTokenUnavailableException`s. `getHeaders()` exposes the rate limit headers, including Auth0's `Auth0-Client-Quota-Limit` and `Auth0-Organization-Quota-Limit`, for logging.
 * A failure with a server error (HTTP 5xx) while refreshing keeps the refresh token and throws `AccessTokenException`, as for issuance. HTTP failures are retained as the cause.
 * Refresh server errors are reported as `AccessTokenException`; a rejected refresh token starts a new session.

## Composing providers by hand
`ExclusiveAccessTokenProvider` now sits above every built-in HTTP provider. If you do not use a cache, concurrent token requests fail fast with `AccessTokenUnavailableException` instead of queueing (with a cache, loads are already serialized by the cache, so this is rarely visible). Wrap providers which you compose by hand in it too.

Preemptive and eager refresh keep running after unchecked exceptions, and a failed background refresh now waits for the error cooldown before the next attempt.

## RestTemplate
The `jwt-client-spring-resttemplate` module is removed. Use `jwt-client-spring` (RestClient) or `jwt-client-spring-webflux` (WebClient); the builders and `entur.jwt.clients` configuration are the same.
