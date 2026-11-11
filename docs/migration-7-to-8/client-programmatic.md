# Client: applications using builders or providers directly

Applies to code which builds token providers with the builders in `jwt-client-core`, composes providers by hand or handles token exceptions. Also read [client-properties.md](client-properties.md), which covers the dependency changes, the removed RestTemplate module and the backoff behaviour. Back to the [overview](README.md).

## Builders
 * `KeycloakClientCredentialsBuilder`: the context path now defaults to `/` (Keycloak 17 and later). For older versions use `withContextPath("/auth")` (`KeycloakClientCredentialsBuilder.LEGACY_CONTEXT_PATH`).
 * `GenericClientCredentialsBuilder.build()` no longer throws a `NullPointerException` without `withAuthorizationHeader(..)`. Client credentials are then sent as request parameters, like the property default `client-credentials-request-format: URL_PARAMETERS`. Call `withAuthorizationHeader(true)` if your server needs the `Authorization` header (the property value `AUTHORIZATION_HEADER`).
 * New builder methods for the backoff: `retryAfter(fallback, unit)` (`0` makes header-less failures ordinary failures; see [client-properties.md](client-properties.md#backoff-after-failed-token-requests)), `preemptiveErrorCooldown(..)` and `eagerErrorCooldown(..)`.

## Handling failures
 * Calls which need a new token during a backoff throw `AccessTokenRetryAfterException`, which is an `AccessTokenUnavailableException`. Handle it like the other `AccessTokenUnavailableException`s. `getHeaders()` exposes the rate limit headers, including Auth0's `Auth0-Client-Quota-Limit` and `Auth0-Organization-Quota-Limit`, for logging.
 * Refresh failures keep or discard the refresh token depending on the response. HTTP failures are retained as the cause.

| Refresh response | Refresh token | Exception |
|---|---|---|
| HTTP 429 or 503 | kept | `AccessTokenRetryAfterException`, with the delay from the response or the fallback delay |
| other HTTP 5xx | kept | `AccessTokenException`, as for issuance |
| any other unexpected response (such as 400 or 401) | discarded | `AccessTokenRetryAfterException`; a new session is started once the backoff ends (at once with a fallback delay of `0`) |

After an HTTP 5xx, the fallback deadline still applies (unless the fallback delay is `0`): a call within the fallback delay throws `AccessTokenRetryAfterException` without calling the server, so an immediate retry fails.

## Composing providers by hand
`ExclusiveAccessTokenProvider` now sits above every built-in HTTP provider; it makes concurrent uncached token requests fail fast. Wrap providers which you compose by hand in it too, to get the same protection and to keep deadline updates race-free.

Preemptive and eager refresh keep running after unchecked exceptions.
