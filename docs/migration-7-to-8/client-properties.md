# Client: properties-only applications

Applies to `jwt-client-core` and the Spring modules (RestClient, WebClient) when clients are configured with `entur.jwt.clients.*` only. For applications which use builders or the token providers directly, also read [client-programmatic.md](client-programmatic.md). Back to the [overview](README.md).

## RestTemplate module removed
`jwt-client-spring-resttemplate` is removed. Depend on `jwt-client-spring` (RestClient) or `jwt-client-spring-webflux` (WebClient) instead; the `entur.jwt.clients` configuration is the same.

## Keycloak: context path defaults to `/`
Token requests now go to `/realms/<realm>/protocol/openid-connect/token`, the default of Keycloak 17 and later. Without this, token requests to Keycloak before 17 (or with `http-relative-path` set to `/auth`) fail with 404:

```yaml
entur:
  jwt:
    clients:
      keycloak:
        myClient:
          context-path: /auth
```

## Generic: client credentials as request parameters
The default is to send client credentials as request parameters, like the Spring default (`client-credentials-request-format: URL_PARAMETERS`). Change the format if your server needs the `Authorization` header.

## Backoff after failed token requests
Built-in HTTP providers now back off after a failed token request, also without a cache:

 * On HTTP 429/503 the `Retry-After` header decides the wait (seconds or HTTP-date); without it, the `X-RateLimit-Reset` (Auth0) or `X-Rate-Limit-Reset` (Okta) timestamp is converted to the equivalent delay. Delays taken from a response are capped at one hour.
 * Other failures, and headers which are missing or malformed, wait 15 seconds (`retry-after.fallback-delay`). Set it to `0` to keep the old behaviour of retrying immediately.
 * Until then, calls which need a new token fail with `AccessTokenRetryAfterException` without calling the server. Cached tokens remain usable.
 * If you do not use a cache, concurrent token requests no longer queue up: the second one fails fast with `AccessTokenUnavailableException`. With a cache, loads are already serialized by the cache, so this is rarely visible.
 * Failed background refreshes with a cache wait before trying again: `cache.preemptive-refresh.error-cooldown` (15 seconds) and `cache.preemptive-refresh.eager.error-cooldown` (60 seconds; scheduled refreshes now recover on their own).
 * A failure with a server error (HTTP 5xx) while refreshing keeps the refresh token.

See the [client README](../../jwt-client/README.md#http-failure-backoff-and-authorization-server-protection).

## Other behaviour changes
 * Any 2xx response to a revoke request is accepted (Keycloak answers 204), and any 2xx token response is accepted.
 * A rejected refresh token starts a new session; empty token responses and unparsable refresh responses are reported as errors.
 * The Basic authorization header is encoded like Spring Security (RFC 6749).
 * Generic clients are included in the client auto-configuration checks.
 * `HttpURLConnection`: connections are always disconnected, so keep-alive is no longer used between token requests.
