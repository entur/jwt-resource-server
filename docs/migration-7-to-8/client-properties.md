# Client: properties-only applications

Applies to `jwt-client-core` and the Spring modules (RestClient, WebClient) when clients are configured with `entur.jwt.clients.*` only. For applications which use builders or the token providers directly, also read [client-programmatic.md](client-programmatic.md). Back to the [overview](README.md).

## Dependencies: Spring Security is no longer included
`jwt-client-spring` no longer depends on `spring-boot-starter-oauth2-client`, which brought in `spring-boot-starter-security`, or on `spring-boot-restclient`. The Spring test libraries (`spring-boot-test`, `spring-boot-test-autoconfigure`, `spring-test`) are no longer on the application classpath either. `jwt-client-spring-webflux` is unchanged.

 * **Security:** a servlet application which got Spring Security only through `jwt-client-spring` had Spring Boot's default security (HTTP Basic or form login on every endpoint, including actuator). After the upgrade, all of its endpoints are open, with no error. If the application needs security, add `spring-boot-starter-security` (or `jwt-spring-web`) yourself. Check with `mvn dependency:tree -Dincludes=org.springframework.security`.
 * **Compilation and startup:** code which injects `RestClient.Builder` (auto-configured by `spring-boot-restclient`), or uses Spring Security, OAuth2 client or Nimbus (`com.nimbusds`) classes, fails to compile or start unless it declares those dependencies itself, for example `spring-boot-starter-restclient` or `spring-boot-starter-oauth2-client`.
 * **BOM:** the parent and `jwt-bom` no longer manage the versions of `spring-boot-starter-oauth2-client` and `spring-boot-starter-restclient`. Take them from the Spring Boot BOM.

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

## Backoff after failed token requests
Built-in HTTP providers now back off after a failed token request, also without a cache:

 * On HTTP 429/503 the `Retry-After` header decides the wait (seconds or HTTP-date); without it, the `X-RateLimit-Reset` (Auth0) or `X-Rate-Limit-Reset` (Okta) timestamp is converted to the equivalent delay. Delays taken from a response are capped at one hour.
 * Other failures, and headers which are missing or malformed, wait 15 seconds (`retry-after.fallback-delay`).
 * Until then, calls which need a new token fail with `AccessTokenRetryAfterException` without calling the server. Cached tokens remain usable.
 * If you do not use a cache, concurrent token requests no longer queue up: the second one fails fast with `AccessTokenUnavailableException`. With a cache, loads are already serialized by the cache, so this is rarely visible.
 * Failed background refreshes with a cache wait before trying again: `cache.preemptive-refresh.error-cooldown` (15 seconds) and `cache.preemptive-refresh.eager.error-cooldown` (60 seconds; scheduled refreshes now recover on their own).
 * A refresh which fails with HTTP 5xx keeps the refresh token. The next attempt waits like after any other failure: for the delay from the response on HTTP 503, otherwise for the fallback delay.

`retry-after.fallback-delay: 0` only stops the client from inventing a wait for failures without a usable header: they are ordinary failures again, with the one immediate retry if `retrying` is enabled. It does not restore the 7.x behaviour completely. Delays from `Retry-After` or reset headers still block token requests (for up to an hour), and concurrent uncached requests still fail fast.

See the [client README](../../jwt-client/README.md#http-failure-backoff-and-authorization-server-protection).

## Other behaviour changes
 * Refresh token and revoke requests now send client authentication, like the token request: the Basic `Authorization` header and the `client_id` / `client_secret` parameters, as configured. Servers which require it for confidential clients, like Keycloak, used to reject every refresh (the client then started a new session) and every revoke on close (sessions stayed until timeout). Sessions are now refreshed and revoked, so session counts and server logs change.
 * Any 2xx response to a revoke request is accepted (Keycloak answers 204), and any 2xx token response is accepted.
 * A rejected refresh token starts a new session; empty token responses and unparsable refresh responses are reported as errors.
 * The Basic authorization header is encoded like Spring Security (RFC 6749).
 * Generic clients are included in the client auto-configuration checks.
 * `HttpURLConnection`: connections are always disconnected, so keep-alive is no longer used between token requests.
