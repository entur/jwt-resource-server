# jwt-client

Client for obtaining JSON Web Token (JWT) using so-called [client credentials]. 

Features:

 * caching with proactive refreshes 
    * minimizes thread congestion
    * reduces spikes in processing time
    * minimizes number of calls to authorization servers
 * fault-tolerance / robustness
    * failed-request backoff, including HTTP `Retry-After`
    * optional one-time retry for unavailable errors other than `AccessTokenRetryAfterException`
    * health status (on last remote access)

Essentially this allows a single JWT to be shared within a single JVM, drastically reducing the load on Authorization Servers, and reducing the server response time.

Supported server flavours:

 * Auth0
 * Keycloak

For other servers, use the generic `Generic` flavour. 

Supported clients:

 * HttpUrlConnection
 * Spring
   * RestClient
   * WebClient (but not in a reactive way)
   * RestTemplate (legacy)

See submodules for Maven / Gradle coordinates.

## Details 
    
The cache by default behaves in a __lazy, proactive__  way:

 * if missing or expired token, the first thread to access the cache requests a new token, while all other threads must wait (are blocked, with a deadline). 
 * if a token is about to expire, request a new in a background thread, while returning the (still valid) current token.

So while empty or expired tokens means that the implementation is essentially blocking, this is preferable to letting all thread request the same token from the authorization server.

Since we're refreshing the cache before the token expires, there will normally not be both a lot of traffic and an expired cache; so thread spaghetti (by blocking) should be avoided.

Eager refresh can also be enabled.

Read the scenario guides, with Mermaid diagrams, in this order:

1. [Preemptive refresh and errors](docs/preemptive-refresh/README.md): request-driven refresh, blocking reloads, retries, cooldowns, concurrency, and health checks.
2. [Eager preemptive refresh and errors](docs/eager-preemptive-refresh/README.md): scheduled refresh without traffic, error recovery, replacement-token timing, and shutdown.

## Usage
Create an instance of `AccessTokenProvider` per application-context (per Authorization Server). Instances of `AccessTokenProvider` cache og refresh access-tokens and are thread-safe. Example:

```
ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance()
                                                             .withHost("my.auth0.com")
                                                             .withProtocol("https")
                                                             .withSecret("mySecret")
                                                             .withClientId("myClientID")
                                                             .build();

// relate network timeouts to cache configuration, see further down
long connectTimeout = 10000; 
long readTimeout = 10000;
AccessTokenProvider accessTokenProvider = AccessTokenProviderBuilder.newBuilder(credentials, connectTimeout, readTimeout).build();
```

Store the `accessTokenProvider` in your application context, then get an access token:

```java
AccessToken accessToken = accessTokenProvider.getAccessToken(false); // or true for force refresh token

String jwt = accessToken.getValue(); // on the form x.y.z

// do remote requests (your code here)
```

# Framework support

## jwt-client-spring
Spring Boot starter for configuration of `AccessTokenProvider` beans.

### Auth0 configuration

```yaml
entur:
    jwt:
        clients:
            auth0:
                myClient:
                    audience: myAudience
                    client-id: myClientId
                    host: entur.org
                    scope: myScope
                    secret: mySecret
```

#### Scopes
For audiences/APIs using permissions, scopes can be used to limit the permissions included in the token (see [example](https://auth0.com/docs/tokens/management-api-access-tokens/create-and-authorize-a-machine-to-machine-application)).

Most machine-to-machine clients should not need to specify scope, and rather run with the default assigned permissions (if any).

### Keycloak configuration

```yaml
entur:
    jwt:
        clients:
            keycloak:
                myClient:
                    audience: myAudience
                    client-id: myClientId
                    host: entur.org
                    realm: myTenant
                    scope: myScope
                    secret: mySecret
                    context-path: / # default; /auth for Keycloak versions before 17
```

The `context-path` is the path Keycloak is served from, and defaults to `/`, the default of Keycloak 17 and later. For Keycloak versions before 17, set `context-path: /auth` (or the value of the Keycloak `http-relative-path` option, if configured). Token requests go to `<context-path>/realms/<realm>/protocol/openid-connect/token`.

When using `KeycloakClientCredentialsBuilder` directly, use `withContextPath(..)`.

### Multiple clients
Configure additional clients by adding keys under `entur.jwt.clients.keycloak` and `entur.jwt.clients.auth0` (like `myClient`) in above examples, i.e.

```yaml
entur:
    jwt:
        clients:
            keycloak:
                myFirstClient:
                    audience: myFirstAudience
                    client-id: myFirstClientId
                    host: first.entur.org
                    realm: myFirstTenant
                    scope: myFirstScope
                    secret: myFirstSecret
                mySecondClient:
                    audience: mySecondAudience
                    client-id: mySecondClientId
                    host: second.entur.org
                    realm: mySecondTenant
                    scope: mySecondScope
                    secret: mySecondSecret
```

Then use a `Qualifier`to autowire:

```
@Autowired
@Qualifier("myFirstClient")
private AccessTokenProvider firstAccessTokenProvider;

@Autowired
@Qualifier("mySecondClient")
private AccessTokenProvider secondAccessTokenProvider;
```

### Testing
To mock `AccessTokenProvider` use either `@MockBean` or override the bean by id (i.e. `myFirstClient` and/or `mySecondClient` in the above examples).

### Cache configuration
To adjust the caching / validity of the token, add the following properties (in addition to the above ones):

```yaml
entur:
    jwt:
        clients:
            auth0:
                myClient:
                    retrying: true # retry once on unavailable errors, except Retry-After
                    retry-after:
                        fallback-delay: 15 # after failure without a usable Retry-After header (seconds); 0 leaves such failures ordinary
                    cache:
                        minimum-time-to-live: 15 # minimum time left on token (seconds)
                        refresh-timeout: 15 # timeout when refreshing the token (seconds)
                        preemptive-refresh:
                            time-to-expires: 30 # time left on token when refreshing in the background (seconds)
                            error-cooldown: 15 # traffic-triggered cooldown after a failed background refresh (seconds)
                            eager:
                                enabled: false
                                error-cooldown: 60 # scheduled retry cooldown after a failed background refresh (seconds)
```

Note that

 * proper configuration of `minimum-time-to-live` depends on the so-called expiry `leeway` configure in the remote service you'll be calling using the access-token.
 * eager preemptive-refresh is triggered by the `ContextStartedEvent` event, which Spring applications must implicitly invoke `.start()` to publish. For example using

```
SpringApplication.run(MyApplication.class, args).start();
```

A failed preemptive refresh starts two independent cooldowns, measured from completion of the failed attempt. Traffic-triggered background refreshes use `cache.preemptive-refresh.error-cooldown` (default 15 seconds). Scheduled eager refreshes use `cache.preemptive-refresh.eager.error-cooldown` (default 60 seconds), even without incoming requests; closing the provider cancels pending retries.

Those two local cooldowns do not gate blocking reloads or the optional immediate `retrying` wrapper. The independent HTTP backoff below rejects required loads without another HTTP request while its deadline is active. The retry wrapper always propagates `AccessTokenRetryAfterException` unchanged, leaving deadline handling to the HTTP provider and cache/scheduler. Setting a background cooldown to zero disables only its local gate; scheduled eager error retries still wait at least one second. Both local settings are independent of `cache.refresh-timeout`.

An expired replacement returned during a foreground reload is rejected, but eager recovery remains scheduled after the eager error cooldown, with a one-second minimum.

For a still-valid replacement whose next eager-refresh deadline has already passed, eager refresh is rescheduled halfway through its remaining usable cache lifetime, with a one-second minimum. Lifetime is measured after the token fetch completes and excludes `minimum-time-to-live`. This keeps automatic refresh running without a tight loop or starting a new error cooldown after a successful response. Existing failure cooldowns still apply; when less than one second of usable lifetime remains, the minimum delay can extend beyond cache expiry.

#### Aggressive prefetching
Those wanting to preemptivly refresh tokens long before they expire, i.e. to always have some minutes (or hours) left on tokens in case of authorization server downtime, 
please note the preemptive-refresh parameter `expires-constraint`, which limits how often preemptive refresh happens (as a percentage of the access-token lifetime). 

This prevents adjustments of the access-token time-to-live (which can be dynamically configured on the authorization server) from resulting in constant refreshes, 
which could negatively affect the authorization server.

### HTTP failure backoff and authorization-server protection

The built-in URLConnection, RestClient, WebClient, and legacy RestTemplate providers enforce backoff for generic, Auth0, and Keycloak clients, **even with caching disabled**. On HTTP 429/503, a valid `Retry-After` determines the delay: nonnegative whole seconds or an RFC-1123 HTTP-date. A missing, blank, or malformed header uses `retry-after.fallback-delay`, default **15 seconds**. Other token-request failures, including connection failures and invalid response bodies, use that fallback too. Revocation is outside this policy.

This is a **failure-only** policy. A valid shorter header overrides the fallback; `0` or a past date permits the next call immediately. `AccessTokenRetryAfterException` still ends the current logical load without an immediate retry, even when its deadline has elapsed. Successful token requests establish no delay. Cache minimum-lifetime rejection after a successful HTTP response is a cache error, not an HTTP failure.

Each HTTP provider instance has one fixed monotonic deadline shared by issuance and refresh. Usable cached tokens remain available. During backoff, required cold, expired, forced, or uncached loads throw `AccessTokenRetryAfterException` (an `AccessTokenUnavailableException`) without HTTP or sleeping until the deadline; cached loads still use the normal reload-lock rules. Rejected calls do not restart the deadline. Background work waits for the **maximum**, not the sum, of the remaining HTTP delay and its applicable local cooldown. Throttled refreshes retain the refresh token; a genuinely rejected refresh token is discarded, with a new session deferred until backoff ends.

Builders expose `retryAfter(fallback, unit)` for built-in HTTP providers, and direct providers expose `setRetryAfterFallbackMillis(...)`. Server directives are always honored. `fallback-delay: 0` stops the client from inventing a wait: a failure without a usable header throws an ordinary `AccessTokenUnavailableException`, records no deadline, and gets the one immediate retry when `retrying` is enabled. Deadlines are JVM-local `System.nanoTime()` values, not epoch timestamps. The builder connects a built-in HTTP provider's deadline to the preemptive cache, which skips background work during backoff. Caches composed by hand (`setRetryAfterDeadline(...)`) or around custom providers learn the deadline only from `AccessTokenRetryAfterException`, so rejected background attempts are logged and observe the local cooldown.

Reuse one provider per client configuration. Cache coordination and the `ExclusiveAccessTokenProvider`, which the builder places directly above every built-in HTTP provider and which rejects overlapping token requests, prevent concurrent request fan-out, while failure backoff prevents repeated calls from immediately hitting a failing server. **This is not a global rate limit or an unconditional "never hammered" guarantee:** independent providers/replicas do not coordinate, successful forced/uncached requests are not rate-capped, and server-directed zero delays permit an immediate subsequent call. Setting `fallback-delay: 0` restores immediate retries for header-less failures. Providers composed by hand must be wrapped in `ExclusiveAccessTokenProvider` to get that protection; custom providers and HTTP-client-internal retries are otherwise outside its control.

### Health indicator configuration
The library supports a Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) via the enabling `jwts` health indicator.

The health indicator is enabled by default. Disable it using the standard Spring Boot property:

```yaml
management:
  health:
    jwts:
      enabled: false
```

Individual clients can be left out of the health indicator using `health: false` in the client configuration, for example `entur.jwt.clients.auth0.myClient.health=false`. Note that the former `entur.jwt.clients.health-indicator.enabled` property has no effect.

The health indicator looks at __the last attempt to get credentials__. It will trigger a refresh if

 * no previous attempt was made
 * last attempt was unsuccessful

An unsuccessful attempt (for example a failed preemptive refresh) does not result in a negative result as long as the cache still holds a valid access-token. An attempt which returns an access-token with less than `minimum-time-to-live` left does result in a negative result, as the cache rejects such an access-token.

In other words, the health check will not refresh expired tokens, but repeated calls to the health-check will result in a positive result once downstream services are back up. As a positive side-effect, on startup, calling the health-check before opening for traffic will result in the cache being populated (read: warmed up).

[client credentials]: https://auth0.com/docs/flows/concepts/client-credentials
