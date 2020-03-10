# jwt-client

Client for obtaining Json Web Token (JWT) using so-called [client credentials]. 

Features:

 * caching with pro-active refreshes 
    * minimizes thread congestion
    * reduces spikes in processing time
    * minimizes number of calls to authorization servers
 * fault-tolerance / robustness
    * transient network error protection (retry once)
    * health status (on last remote access)

Essentially this allows a single JWT to be shared within a single JVM, drastically reducing the load on Authorization Servers, and reducing the server response time.

Supported servers:

 * Auth0
 * Keycloak

## Details 
    
The cache behaves in a __lazy, proactive__  way:

 * if missing or expired token, the first thread to access the cache requests a new token, while all other threads must wait (are blocked, with a deadline). 
 * if an token is about to expire, request a new in a background thread, while returning the (still valid) current token.

So while empty or expired tokens means that the implementation is essentially blocking, this is preferable to letting all thread request the same token from the authorization server.

Since we're refreshing the cache before the token expires, there will normally not be both a lot of traffic and an expired cache; so thread spaghetti (by blocking) should be avoided.

Actively refreshing the cache is possible, if desired.

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

### Keycloak configuration

```yaml
entur:
    jwt:
        client:
            keycloak:
                myClient:
                    audience: myAudience
                    client-id: myClientId
                    host: entur.org
                    realm: myTenant
                    scope: myScope
                    secret: mySecret
```

### Multiple clients
Configure additional clients by adding keys under `entur.jwt.client.keycloak` and `entur.jwt.client.auth0` (like `myClient`) in above examples, i.e.

```yaml
entur:
    jwt:
        client:
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

### Health indicator configuration
The library supports a Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) via the configuration

```yaml
entur:
    jwt:
        client:
            health-indicator:
                enabled: true
```

The health indicator looks at __the last attempt to get credentials__. It will trigger a refresh if

 * no previous attempt was made
 * last attempt was unsuccessful

In other words, the health check will not refresh expired credentials, but repeated calls to the health-check will result in a positive result once downstream services are back up. As a positive side-effect, on startup, calling the health-check before opening for traffic will result in the cache being populated (read: warmed up).


[client credentials]: https://auth0.com/docs/flows/concepts/client-credentials
