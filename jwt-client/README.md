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

See submodules for Maven / Gradle coordinates.

## Details 
    
The cache by default behaves in a __lazy, proactive__  way:

 * if missing or expired token, the first thread to access the cache requests a new token, while all other threads must wait (are blocked, with a deadline). 
 * if a token is about to expire, request a new in a background thread, while returning the (still valid) current token.

So while empty or expired tokens means that the implementation is essentially blocking, this is preferable to letting all thread request the same token from the authorization server.

Since we're refreshing the cache before the token expires, there will normally not be both a lot of traffic and an expired cache; so thread spaghetti (by blocking) should be avoided.

Eager refresh can also be enabled.

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
```

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
                    retrying: true # retry (once) if getting token fails                    
                    cache:
                        minimum-time-to-live: 15 # minimum time left on token (seconds)
                        refresh-timeout: 15 # timeout when refreshing the token (seconds)
                        preemptive-refresh:
                            time-to-expires: 30 # time left on token when refreshing in the background (seconds)
                            eager:
                                enabled: false
```

Note that

 * proper configuration of `minimum-time-to-live` depends on the so-called expiry `leeway` configure in the remote service you'll be calling using the access-token.
 * eager preemptive-refresh is triggered by the `ContextStartedEvent` event, which Spring applications must implicitly invoke `.start()` to publish. For example using

```
SpringApplication.run(MyApplication.class, args).start();
```

#### Aggressive prefetching
Those wanting to preemptivly refresh tokens long before they expire, i.e. to always have some minutes (or hours) left on tokens in case of authorization server downtime, 
please note the preemptive-refresh parameter `expires-constraint`, which limits how often preemptive refresh happens (as a percentage of the access-token lifetime). 

This prevents adjustments of the access-token time-to-live (which can be dynamically configured on the authorization server) from resulting in constant refreshes, 
which could negatively affect the authorization server.

### Health indicator configuration
The library supports a Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) via the configuration

```yaml
entur:
    jwt:
        clients:
            health-indicator:
                enabled: true
```

The health indicator looks at __the last attempt to get credentials__. It will trigger a refresh if

 * no previous attempt was made
 * last attempt was unsuccessful

In other words, the health check will not refresh expired tokens, but repeated calls to the health-check will result in a positive result once downstream services are back up. As a positive side-effect, on startup, calling the health-check before opening for traffic will result in the cache being populated (read: warmed up).

[client credentials]: https://auth0.com/docs/flows/concepts/client-credentials
