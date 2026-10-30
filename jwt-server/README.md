# jwt-server
Validation of JSON Web tokens on resource servers. Components:

 * [spring] - Spring Boot integration (of the above) via Spring Security.

## Spring Boot Integration
Spring Boot starter for Json Web Token (JWT) authorization. 

Functional overview:

 * Get Json Web Keys from the Authorization Server; use them to
 * verify JWT signatures in incoming requests, then
 * enforce generic JWT claim constraints (like checking audience, timestamp etc), then
 * parse authorities (permissions) and populate the security context,
 * let Spring Security enforce access per method (`@EnableGlobalMethodSecurity(prePostEnabled = true)`
 * optionally injects transformed JWT security context into downstream method signatures

Also supports a few typical CORS settings. A custom `WebSecurityConfigurerAdapter` can be provided by the application.

## Configuration

### Tenant configuration
The default implementation supports configuration of one or more tenants.
 
 * tenant id (key for configuration)
 * issuer
 * JSON Web Key location

Claim validation (common for all tenants):

 * audiences (required)
 * expires-at leeway
 * issued-at leeway
 * and more
 
For YAML, this amounts to something like

```yaml
entur:
  jwt:
    enabled: true # note: this is the default value
    tenants:
      myKeycloak: # i.e. tenant id
        issuer: https://myRealm.keycloak.com
        jwk: 
          location: https://my.keycloak.com/auth/realms/myRealm/protocol/openid-connect/certs
    claims:
      expires-at-leeway: 15
      issued-at-leeway: 5
      audiences: # required, at least one
        - https://my.audience
```

The audiences are required: with JWT enabled and at least one enabled tenant, startup fails if `entur.jwt.claims.audiences` is not set.
Tokens must contain (in the `aud` claim) at least one of the configured audiences. Without audience validation, a token issued
by the same tenant for any other API would be accepted.

### Custom claim validation
To validate additional claims, add one or more `OAuth2TokenValidator<Jwt>` beans. These are used in addition to the validators configured above:

```java
@Bean
public OAuth2TokenValidator<Jwt> myClaimValidator() {
    return new JwtClaimValidator<String>("my-claim", "my-value"::equals);
}
```

To replace the configured validators, provide an `EnturJwtValidators` bean:

```java
@Bean
public EnturJwtValidators enturJwtValidators() {
    return new EnturJwtValidators(List.of(new MyValidator()));
}
```

The expiry (`exp`) and not-before (`nbf`) claims are always validated: if the replacement does not validate them, validators with the configured `expires-at-leeway` and `issued-at-leeway` are added.

The replacement is responsible for validating the audience: `entur.jwt.claims.audiences` is then neither used nor required.

## Authorization configuration

By default, all requests must be so-called _fully authenticated_. In other words all requests must have a valid JWT
token (from any of the configured tenants).

Open endpoints (i.e. permitted for all, open to the world) must be explicitly configured (white-listed) using MVC or Ant
matchers.

Example for open endpoints:

```yaml
entur:
  authorization:
    enabled: true # note: this is the default value
    permit-all:
      matcher:
        patterns:
          - /unprotected/**
      matcher:
        patterns:
         - /some/path/{myVariable}
```

Note that Spring Web uses MVC matchers. In other words, for a `@RestController` with a method

```java
@GetMapping(value = "/open/country/{countryCode}")
public String authenticatedEndpoint(){
    // your code here
}
```

add the MVC matcher `/open/country/{countryCode}`. Optionally also specify the HTTP method using

```yaml
entur:
  authorization:
    permit-all:
      matcher:
        method:	
          get:
            patterns:
              - /some/path/{myVariable}
```

MVC matchers are in general __broader than Ant matchers__:

* antMatchers("/unprotected") matches only the exact `/unprotected` URL
* mvcMatchers("/unprotected") matches `/unprotected` as well as `/unprotected/`, `/unprotected.html`, `/unprotected.xyz`

Also note that if the JWT filter knows there is no permit-all (while `entur.authorization.enabled=true`), it will reject
requests without JWT earlier in the chain.

Implementation note: The _fully authenticated_ check will take effect before request unmarshalling and thus before
interaction with closed REST controller endpoints. So unwanted requests (i.e. requests without a token which obviously
will fail `@PreAuthorize` authorization checks in the controller) are rejected as early as possible, in a secure and
lightweight way.

For Spring Web, error dispatches (i.e. the servlet container forwarding a failed request to the error page, like Spring
Boot's `/error`) are permitted, so that errors from open endpoints keep their status (like 400, 404, 415 or 500) for
requests without a token. Requests made directly to the error page must still be authenticated.

#### Actuator

To
expose [actuator endpoints](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html)
, add

```yaml
entur:
  authorization:
    permit-all:
      matcher:
        patterns:
          - /actuator/**
```

### Adding fine-grained security to your Controller
Secure endpoints using [method access-control expressions] by adding the `@PreAuthorize` and `@PostAuthorize` annotations. See the following code example to see a basic implementation.

```java
@RestController
public class TestController {

    @GetMapping(value = "/myAdminService",  produces = arrayOf(MediaType.TEXT_PLAIN_VALUE))
    @PreAuthorize("hasAnyAuthority('admin')")
    public String authenticatedEndpoint(){
        // your code here
    }
}
```

See the [Spring documentation]([https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#access-control-using-preauthorize-and-postauthorize](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#access-control-using-preauthorize-and-postauthorize)) for further details.

#### Authorities
The authorities are taken from the access-token claims:

 * `scope` (or `scp`): with prefix `SCOPE_`
 * `permissions` (Auth0): as-is
 * `resource_access` (Keycloak): the roles of the configured client, with prefix `ROLE_`

For Keycloak, configure the client whose roles are mapped, normally the client id of this resource server:

```yaml
entur:
  jwt:
    flavours:
      keycloak:
        client-id: booking-api
```

Only the roles in `resource_access.booking-api.roles` are mapped, so role `booking-reader` becomes authority `ROLE_booking-reader` (for use with `hasRole('booking-reader')`). Keycloak (with the default _Full scope allowed_) adds the roles of every client the user has roles in, and the roles of other clients (like role `admin` on client `reporting-ui`) must not grant access to this resource server.

Without a client id, no client roles are mapped; a warning is logged the first time a token with client roles is seen.

Disable the Keycloak mapping using `entur.jwt.flavours.keycloak.enabled=false`, or both the Auth0 and Keycloak mappings using `entur.jwt.flavours.enabled=false`.

#### Accessing JWT claims
The library also makes it possible to inject a derived method argument generated from the authorization header: 

```java
@RestController
public class TestController {

    @GetMapping(value = "/myAdminService",  produces = arrayOf(MediaType.TEXT_PLAIN_VALUE))
    @PreAuthorize("hasAnyAuthority('admin')")
    public String authenticatedEndpoint(JwtPayload token){
        // your code here
    }
}
```

See configuration of `JwtArgumentResolver` for further details. Alternatively get to the token via the security context:

```java
JwtAuthenticationToken authentication = (JwtAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();

// get token value (including Bearer)
String token = authentication.getCredentials(); //  'Bearer XYZ'

// get claim
String myClaim = authentication.getClaim("myClaim", String.class);
```

Note that 'storing a lot of stuff' in the access-token is generally not recommended.

### Testing
It is __higly recommended that you have some simple tests that validates that the security configuration is working as expected__.

The [jwt-junit5-spring] module provide JUnit5 support. In a nutshell:

```java
@AuthorizationServer
public class MyTest {

    @Test
    public void test(@AccessToken(audience = "https://my.audience") String token) throws IOException {
        // set token in Autorization header and invoke calls
    }
}
```

The `@AuthorizationServer` test extention spawns/overwrites the tenant JWK location with a local file URL. The audiences
are not mocked, so configure `entur.jwt.claims.audiences` for tests as well, and add one of them to the tokens.

#### Multi-tentant testing
Use tenant id for multi-tentant support:

```java
@AuthorizationServer("myKeycloak")
@AuthorizationServer("myAuth0")
public class MyTest {

    @Test
    public void test(@AccessToken(by = "myKeycloak") String token) throws IOException {
        // set token in Autorization header and invoke calls
    }
}
```

See [jwt-test] for further details.

### Json Web Keys (JWK) configuration
As a reminder; JWKs are the keys used to validate JWT signatures, so the data inside can be trusted. They are provided by the Authorization Server. 

The default configuration is as follows:

 * refresh cache every 60 minutes
 * refresh cache in the background 30 seconds before it expires, if there are requests (preemptive refresh)
 * block at most 15 seconds for cache refresh before failing
 * instantly retry once to capture transient IOExceptions
 * keep cache at most 10 hours, should cache refresh fail (i.e. outage)
 * limit refreshes (including those triggered by unknown signature keys) to at most 2 per 10 seconds
 * time out HTTP requests for keys after 15 seconds (connect and read)
 * Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) enabled

This corresponds to the following configuration:

```yaml
entur:
    jwt:
        jwk:
            connect-timeout: 15 # seconds
            read-timeout: 15 # seconds
            cache:
              enabled: true
              time-to-live: 3600 # seconds
              refresh-timeout: 15 # seconds
              preemptive:
                enabled: true
                time-to-expires: 30 # seconds
                eager:
                  enabled: false # refresh even if there are no requests
            retry:
              enabled: true
            outage-cache:
              enabled: true
              time-to-live: 36000 #seconds
            rate-limit: # per tenant
              enabled: true
              refill-rate: 0.1 # per second
```

Note that eager cache refresh (if enabled) does not kick off until first time the cache is populated, which would normally be through health checks or first time a token is to be validated.

Rate limiting allows two refreshes per interval of 1 / `refill-rate` seconds, so that under normal operation one refresh is left for key rotation should the other be used by preemptive refresh. Rate limiting requires caching, so disabling the cache also disables rate limiting (with a warning). With both enabled, the cache `time-to-live` must be greater than the rate limit interval, otherwise startup fails.

#### Key rotation
The authorization server might choose to rotate its keys. When that happens, the key id used to sign the access-tokens changes, and a new key id will be noted in the JWT header. This implementation will promptly refresh the keys and normally be able to instantly verify new tokens. Previously issued tokens will be able to verify if the key list still contains the old key.

#### Health indicator
The library supports a Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) via the enabling `jwks` health indicator. It looks at __the last attempt__ to get signing keys. It will trigger a refresh if

 * no previous attempt was made
 * last attempt was unsuccessful

In other words, the health check will not refresh expired keys, but repeated calls to the health-check __will result in a positive result once downstream services are back up__. As a positive side-effect, on startup, calling the health-check before opening for traffic will result in the cache being populated (read: warmed up).

After an unsuccessful attempt, the health check fetches the keys even if they are still cached. These refreshes are rate limited together with the refreshes triggered by unknown signature keys.

The health indicator is enabled by default. Disable it using the standard Spring Boot property:

```yaml
management:
  health:
    jwks:
      enabled: false
```

Note that the former `entur.jwt.jwk.health-indicator.enabled` property has no effect.

### Context logging
For copying interesting JWT fields through to the MDC logging context, configure mappings:

```yaml
entur:
  jwt:
    mdc:
      enabled: true
      mappings:
      - from: iss #from claim
        to: issuer
```

MDC mappings are not supported for WebFlux; startup fails if `entur.jwt.mdc.mappings` are configured (unless `entur.jwt.mdc.enabled=false`).

### Cross-Origin Resource Sharing (CORS)
The CORS support is intended for use-cases where your customers do NOT normally call your API directly from web-browser and other distributed apps like mobile applications (technically, this cannot be prevented using CORS). With the notable exception of your development portal.

This is so __that API-keys, client credentials, access-tokens and/or other secrets are not compromised__. Webapps are intended to have a dedicated backend service on the same domain, so no CORS request are necessary.

Configuration example:

```yaml
entur:
  cors: 
    enabled: true
    mode: xyz
    origins:
      - https://myapp.entur.org
      - https://myotherpetstore.swagger.io
      - https://*.mydomain.org
    # allow-credentials: false # default automatic, see below
```

where `xyz` is from the following list

* `api` (default) - CORS requests from selected sites. Recommended exceptions:
   * Your API development portal 
   * Petstore
* `webapp` - no CORS requests are accepted 

Each origin is either

* an exact origin, like `https://myapp.entur.org`,
* an origin pattern containing `*`, like `https://*.mydomain.org` (see Spring's `CorsConfiguration.setAllowedOriginPatterns(..)`), or
* `*` for any origin.

The `allow-credentials` property sets the `Access-Control-Allow-Credentials` response header, which browsers require for requests with cookies, HTTP authentication or TLS client certificates. Access-tokens sent as bearer tokens in the `Authorization` header do not need it, so origin `*` without credentials lets scripts on any website call your API with an access-token.

* not set (default) - `true`, unless the origins contain `*`, then `false`
* `true` - not allowed together with origin `*`, as browsers reject that combination; startup fails
* `false`

#### Custom CORS configuration
To use your own CORS configuration, disable the CORS support of this starter with `entur.cors.enabled=false`; otherwise its bean named `corsConfigurationSource` clashes with yours. Then

* for [jwt-spring-web], add a `CorsConfigurationSource` bean. The bean name must be `corsConfigurationSource` in order for Spring Security to pick up the bean.

```java
@Bean("corsConfigurationSource")
public CorsConfigurationSource myCorsConfigurationSource() {
    // ...
} 
```

* for [jwt-spring-webflux], add a `CorsWebFilter` bean which runs before the Spring Security filter chain (order `-100`), so that preflight requests, which carry no access-token, are not rejected. This starter's own bean named `corsConfigurationSource` is such a `CorsWebFilter` (order `-101`), so the `CorsConfigurationSource` approach above does not apply.

```java
@Bean
@Order(-101)
public CorsWebFilter myCorsWebFilter() {
    // ...
} 
```

#### CORS and API gateway

In general, the API gateway should respond with HTTP 403 to requests with unknown origins. All other requests, including
OPTIONS calls, can be sent backwards to the Spring application.

See [jwt-spring-web] for a concrete implementation example.

## Custom JWT decoders
JWTs are decoded by per-issuer decoders built from the `entur.jwt.tenants` configuration. A `JwtDecoder` or `ReactiveJwtDecoder` bean in the application context is ignored, including one created by Spring Boot from `spring.security.oauth2.resourceserver.jwt.*` properties. To customize JWT decoding for the web and gRPC modules, provide a `ClosableJwtDecoders` bean (a map of issuer to `JwtDecoder`) instead. To keep the [claim validation](#custom-claim-validation), build it using `ClosableJwtDecodersBuilder` with the validators from `JwtDecoderValidators.combine(..)`.

To fail startup if there is such a bean (recommended; the default in the next major version), enable the check:

```yaml
entur:
  jwt:
    decode:
      fail-on-jwt-decoder-bean: true # default false
```

## Custom security filter chain
For WebFlux, startup fails if the application defines its own `SecurityWebFilterChain` bean, as it would shadow the chain of this starter. To use a custom chain, set `entur.jwt.enabled=false` and `entur.authorization.enabled=false`, or exclude the starter's chain using `@SpringBootApplication(exclude = {JwtWebFluxSecurityAutoConfiguration.class})`.

## Advanced features
A couple of optional, opt-in performance features are available. Both default to disabled and are safe to leave off.

### Header-to-issuer mapping
In a multi-tenant setup (more than one configured issuer), figuring out which tenant a token belongs to normally requires fully parsing the JWT (to read the `iss` claim) before the matching per-issuer `JwtDecoder` can be selected.

`FastIssuerJwtDecoder` optimizes this by caching a mapping from the JWT's header (the raw, unparsed segment before the first `.`) to the issuer it previously resolved to. JWT headers are small and typically contain just `alg` and `kid`, which are effectively static per signing key - so once a header has been seen, subsequent tokens with that same header can jump straight to the right per-issuer decoder (fast path) instead of parsing the whole token just to find the issuer (slow path). Claims and the signature are still fully verified as normal either way; only issuer resolution is short-circuited.

This setting has no effect if only one issuer/tenant is configured.

```yaml
entur:
  jwt:
    decode:
      header:
        map-to-issuer:
          enabled: true # opt-in, default false
          max-size: 100 # default; -1 for unlimited
```

To guard against unexpected entropy in JWT headers (e.g. random/dynamic values that would otherwise grow the cache unbounded), the cache is capped at `max-size` distinct headers; if the cap is exceeded, the optimization is disabled entirely (logged as a warning) rather than left partially populated. Use `max-size: -1` to disable the cap.

By default, only headers with a non-empty `kid` are considered safe to cache (see `DefaultJwtHeaderToIssuerMapperDecider`); provide your own `JwtHeaderToIssuerMapperDecider` bean to customize this.

### Decoded JWT cache
Verifying a JWT's signature on every request has a real CPU cost, especially for PKI-based signatures. The decoded JWT cache avoids repeating that work for tokens that have already been seen and validated.

Intended for services:
 * with a relatively limited set of clients,
 * with a reasonably long JWT time-to-live, and
 * using CPU-intensive signatures / PKI.

Services outside this profile (e.g. many distinct, short-lived clients/tokens, or already-cheap verification such as HMAC) are unlikely to see a meaningful benefit.

Only the decoding/signature verification step is cached - claim validators (audience, expiry etc.) still run on every request, so an expired or otherwise invalid cached token is never served as valid.

A cached token is only used while the JWK set still holds the key(s) it was verified with: on every cache hit, the keys matching the token's header are looked up in the (cached) JWK set, and compared with the keys from when the token was verified. This is a lookup, not a signature verification. So the cache follows the JWK set like decoding without the cache does: a rotated or revoked key is detected as soon as the JWK set is refreshed, and during a JWK set outage cached tokens are accepted for as long as the JWK set is served from the JWK outage cache.

The cache is opt-in per tenant, and requires the JWK set cache (enabled by default; startup fails without it):

```yaml
entur:
  jwt:
    jwk:
      cache:
        enabled: true # default; required for the decoded JWT cache
    tenants:
      myKeycloak:
        decoder-cache:
          enabled: true # opt-in per issuer, default false
          size: 250 # target size; default; -1 for unlimited
          mode: lru # default; what to do when full: lru, fifo or fixed
          cleanup-interval: 60 # seconds; how often expired JWTs are removed; default; must be positive
```

`size` is the target size, i.e. the number of JWTs the cache normally holds at most. In extreme cases (see below) the cache holds up to double the target size.

When the cache holds `size` JWTs, `mode` decides what happens to new JWTs:

 * `lru` (default): evict the least recently used JWTs, i.e. tokens from clients (pods) which have stopped calling.
 * `fifo`: evict the JWTs which were cached first.
 * `fixed`: do not cache new JWTs until cached JWTs are removed by the cleanup (i.e. expire). A warning is logged when the cache first fills up.

For `lru` and `fifo`, eviction runs on a background thread: once the cache is full, new JWTs are still cached (temporarily exceeding `size`) and eviction is triggered straight away, reducing the cache to 90% of `size`. So the cost of eviction is spread over many cache misses, and neither cache hits nor misses wait for it. Should eviction not keep up, new JWTs are not cached once the cache holds double the target size. With `fixed`, the cache does not grow beyond `size` (approximately: concurrent additions might overshoot by a few JWTs). A `size` of 0 disables the cache.

Eviction and the removal of expired JWTs run on a single background thread, shared by the caches of all tenants. Removing expired JWTs only checks their expiry (`exp` claim), it does not run the claim validators. JWTs without expiry are not cached.

With more than one tenant, also enable [header-to-issuer mapping](#header-to-issuer-mapping), as otherwise every JWT, cached or not, is first parsed to read its issuer (`iss` claim) before the tenant's cache is consulted.

[jwt-spring-web]: spring/jwt-spring-web
[jwt-spring-webflux]: spring/jwt-spring-webflux
[jwt-test]: ../jwt-test
[jwt-junit5-spring]: ../jwt-test/jwt-junit5-spring
[method access-control expressions]: [https://www.baeldung.com/spring-security-method-security](https://www.baeldung.com/spring-security-method-security)
[spring]: spring

