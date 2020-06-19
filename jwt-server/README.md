# jwt-server
Validation of JSON Web tokens on resource servers. Components:

 * [jwk] - Makes JSON Web Keys published by the Authorization Server *'almost always'* available to higher-level frameworks. These are used to verify JSON Web Token signatures.
 * [jwt-verifier] - Verification of JSON Web Tokens tokens using JSON Web Keys. 
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

Claim validation (common for all tenants) can also be added:

 * audiences
 * expires-at leeway
 * issued-at leeway
 * and more
 
For YAML, this amounts to something like

```yaml
entur:
  jwt:
    enabled: true
    tenants:
      myKeycloak: # i.e. tenant id
        issuer: https://myRealm.keycloak.com
        jwk: 
          location: https://my.keycloak.com/auth/realms/myRealm/protocol/openid-connect/certs
    claims:
      expires-at-leeway: 15
      issued-at-leeway: 5
      audiences: # at least one
        - https://my.audience
```

A tenant id-filter can be used to conveniently enable/disable specific tenants. Using this filter could also simplify sharing configuration, for example using a ConfigMap in Kubernetes.

```
entur:
  jwt:
    filter:
      - partner-auth0
```

## Security configuration
By default, all requests must be so-called _fully authenticated_. In other words all requests must have a valid JWT token (of any of the configured tenants). 

Open endpoints (i.e. permitted for all, open to the world) must be explicitly configured using MVC or Ant matchers:

```yaml
entur:
  authorization:
    permit-all:
      ant-matcher:
        patterns:
         - /unprotected/**
      mvc-matcher:
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
      mvc-matcher:
        method:
          get:
            patterns:
             - /some/path/{myVariable}
```

MVC matchers are in general __broader than Ant matchers__:

 * antMatchers("/unprotected") matches only the exact `/unprotected` URL
 * mvcMatchers("/unprotected") matches `/unprotected` as well as `/unprotected/`, `/unprotected.html`, `/unprotected.xyz`

#### Actuator
To expose [actuator endpoints](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-features.html), add

```yaml
entur:
  jwt:
    authorization:
      permit-all:
        ant-matcher:
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
    public void test(@AccessToken String token) throws IOException {
        // set token in Autorization header and invoke calls
    }
}
```

The `@AuthorizationServer` test extention spawns/overwrites the tenant JWK location with a local file URL.

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
 * block at most 15 seconds for cache refresh before failing
 * instantly retry once to capture transient IOExceptions
 * keep cache at most 10 hours, should cache refresh fail (i.e. outage)
 * limit refreshes (triggered by unknown signature keys) to at most 1 per 10 seconds
 * Spring [HealthIndicator](https://docs.spring.io/spring-boot/docs/current/api/org/springframework/boot/actuate/health/HealthIndicator.html) enabled

This corresponds to the following configuration:

```yaml
entur:
    jwt:
        jwk:
            cache:
              enabled: true
              time-to-live: 3600 # seconds
              refresh-timeout: 15 # seconds
            retry:
              enabled: true
            outage-cache:
              enabled: true
              time-to-live: 36000 #seconds
            rate-limit: # per tenant
              enabled: true
              bucket-size: 10
              refill-rate: 0.1 # per second
            health-indicator:
              enabled: true
```

#### Key rotation
The authorization server might choose to rotate its keys. When that happens, the key id used to sign the access-tokens changes, and a new key id will be noted in the JWT header. This implementation will promptly refresh the keys and normally be able to instantly verify new tokens. Previously issued tokens will be able to verify if the key list still contains the old key.

#### Health indicator
The health indicator looks at __the last attempt__ to get signing keys. It will trigger a refresh if

 * no previous attempt was made
 * last attempt was unsuccessful

In other words, the health check will not refresh expired keys, but repeated calls to the health-check __will result in a positive result once downstream services are back up__. As a positive side-effect, on startup, calling the health-check before opening for traffic will result in the cache being populated (read: warmed up).

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
```

where `xyz` is from the following list

* `api` - CORS requests from selected sites. Recommended exceptions:
   * Your API development portal 
   * Petstore
* `webapp` - no CORS requests are accepted 

If no mode is set, no configuration is added by this starter. This allows for adding your own custom implementation.

```java
@Bean("corsConfigurationSource")
public CorsConfigurationSource myCorsConfigurationSource() {
    // ...
} 
```

Note that the bean name must be as above in order for Spring to pick up the bean. 

#### CORS and API gateway
In general, the API gateway should respond with HTTP 403 to requests with unknown origins. All other requests, including OPTIONS calls, can be sent backwards to the Spring application.

### Implementing framework support
The core implementation expects a few beans to be present:

 * JwtVerifierFactory - JwtVerifier factory
 * JwtClaimExtractor - JWT claim extractor for log context (MDC) support and authorization detailing.
 * JwtAuthorityMapper - mapping from JWT (scope, permissions, etc) to authority
 * JwtArgumentResolver - argument resolver support. Transforms the JwtAuthenticationToken to an object of your desire for injection in downstream method arguments.

See [jwt-spring-auth0] for a concrete implementation example.

[jwt-spring-auth0]: spring/jwt-spring-auth0
[jwt-test]: ../jwt-test
[jwt-junit5-spring]: ../jwt-test/jwt-junit5-spring
[method access-control expressions]: [https://www.baeldung.com/spring-security-method-security](https://www.baeldung.com/spring-security-method-security)
[jwk]: jwk
[jwt-verifier]: jwt-verifier
[spring]: spring

