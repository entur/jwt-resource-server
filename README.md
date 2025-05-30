[![Maven Central](https://img.shields.io/maven-central/v/org.entur.jwt-rs/parent.svg)](https://mvnrepository.com/artifact/org.entur.jwt-rs)

# jwt-resource-server

Tools for synchronous (servlet-based) __OpenID resource servers__ relying on use of [Access Tokens]([https://auth0.com/docs/tokens/access-tokens](https://auth0.com/docs/tokens/access-tokens)) for authorization. These come in the form of JSON Web Tokens (JWT) issued by Authorization Servers like Auth0 and Keycloak. Authorization Servers __sign JWTs__ with private keys, resource servers then download the corresponding public keys from the Authorization Servers and __validate the JWTs__ by verifying the signature.

## Primer
Technically, this library deals with HTTP requests using the __Authorization__ header. Example HTTP request:

``` 
GET /some/restricted/service/1
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsI.eyJzdWIIjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpM
```
where the __Base64-encoded value__ is the token itself. For a valid token, the server could process the request and respond:

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 1024
```

Alternatively, the server might return __HTTP 401 Unauthorized__ if the token was not accepted, or __HTTP 403 Forbidden__ if the token did not contain the enough permissions. 

## Overview
Users of this library will benefit from:

 * Robust multi-tenant JWT [access-token validation](jwt-server)
 * Robust JWT [access-token client](jwt-client)
 * Flexible JWT [JUnit 5 test-support](jwt-test)
 * [Spring Boot support](jwt-server) for the above

In order to keep complexity (and risk) down, the library wraps existing third party libraries for low-level parsing, signature validation and authorization enforcement. Notable features:

 * thread-safe sharing of keys (for signature verification) and access-tokens within each JVM
 * proactive background refresh of keys and tokens
 * keys and token health status (on last remote invocation)
 * annotation-based token mocking with test method signature argument support
 * open/closed endpoint filter, so that requests to closed endpoints can be proactively rejected before payload is unmarshalled

Async is not yet supported.

## Project structure

 * [jwt-server] - for handling incoming service calls (i.e. in your backend)
 * [jwt-client] - for making outgoing service calls (i.e. support for obtaining a token first)
 * [jwt-test] - JUnit 5 test support.
 * [examples] - Example projects.

See documentation contained in each folder to get started. Or skip right to the [examples](examples). 

# License
[European Union Public Licence v1.2](https://eupl.eu/).

# History
 - 5.1.0: Spring Boot 3.4.x + remove Lognet gRPC 
 - 5.0.4: Adjust gRPC anonymous access so that PERMISSION_DENIED is converted to UNAUTHENTICATED in more cases. Reject non-whitelisted anonymous access earlier. 
 - 5.0.3: Add support for refreshing access-tokens for clients which see unauthenticated responses. 
   - Added a gRPC module with an interceptor support for the above.
 - 5.0.2: Add Spring properties annotation processor for more friendly property configuration.
 - 5.0.1: Support for [gRPC Ecosystem](https://github.com/grpc-ecosystem). [Lognet gRPC](https://github.com/LogNet/grpc-spring-boot-starter) is now deprecated.
 - 4.2.7: Bump dependencies
 - 4.2.6: Adjust dependencies to better align with Spring Boot version
 - 4.2.5: Bump dependencies, now at Spring Boot 3.3. 
 - 4.2.4: Change log level for permission denied and authorization exceptions to INFO. `StatusRuntimeException` with `INTERNAL` status logs as ERROR, otherwise INFO.
 - 4.2.3: Allow authorization matcher to specify `ant` type. 
 - 4.2.2: Bump dependencies
 - 4.2.0 to 4.2.1: Refresh health indicators in the background, add even more logging. 
 - 4.1.7: Adjust health indicator logging.
 - 4.1.6: Adjust health indicator timeout when multiple JWK sources + bump dependencies. 
 - 4.1.5: Add event listener to JWKs rate limiter, remove unused property. 
 - 4.1.4: Improve client builder empty string checks
 - 4.1.2: Improve logging of JWK events, bump dependencies.
 - 4.1.1: Improve gRPC exception handling configuration.
 - 4.1.0: The JWT `scope` (or `scp`) claim will now be converted to `GrantedAuthority` using the default Spring approach of prefixing with `SCOPE_`. Add a bean `NoopJwtAuthorityEnricher` to disable scope being converted to authorities all together.
 - 4.0.1: Dependency updates
 - 4.0.0: Adjust gRPC MDC handling + enrich gRPC authentication from Auth0/Keycloak access token
 - 3.1.0: Support for a `generic` JWT client type (by [viliket](https://github.com/viliket))
 - 3.0.x: Spring Boot 3 support
   - `Auth0` artifacts replaced by Spring OAuth equivalents 
   - Takes advantage of [latest Nimbus Jose JWKs handling](https://connect2id.com/products/nimbus-jose-jwt/examples/enhanced-jwk-retrieval).
 - 2.0.5-2.0.6: Ignore cookies as Apache did not accept the ones returned from Auth0 due to use of custom domain + bump dependencies
 - 2.0.2-2.0.4: Maintenance release
 - 2.0.0: Splits up the artifacts of web mvc (web) and reactive (webflux), respectively. Therefore, there are major renaming in some artifacts. For instance, if you are implementing `jwt-spring-auth0`, you should rename this to `jwt-spring-auth0-web`. 
 - 1.1.13: Support for WebClient (used in a synchronous way) in new `jwt-client-spring-cloud` artifact.
 - 1.1.x: gRPC, eager caching, new health check tweaks
 - 1.0.x: Initial release and adjustments for first use. 

[jwk]:                    jwt-server/jwk
[jwt-verifier]:           jwt-server/jwk-verifier
[jwt-server]:             jwt-server
[jwt-client]:             jwt-client
[jwt-test]:               jwt-test
[java-jwt]:               https://github.com/auth0/java-jwt
[examples]:               examples

