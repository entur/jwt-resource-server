[![Build Status](https://travis-ci.org/entur/jwt-resource-server.svg?branch=master)](https://travis-ci.org/entur/jwt-resource-server)

# jwt-resource-server

> work in progress

Tools for synchronous (servlet-based) OpenID resource servers relying on use of JSON Web Tokens (JWT) issued by Authorization Servers like Auth0 and Keycloak.

Users of this library will benefit from:

 * Robust multi-tenant [access-token validation](jwt-server)
 * Robust [access-token client](jwt-client)
 * Flexible [JUnit 5 test-support](jwt-test)
 * [Spring Boot support](jwt-server) for the above

In order to keep complexity (and risk) down, the library wraps existing third party libraries for low-level parsing, signature validation and authorization enforcement. Notable features:

 * thread-safe sharing of keys and tokens within each JVM
 * proactive background refresh of keys and tokens
 * keys and token health status (on last remote invocation)
 * annotation-based token mocking with test method signature argument support

Async is not yet supported.

## Modules

 * [jwt-server] - Resource-server JSON Web Token validation, including Spring Boot support.
 * [jwt-client] - A client which makes machine-to-machine JSON Web Tokens issued by the Authorization Server *'almost always'* available to resource server consumers in such a way that tokens can be shared between threads.
 * [jwt-test] - Unit test support with JUnit 5.

# License
[European Union Public Licence v1.2](https://eupl.eu/).
 
[jwk]:                    jwt-server/jwk
[jwt-verifier]:           jwt-server/jwk-verifier
[jwt-server]:             jwt-server
[jwt-client]:             jwt-client
[jwt-test]:               jwt-test
[java-jwt]:               https://github.com/auth0/java-jwt

