


[![Build Status](https://travis-ci.org/entur/jwt-resource-server.svg?branch=master)](https://travis-ci.org/entur/jwt-resource-server) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=entur_jwt-resource-server&metric=coverage)](https://sonarcloud.io/dashboard?id=entur_jwt-resource-server) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=entur_jwt-resource-server&metric=alert_status)](https://sonarcloud.io/dashboard?id=entur_jwt-resource-server)

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

 - 1.1.x: gRPC, eager caching, new health check tweaks
 - 1.0.x: Initial release and adjustments for first use. 

[jwk]:                    jwt-server/jwk
[jwt-verifier]:           jwt-server/jwk-verifier
[jwt-server]:             jwt-server
[jwt-client]:             jwt-client
[jwt-test]:               jwt-test
[java-jwt]:               https://github.com/auth0/java-jwt
[examples]:               examples

