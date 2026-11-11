# Migrating from 7.x to 8.0.0

Version 8.0.0 removes code deprecated in 7.2.x and fixes several unsafe defaults. Spring Boot stays at 4.1.x. See also the [CHANGELOG](../../CHANGELOG.md).

Pick the guides which match how your application uses the library:

| | Properties only | Programmatic |
|---|---|---|
| **Server** (`jwt-server`: web, WebFlux, gRPC) | [server-properties.md](server-properties.md) | [server-programmatic.md](server-programmatic.md) |
| **Client** (`jwt-client`: generic, Auth0, Keycloak) | [client-properties.md](client-properties.md) | [client-programmatic.md](client-programmatic.md) |

 * *Properties only*: the application is configured with `application.yml` / `application.properties` and does not define beans or call library classes itself.
 * *Programmatic*: the application defines beans, builders or subclasses of library classes. Read the properties guide as well; the properties guide covers everything visible without code.

Tests using `jwt-test` (non-Spring and Spring): [test.md](test.md).

## Startup failures
A server application fails at startup until each of these is fixed. See [server-properties.md](server-properties.md#startup-fails-unless-you-change-the-properties) and [server-programmatic.md](server-programmatic.md):

 * `entur.jwt.claims.audiences` is missing.
 * There is a `JwtDecoder` bean, including the one Spring Boot creates from `spring.security.oauth2.resourceserver.jwt.*`.
 * Two enabled tenants have the same issuer.
 * An MDC mapping has no `from` or `to`.
 * gRPC: Spring Boot enables servlet gRPC.
 * WebFlux: the application defines its own `SecurityWebFilterChain` bean.

Client applications get no new startup failures.

## Access changes without an error
These changes do not fail at startup, but change who can call your application:

 * `jwt-client-spring` no longer brings in Spring Security. A servlet application which got Spring Boot's default security only through it is now open. See [client-properties.md](client-properties.md#dependencies-spring-security-is-no-longer-included).
 * gRPC with `entur.jwt.enabled=false`: methods which are not permit-all are now rejected with `UNAUTHENTICATED`.
 * gRPC with `entur.authorization.enabled=false`: all methods are now open to anonymous callers.
 * gRPC permit-all entries with the same service name are now merged.

See [server-properties.md](server-properties.md#grpc-access-with-jwt-or-authorization-disabled) for the gRPC changes.
