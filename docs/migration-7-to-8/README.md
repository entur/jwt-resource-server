# Migrating from 7.x to 8.0.0

Version 8.0.0 removes code deprecated in 7.2.x and fixes several unsafe defaults. Spring Boot stays at 4.1.x. See also the [CHANGELOG](../../CHANGELOG.md).

Pick the guides which match how your application uses the library:

| | Properties only | Programmatic |
|---|---|---|
| **Server** (`jwt-server`: web, WebFlux, gRPC) | [server-properties.md](server-properties.md) | [server-programmatic.md](server-programmatic.md) |
| **Client** (`jwt-client`: generic, Auth0, Keycloak) | [client-properties.md](client-properties.md) | [client-programmatic.md](client-programmatic.md) |
| **Test** (`jwt-test`: non-Spring and Spring) | [test.md](test.md) | |

 * *Properties only*: the application is configured with `application.yml` / `application.properties` and does not define beans or call library classes itself.
 * *Programmatic*: the application defines beans, builders or subclasses of library classes. Read the properties guide as well; the properties guide covers everything visible without code.

Most upgrades are blocked by the same three startup failures: missing `entur.jwt.claims.audiences`, a `JwtDecoder` bean (including the one Spring Boot creates from `spring.security.oauth2.resourceserver.jwt.*`), and duplicate tenant issuers. Start with [server-properties.md](server-properties.md).
