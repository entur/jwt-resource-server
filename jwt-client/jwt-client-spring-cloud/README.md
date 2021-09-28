# jwt-client-spring
Spring Boot starter for jwt-client. The client creates its own `WebClient` for performing external calls.

See [Auth0SingleClientTest] for a mocking example.

## Maven / Gradle coordinates
Maven coordinates:

```xml
<dependency>
    <groupId>org.entur.jwt-rs</groupId>
    <artifactId>jwt-client-spring-cloud</artifactId>
    <version>${jwt-rs.version}</version>
</dependency>
```

Gradle coordinates:

```groovy
api("org.entur.jwt-rs:jwt-client-spring:${jwtResourceServerVersion}")
```

[Auth0SingleClientTest]: src/test/java/org/entur/jwt/client/springreactive/Auth0SingleClientTest.java
