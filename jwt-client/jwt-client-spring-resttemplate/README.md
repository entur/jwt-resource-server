# jwt-client-spring-resttemplate
Spring Boot starter for jwt-client with legacy RestTemplate. The client creates its own `RestTemplate` for performing external calls.

See [Auth0SingleClientTest] for a mocking example.

## Maven / Gradle coordinates
Maven coordinates:

```xml
<dependency>
    <groupId>org.entur.jwt-rs</groupId>
    <artifactId>jwt-client-spring-resttemplate</artifactId>
    <version>${jwt-rs.version}</version>
</dependency>
```

Gradle coordinates:

```groovy
api("org.entur.jwt-rs:jwt-client-spring-resttemplate:${jwtResourceServerVersion}")
```

[Auth0SingleClientTest]: src/test/java/org/entur/jwt/client/spring/Auth0SingleClientTest.java
