# jwt-client-spring-webflux
Spring Boot starter for jwt-client. The client creates its own `WebClient` for performing external calls.

As the client is a blocking implementation, use this with the eager option.

## Maven / Gradle coordinates
Maven coordinates:

```xml
<dependency>
    <groupId>org.entur.jwt-rs</groupId>
    <artifactId>jwt-client-spring-webflux</artifactId>
    <version>${jwt-rs.version}</version>
</dependency>
```

Gradle coordinates:

```groovy
api("org.entur.jwt-rs:jwt-client-spring-webflux:${jwtResourceServerVersion}")
```
