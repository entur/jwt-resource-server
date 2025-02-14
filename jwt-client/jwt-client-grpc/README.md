# jwt-client-grpc
Some helper classes for use of gRPC:

### Force refresh token on UNAUTHENTICATED response:
Primarily intended to handle key rotation where the old keys are instantly revoked (i.e. no longer part of the JWKs). 

While it might be possible to check the current token against the JWKs, there might be other reasons for UNAUTHENTICATED, 
i.e. bugs/misconfiguration in the resources-servers and/or authorization-servers. So refreshing is the catch-all approach.
  
Refreshes are rate-limited to avoid saturating the authorization server. 

Note: There is no retry of the failing calls, just refresh of the token to avoid additional failing calls; In the case of JWK rotation, 
calls would otherwise fail until the JWT is refreshed due to time expiry. 

## Maven / Gradle coordinates

Maven coordinates:

```xml
<dependency>
    <groupId>org.entur.jwt-rs</groupId>
    <artifactId>jwt-client-grpc</artifactId>
    <version>${jwt-rs.version}</version>
</dependency>
```

Gradle coordinates:

```groovy
api("org.entur.jwt-rs:jwt-client-grpc:${jwtResourceServerVersion}")
```
