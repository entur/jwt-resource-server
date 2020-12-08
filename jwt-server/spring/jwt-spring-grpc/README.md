# Json Web Token Spring Boot Starter for gRPC
Configure JWT issuers like in the Spring Boot Starter sibling project.

## Usage 

> Servlet containers and Netty use different threading models. So directly applying Spring Security is too risky given the use of the `ThreadLocal` in `SecurityContext`; authorization can be leaked between requests. However with the subset of Spring Security supported in the this library, this is not very important.

The authorization tokens are parsed by a gRPC interceptor and passed in using the gRPC request context. Enforcement of authorization is manual using the utility methods from the `GrpcAuthorization` interface.

### Anonymous access
Anonymous access must be explicitly configured:

```
entur:
  authorization:
    permit-all:
      grpc:
        services:
          - name: org.entur.jwt.spring.grpc.test.GreetingService
            methods:
              - unprotected
              - unprotectedWithOptionalTenant
```

### Logging
If you have added MDC log mappings, 

```
entur:
  jwt:
    mdc:
      enabled: true
      mappings:
      - from: iss
        to: issuer
      - from: azp
        to: azp
```

Use the `GrpcJwtMappedDiagnosticContextMapper` to populate and clear the MDC.

```
GrpcJwtMappedDiagnosticContextMapper.addContext();
try {
    // your log statements here
} finally {
    GrpcJwtMappedDiagnosticContextMapper.removeContext();
}
```

### Example
For a code example, see the ́`GreetingController` example in the test sources. 
