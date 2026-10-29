# Json Web Token Spring Boot Starter for Spring gRPC with Native gRPC server
Configure JWT issuers like in the Spring Boot Starter sibling project.

## Usage 

The authorization tokens are parsed by a gRPC interceptor and passed along using the gRPC request context. Enforce  authorization (manually) using utility methods from the `GrpcAuthorization` interface:

```
requireAllAuthorities("read", "modify");
```

To access the token directly, use

```
JwtAuthenticationToken authentication = getToken();
```

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

### Disabling authorization
Setting `entur.authorization.enabled=false` allows anonymous access to all gRPC methods (the permit-all configuration above is then ignored). Tokens which are present are still validated, so calls with an invalid token are rejected with `UNAUTHENTICATED`. Enforce authorization manually using `GrpcAuthorization` where needed.

```
entur:
  authorization:
    enabled: false
```

Note that this property also applies to the Spring Web / WebFlux modules, if present.

### MDC logging
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

also implement a bean of type `GrpcMdcAdapter`.
