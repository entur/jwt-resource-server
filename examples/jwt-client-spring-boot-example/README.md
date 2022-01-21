
# jwt-client-spring-boot-example

This repository contains a demo application showing how to use the `jwt-client-spring`, with three approaches to mocking:

 * Mock remote server using `MockRestServiceServer`
 * Mock using regular Spring bean
 * Mock using `@MockBean`
 
Actually making calls using JWTs is not covered, but would go something like first wiring

```
@Autowired
private AccessTokenProvider tokenService;
```

then later, when making a call, adding the appropriate header:

```
headers.put("Authorization", "Bearer " + tokenService.getAccessToken(false).getValue());
```

Running as standalone (non-test) requires additional configuration.
