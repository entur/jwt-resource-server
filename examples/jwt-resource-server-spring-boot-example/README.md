
# jwt-resource-server-spring-boot-example

This repository contains a demo application showing how to use the `jwt-spring-auth0` and `jwt-spring-test`:

  * Classic [Spring REST controller](src/main/java/org/entur/jwt/spring/demo/GreetingController.java)
  * YAML configuration
  * Protected and unprotected endpoints
      * `/unprotected` - no authentication required
      * `/protected` - checks that fully authenticated
      * `/protected/withArgument` - with JWT injected in method signature
      * `/protected/withPermission` - with permission check (detailed access control)
  * [Units tests](src/test/java/org/entur/jwt/spring/demo/GreetingControllerTest.java) with mock tokens
      * tokens created via test method injection

If you have questions to how to use this starter then take a look at this [README](../../jwt-server/README.md).

Running as standalone (non-test) requires additional configuration.

## Contents

**GreetingController**

```
Spring-flavored REST with per-method access-control.
```

**GreetingControllerTest**

```
Tests that verifies that open endpoints are accessible and that secured endpoints require a valid token.
```

**ActuatorTest**
```
Test health status (includes contribution from this library as of whether JWK are available or not).
```

