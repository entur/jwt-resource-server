# jwt-resource-server-spring-boot-grpc-web-example

Demo application with both REST and gRPC endpoints, using `jwt-spring-web` and `jwt-spring-grpc-native` together:

  * Spring [REST controller](src/main/java/org/entur/jwt/spring/demo/GreetingController.java)
      * `/unprotected` - no authentication required
      * `/protected` - checks that fully authenticated
  * Spring [gRPC service](src/main/java/org/entur/jwt/spring/demo/GreetingGrpcService.java) ([proto](src/main/protobuf/greeting.proto))
      * `unprotected` - no authentication required (see `entur.authorization.permit-all.grpc` in [application.yaml](src/main/resources/application.yaml))
      * `protectedGreeting` - requires a valid token
  * One set of JWT decoders shared by REST and gRPC, so the (opt-in) decoded JWT cache holds each token once

If you have questions to how to use this starter then take a look at this [README](../../jwt-server/README.md).

Running as standalone (non-test) requires additional configuration (i.e. tenants).

## Contents

**GreetingControllerTest**

```
REST endpoints with and without a valid token.
```

**GreetingGrpcServiceTest**

```
gRPC methods with and without a valid token.
```

**ActuatorTest**

```
Health probes do not require a token.
```

**SharedJwtDecoderCacheTest**

```
REST and gRPC share the JWT decoders, so a token used for both is cached (verified) once.
```
