
# jwt-test
[JUnit 5] support for working with Json Web Tokens.

Features:

 * annotation-based `@AuthorizationServer` configuration
 * annotation-based injection of `@AccessToken` strings in test methods

The library does __no traditional mocking__ (i.e. not using [Mockito]), it instead creates certificates and supplies the necessary resources / configuration hooks for verification of the test tokens it issues. 

## Usage
Use `@AuthorizationServer` and `@AccessToken` annotations to configure one or more tenants:

```java
@AuthorizationServer
public class AuthorizationServerTest {

    @Test
    public void myTest(@AccessToken String token) {
        // call your backend using the token
    }
}
```

Tokens can be adjusted by using additional annotations, for example

```java
@Test
public void myTest(@AccessToken @NumberClaim(name="https://my.organisation", value=1) String token) {
    // ..
}
```

Tokens are always signed using the authorization server's RSA key, which is published in the JSON Web Keys with algorithm `RS256`. The `@AlgorithmHeader` annotation only changes the `alg` header, so when tokens are validated by the resource server modules of this project (which require the algorithm of the key to match the header):

 * `RS256` (the default) tokens are accepted.
 * `RS384`, `RS512`, `PS256`, `PS384` and `PS512` tokens are signed, but rejected.
 * Other algorithms (`ES256`, `HS256`, `EdDSA`, `none` and so on) are not supported; creating the token fails.

Note that the `@AuthorizationServer` annotation must run be before other annotations which are responsible for bootstrapping the application; in other words this annotation should usually be the first (highest) annotation on the test class.

See [jwt-junit5-entur] for Entur-specific `@AccessToken` annotations like `PartnerAuth0Token`.

## Multi-tenant support
Add an `key` to identify the servers

```java
@AuthorizationServer("myKeycloak")
@AuthorizationServer("myAuth0")
```

then specify the correct source in the method signature annotation:

```java
@Test
public void testMyId(@AccessToken(by="myAuth0") String token) {
	// ..
}
```

## Spring Boot
Add [jwt-junit5-spring] for Spring Boot test support. 

Example unit test:

```java
@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class GreetingControllerTest {

    @LocalServerPort
    private int port;

    @Test
    public void testProtectedEndpoint(@AccessToken(audience = "https://my.audience") String token) {
        given()
           .port(port)
           .log().all()
         .when()
            .header("Authorization", token)
            .get("/protected")
         .then()
            .log().all()
            .assertThat().statusCode(HttpStatus.OK.value());
    }
}
```

Note that the `@AuthorizationServer` must come before `@SpringBootTest`.

## Customizing `@AccessToken`

### Details
The `@AuthorizationServer` and `@AccessToken` can (and perhaps should) be detailed to fit your specific needs. The annotations support custom encoding via `AccessTokenEncoder` and `AuthorizationServerEncoder`. 

For example creating the following access-token type
```
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Inherited
@AccessToken(
    audience = "my.domain.org.audience",
    encoder = MyAccessTokenEncoder.class
)
public @interface MyAccessToken {
    public long myId();
}
```

will allow for writing unit tests like

```java
@Test
public void testMyId(@MyAccessToken(myId = 5) String token) {
    // ..
}
```

## Implementing framework support
In order to configure specific token validation backends, a `ServiceLoader` is used to look up instances of `ResourceServerConfigurationEnricher` and `ResourceServerConfigurationResolver`. These should configure your application framework, for example by outputting a properties file which is read during application test bootstrap. 

Implementations included in this library:

 * [jwt-junit5-spring]

[jwt-junit5-spring]: ../jwt-junit5-spring
[jwt-junit5-entur]: ../jwt-junit5-entur
[JUnit 5]: https://junit.org/junit5/
[Mockito]: https://site.mockito.org/
