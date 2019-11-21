
# jwt-test
[JUnit 5] support for working with Json Web Tokens.

Features:

 * annotation-based `@AuthorizationServer` configuration
 * annotation-based injection of `@AccessToken` strings in test methods

The library does __no traditional mocking__ (i.e. not using [Mockito]), it instead creates certificates and supplies the necessary resources / configuration hooks for verification of the test tokens it issues. 

## Usage
Use `@AuthorizationServer` and `@AccessToken` annotations to configure one or more tenants:

```
@AuthorizationServer
public class AuthorizationServerTest {

    @Test
    public void myTest(@AccessToken String token) {
        // call your backend using the token
    }
}
```

Tokens can be adjusted by using additional annotations, for example

```
@Test
public void myTest(@AccessToken @NumberClaim(name="https://my.organisation", value=1) String token) {
    // ..
}
```

Note that the `@AuthorizationServer` annotation must run be before other annotations which are responsible for bootstrapping the application; in other words this annotation should usually be the first (highest) annotation on the test class.

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

```
@Test
public void testMyId(@MyAccessToken(myId = 5) String token) {
    // ..
}
```

## Multi-tenant support
Add an `key` to identify the servers

```
@AuthorizationServer("myKeycloak")
@AuthorizationServer("myAuth0")
```

then specify the correct source in the method signature annotation:

```
@Test
public void testMyId(@AccessToken(by="myAuth0") String token) {
	// ..
}
```


## Implementing framework support
In order to configure specific token validation backends, a `ServiceLoader` is used to look up instances of `ResourceServerConfigurationEnricher` and `ResourceServerConfigurationResolver`. These should configure your application framework, for example by outputting a properties file which is read during application test bootstrap. 

Implementations included in this library:

 * [jwt-spring-test] for [jwt-spring-auth0]

[jwt-spring-test]: .../jwt-spring/jwt-spring-test
[jwt-spring-auth0]: ../jwt-spring/jwt-spring-auth0
[JUnit 5]: https://junit.org/junit5/
[Mockito]: https://site.mockito.org/
