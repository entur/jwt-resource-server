# jwt-junit5-entur
Entur-specific JUnit 5 test-support.

Class level annotations (i.e. JUnit5 Extension):

* `PartnerAuth0AuthorizationServer` mock authentication server
    * id `partner-auth0`

Method level annotations:

* `PartnerAuth0Token` - mock access-token
   * Fixed claims: 
        * audience https://auth0.partner.mock.audience
   * Configurable claims:
        * namespace - Auth0 custom claim prefix
        * organisationId - organisasjonsid
        * scopes - scopes claim
        * permission - Auth0-managed permissions

Example of use with `RestAssured`:

```java
@PartnerAuth0AuthorizationServer
public class PartnerAccessTokenTest {

    @LocalServerPort
    private int port;

    @Test
    public void testTokenWithOrganisation(@PartnerAuth0Token(organisationId = 1) String token) throws IOException {
        given()
            .port(port)
            .log().all()
        .when()
            .header("Authorization", token)
            .get("/my/protected/endpoint")
        .then()
            .log().all()
            .assertThat()
            .statusCode(HttpStatus.OK.value());
    }

}
```

With [fine-grained permissions](https://auth0.com/docs/dashboard/guides/apis/add-permissions-apis)

```java
@PartnerAuth0AuthorizationServer
public class PartnerAccessTokenTest {

    @LocalServerPort
    private int port;

    @Test
    public void testTokenWithPermissions(@PartnerAuth0Token(organisationId = 5, permissions = {"configure"}) String token) throws IOException {
        // your code here
    }
}
```

Additional mock tokens for testing:

 * `@ExpiredPartnerAuth0Token` - token which has expired already
 * `@NotYetIssuedPartnerAuth0Token` - token which is not yet issued
 * `@UnknownIssuerPartnerAuth0Token` - token with unknown issuer
 * `@UnknownAudiencePartnerAuth0Token` - token with unknown audience
 * `@InvalidSignaturePartnerAuth0Token` - token with invalid signature
 * `@UnknownKeyIdPartnerAuth0Token` - token with unknown signature key id

## Maven / Gradle coordinates

Maven coordinates:

```xml
<dependency>
    <groupId>org.entur.jwt-rs</groupId>
    <artifactId>jwt-verifier-auth0</artifactId>
    <version>${jwt-junit5-entur}</version>
    <scope>test</scope>
</dependency>
```

Gradle coordinates:

```groovy
api("org.entur.jwt-rs:jwt-junit5-entur:${jwtResourceServerVersion}")
```


