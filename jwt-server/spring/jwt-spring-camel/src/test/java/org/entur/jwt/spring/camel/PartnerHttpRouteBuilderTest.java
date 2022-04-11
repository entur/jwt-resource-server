/*
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 *   https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 *
 */

package org.entur.jwt.spring.camel;

import org.apache.camel.model.ModelCamelContext;
import org.apache.camel.test.spring.junit5.CamelSpringBootTest;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0AuthorizationServer;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

import java.net.URI;

import static io.restassured.RestAssured.given;

@PartnerAuth0AuthorizationServer
@CamelSpringBootTest
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class PartnerHttpRouteBuilderTest {

    @LocalServerPort
    public int port;

    @Autowired
    protected ModelCamelContext context;

    @Test
    public void testPartnerRouteWithPartnerToken(@PartnerAuth0Token(organisationId = 1) String token) throws Exception {
        context.start();

        URI uri = new URI("http://localhost:" + port + "/camel/myPath/myCodeSpace");

        given().header("Authorization", token).log().all().when().get(uri).then().log().all().assertThat().statusCode(200);
    }

    @Test
    public void testPartnerRouteWithoutToken() throws Exception {
        context.start();

        URI uri = new URI("http://localhost:" + port + "/camel/myPath/myCodeSpace");

        given().log().all().when().get(uri).then().log().all().assertThat().statusCode(401);
    }
}