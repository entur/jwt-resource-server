package org.entur.jwt.spring.demo;

import static io.restassured.RestAssured.given;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.PermissionEvaluator;

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class PermissionReadTest {

    @MockBean
    private PermissionEvaluator permissionEvaluator;

    @LocalServerPort
    protected int port;

    private List<String> hosts = Arrays.asList(
            "http://localhost:"
    );

    @Test
    public void permission_read_allowed(@AccessToken(audience = "https://my.audience") String token) {
        when(permissionEvaluator.hasPermission(any(),any(),any())).thenReturn(true);

        hosts.forEach(host -> {
            given()
            .when()
                    .log().all()
                    .header("Authorization", token)
                    .get(host + port + "/protected/permission/read")
            .then()
                    .log().all()
            .assertThat()
                    .statusCode(HttpStatus.OK.value());
        });

        verify(permissionEvaluator,times(1)).hasPermission(any(),any(),any());
    }

    @Test
    public void permission_read_not_allowed(@AccessToken(audience = "https://my.audience") String token) {
        when(permissionEvaluator.hasPermission(any(),any(),any())).thenReturn(false);

        hosts.forEach(host -> {
            given()
            .when()
                    .log().all()
                    .header("Authorization", token)
                    .get(host + port + "/protected/permission/read")
            .then()
                    .log().all()
            .assertThat()
                    .statusCode(HttpStatus.FORBIDDEN.value());
        });

        verify(permissionEvaluator,times(1)).hasPermission(any(),any(),any());
    }
}