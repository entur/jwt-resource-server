package org.entur.jwt.spring.grpc;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

import java.io.File;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 
 * Rename the jwk file so that it first cannot be found, check that service responses are as expected.
 * 
 */

@AuthorizationServer("unreliable")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)

@TestPropertySource(properties = {
        "management.endpoint.health.probes.enabled=true",
        "management.endpoint.health.group.readiness.include=jwks",}
)
public class AuthorizationServerDownWithOutageFallbackTest extends AbstractGrpcTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Value("${entur.jwt.tenants.unreliable.jwk.location}")
    private String jwkLocation;

    @Autowired
    private ListJwksHealthIndicator listJwksHealthIndicator;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    public void hide() {
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkFile.renameTo(jwkRenameFile));
    }

    public void show() {
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkRenameFile.renameTo(jwkFile));
    }

    @Test 
    public void testProtectedResource(@AccessToken(audience = "https://my.audience") String header) throws KeySourceException, InterruptedException {
        GreetingResponse greetingResponse = stub(header).protectedWithPartnerTenant(greetingRequest);

        Health health = listJwksHealthIndicator.health();
        assertThat(health.getStatus().getCode()).isEqualTo("UP");

        hide();

        Map<String, JWKSource<?>> jwkSources = jwkSourceMap.getJwkSources();

        for (Map.Entry<String, JWKSource<?>> entry : jwkSources.entrySet()) {
            JWKSource<?> value = entry.getValue();

            JWKMatcher mock = Mockito.mock(JWKMatcher.class);
            value.get(new JWKSelector(mock), null);

            if(value instanceof JWKSetBasedJWKSource<?> jwkSetBasedJWKSource) {
                JWKSetSource<?> jwkSetSource = jwkSetBasedJWKSource.getJWKSetSource();
                //jwkSetSource.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis() + 10 * 60 * 60 * 1000 - 20, null);


                if(jwkSetSource instanceof RefreshAheadCachingJWKSetSource<?> r) {
                    r.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis() + r.getTimeToLive() - 25, null);
                }

            }
        }

        Thread.sleep(1000);

        Health healthAfter = listJwksHealthIndicator.health();
        assertThat(healthAfter.getStatus().getCode()).isEqualTo("UP");



    }

}