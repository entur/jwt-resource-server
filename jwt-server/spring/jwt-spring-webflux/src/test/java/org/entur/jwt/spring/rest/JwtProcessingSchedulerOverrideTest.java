package org.entur.jwt.spring.rest;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static com.google.common.truth.Truth.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Test that the keys are looked up on a custom {@code jwtProcessingScheduler} bean, through the auto-configured filter chain.
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
public class JwtProcessingSchedulerOverrideTest {

    private static final List<String> LOOKUP_THREADS = new CopyOnWriteArrayList<>();

    @TestConfiguration
    static class SchedulerConfiguration {

        @Bean(destroyMethod = "dispose", defaultCandidate = false)
        public Scheduler jwtProcessingScheduler() {
            return Schedulers.newBoundedElastic(1, 10, "custom-jwt-processing", 60, true);
        }

        // record the threads which look up the keys
        @Bean
        public static BeanPostProcessor recordingJwkSourceMap() {
            return new BeanPostProcessor() {
                @Override
                @SuppressWarnings({"rawtypes", "unchecked"})
                public Object postProcessAfterInitialization(Object bean, String beanName) {
                    if (bean instanceof JwkSourceMap jwkSourceMap) {
                        Map<String, JWKSource<SecurityContext>> jwkSources = new HashMap<>();
                        for (Map.Entry<String, JWKSource<SecurityContext>> entry : ((Map<String, JWKSource<SecurityContext>>) jwkSourceMap.getJwkSources()).entrySet()) {
                            JWKSource<SecurityContext> jwkSource = entry.getValue();
                            jwkSources.put(entry.getKey(), (selector, context) -> {
                                LOOKUP_THREADS.add(Thread.currentThread().getName());
                                return jwkSource.get(selector, context);
                            });
                        }
                        return new JwkSourceMap<>(jwkSources, jwkSourceMap.getJwkEventListeners()) {
                            @Override
                            public void close() throws IOException {
                                jwkSourceMap.close();
                            }
                        };
                    }
                    return bean;
                }
            };
        }
    }

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testLooksUpKeysOnCustomScheduler(@AccessToken(audience = "mock.my.audience") String token) {
        webTestClient
            .get()
            .uri("/protected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful();

        assertThat(LOOKUP_THREADS).isNotEmpty();
        for (String thread : LOOKUP_THREADS) {
            assertThat(thread).startsWith("custom-jwt-processing");
        }
    }
}
