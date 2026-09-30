package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The decoded JWT cache is not supported for webflux; verify that enabling it is not silently ignored.
 */
@AuthorizationServer("a")
@ExtendWith({OutputCaptureExtension.class, SpringExtension.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
})
@DirtiesContext
public class DecoderCacheNotSupportedWarningTest {

    @Test
    public void testWarnsThatDecoderCacheIsNotSupported(CapturedOutput output) {
        assertThat(output.getAll()).contains("Tenant 'a' has decoder-cache.enabled=true, but the decoded JWT cache is not supported for webflux");
    }
}
