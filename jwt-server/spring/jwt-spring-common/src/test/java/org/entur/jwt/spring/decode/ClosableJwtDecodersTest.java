package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ClosableJwtDecodersTest {

    private static final JwtDecoder PLAIN_DECODER = token -> {
        throw new IllegalStateException("Not used");
    };

    // a decoder which can be closed, i.e. like the decoded JWT cache decoder
    private static class CloseableJwtDecoder implements JwtDecoder, AutoCloseable {

        private final AtomicInteger closed = new AtomicInteger();
        private final RuntimeException closeException;

        CloseableJwtDecoder() {
            this(null);
        }

        CloseableJwtDecoder(RuntimeException closeException) {
            this.closeException = closeException;
        }

        @Override
        public Jwt decode(String token) {
            throw new IllegalStateException("Not used");
        }

        @Override
        public void close() {
            closed.incrementAndGet();
            if (closeException != null) {
                throw closeException;
            }
        }
    }

    @Test
    public void testGetJwtDecodersReturnsSameMap() {
        Map<String, JwtDecoder> decoders = Map.of("https://issuer-a", PLAIN_DECODER);
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(decoders);

        assertThat(closableJwtDecoders.getJwtDecoders()).isSameAs(decoders);
    }

    @Test
    public void testCloseClosesOnlyCloseableDecoders() throws Exception {
        CloseableJwtDecoder closeableDecoder = new CloseableJwtDecoder();

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of(
                "https://issuer-a", PLAIN_DECODER,
                "https://issuer-b", closeableDecoder
        ));

        closableJwtDecoders.close();

        assertThat(closeableDecoder.closed.get()).isEqualTo(1);
    }

    @Test
    public void testCloseIsNoOpForEmptyMap() {
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of());

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();
    }

    @Test
    public void testClosePropagatesExceptionFromUnderlyingDecoder() {
        CloseableJwtDecoder closeableDecoder = new CloseableJwtDecoder(new IllegalStateException("boom"));

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of("https://issuer-a", closeableDecoder));

        assertThatThrownBy(closableJwtDecoders::close)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("boom");
    }
}
