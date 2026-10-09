package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

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
    public void testCloseClosesResourcesBeforeDecoders() throws Exception {
        List<String> order = new ArrayList<>();
        JwtDecoder decoder = new CloseableJwtDecoder() {
            @Override
            public void close() {
                order.add("decoder");
            }
        };
        AutoCloseable resource = () -> order.add("resource");

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of("https://issuer-a", decoder), List.of(resource));

        closableJwtDecoders.close();

        assertThat(order).containsExactly("resource", "decoder");
    }

    @Test
    public void testCloseIsNoOpForEmptyMap() {
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of());

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();
    }

    @Test
    public void testCloseClosesAllDecodersEvenIfOneThrows() {
        IllegalStateException boomA = new IllegalStateException("boom-a");
        IllegalStateException boomB = new IllegalStateException("boom-b");
        CloseableJwtDecoder failingA = new CloseableJwtDecoder(boomA);
        CloseableJwtDecoder failingB = new CloseableJwtDecoder(boomB);
        CloseableJwtDecoder healthy = new CloseableJwtDecoder();

        // linked map: deterministic close order
        Map<String, JwtDecoder> decoders = new LinkedHashMap<>();
        decoders.put("https://issuer-a", failingA);
        decoders.put("https://issuer-b", healthy);
        decoders.put("https://issuer-c", failingB);
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(decoders);

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();

        assertThat(failingA.closed.get()).isEqualTo(1);
        assertThat(healthy.closed.get()).isEqualTo(1);
        assertThat(failingB.closed.get()).isEqualTo(1);
    }

    @Test
    public void testCloseClosesDecodersEvenIfResourceThrows() {
        IllegalStateException boom = new IllegalStateException("boom");
        AutoCloseable failingResource = () -> {
            throw boom;
        };
        CloseableJwtDecoder decoder = new CloseableJwtDecoder();

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of("https://issuer-a", decoder), List.of(failingResource));

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();
        assertThat(decoder.closed.get()).isEqualTo(1);
    }

    @Test
    public void testCloseSwallowsExceptionFromUnderlyingDecoder() {
        CloseableJwtDecoder closeableDecoder = new CloseableJwtDecoder(new IllegalStateException("boom"));

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of("https://issuer-a", closeableDecoder));

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();
        assertThat(closeableDecoder.closed.get()).isEqualTo(1);
    }
}
