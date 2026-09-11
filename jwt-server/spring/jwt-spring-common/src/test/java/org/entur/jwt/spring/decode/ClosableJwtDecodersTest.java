package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

public class ClosableJwtDecodersTest {

    @Test
    public void testGetJwtDecodersReturnsSameMap() {
        Map<String, JwtDecoder> decoders = Map.of("https://issuer-a", mock(JwtDecoder.class));
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(decoders);

        assertThat(closableJwtDecoders.getJwtDecoders()).isSameAs(decoders);
    }

    @Test
    public void testCloseClosesOnlyCloseableDecoders() throws Exception {
        JwtDecoder plainDecoder = mock(JwtDecoder.class);
        CloseableJwtDecoder closeableDecoder = mock(CloseableJwtDecoder.class, withSettings().extraInterfaces(AutoCloseable.class));

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of(
                "https://issuer-a", plainDecoder,
                "https://issuer-b", (JwtDecoder) closeableDecoder
        ));

        closableJwtDecoders.close();

        verify((AutoCloseable) closeableDecoder, times(1)).close();
        // plain decoder has no close method to verify, but ensure no exception thrown for it
    }

    @Test
    public void testCloseIsNoOpForEmptyMap() {
        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of());

        assertThatCode(closableJwtDecoders::close).doesNotThrowAnyException();
    }

    @Test
    public void testClosePropagatesExceptionFromUnderlyingDecoder() throws Exception {
        CloseableJwtDecoder closeableDecoder = mock(CloseableJwtDecoder.class, withSettings().extraInterfaces(AutoCloseable.class));
        org.mockito.Mockito.doThrow(new IllegalStateException("boom")).when((AutoCloseable) closeableDecoder).close();

        ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecoders(Map.of("https://issuer-a", (JwtDecoder) closeableDecoder));

        assertThatThrownBy(closableJwtDecoders::close)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("boom");
    }

    private interface CloseableJwtDecoder extends JwtDecoder {
    }
}
