package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class OutageCachedJwksProviderTest extends AbstractDelegateProviderTest {

    private OutageCachedJwksProvider<JwkImpl> provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new OutageCachedJwksProvider<>(delegate, Duration.ofHours(10));
    }

    @Test
    public void shouldUseDelegate() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks);
        assertThat(provider.getJwks(false), equalTo(jwks));
    }

    @Test
    public void shouldUseDelegateWhenCached() throws Exception {
        List<JwkImpl> last = Arrays.asList(jwk, jwk);

        when(delegate.getJwks(false)).thenReturn(jwks).thenReturn(last);
        assertThat(provider.getJwks(false), equalTo(jwks));
        assertThat(provider.getJwks(false), equalTo(last));
    }

    @Test
    public void shouldUseCacheWhenDelegateSigningKeyUnavailable() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwksUnavailableException("TEST", null));
        provider.getJwks(false);
        assertThat(provider.getJwks(false), equalTo(jwks));
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldNotUseExpiredCacheWhenDelegateSigningKeyUnavailable() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwksUnavailableException("TEST", null));
        provider.getJwks(false);

        assertThrows(JwksUnavailableException.class, () -> {
            provider.getJwks(provider.getExpires(System.currentTimeMillis() + 1), false);
        });
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider(), equalTo(delegate));
    }
}
