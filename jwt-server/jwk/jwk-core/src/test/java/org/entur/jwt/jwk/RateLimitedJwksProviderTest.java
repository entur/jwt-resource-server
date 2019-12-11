package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.bucket4j.Bucket;

public class RateLimitedJwksProviderTest extends AbstractDelegateProviderTest {

    private RateLimitedJwksProvider<JwkImpl> provider;

    private Bucket bucket;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        bucket = mock(Bucket.class);
        provider = new RateLimitedJwksProvider<>(delegate, bucket);
    }

    @Test
    public void shouldFailToGetWhenBucketIsEmpty() throws Exception {
        when(bucket.tryConsume(1)).thenReturn(false);
        assertThrows(RateLimitReachedException.class, () -> {
            provider.getJwks(false);
        });
    }

    @Test
    public void shouldGetWhenBucketHasTokensAvailable() throws Exception {
        when(bucket.tryConsume(1)).thenReturn(true);
        when(delegate.getJwks(false)).thenReturn(jwks);
        assertThat(provider.getJwks(false), equalTo(jwks));
        verify(delegate).getJwks(false);
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider(), equalTo(delegate));
    }

}
