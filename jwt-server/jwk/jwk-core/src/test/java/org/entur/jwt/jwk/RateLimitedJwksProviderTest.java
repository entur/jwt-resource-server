package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.*;

import java.util.Arrays;

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

    @Test
    public void checkIgnoresTransferException() throws InterruptedException, JwksException {
        JwkProvider<Object> build = builder().rateLimited(true).build();

        when(delegate.getJwks(any(Boolean.class))).thenThrow(new JwksTransferException("")).thenReturn(Arrays.asList(mock(JwkImpl.class)));

        // transfer exception should not count against the bucket
        assertThrows(JwksTransferException.class, () -> {
            build.getJwks(true);
        });

        // should be able to get the list 10 times
        for(int i = 0; i < 10; i++) {
            build.getJwks(true);
        }

        // but then the bucket is empty
        assertThrows(RateLimitReachedException.class, () -> {
            build.getJwks(true);
        });

    }



}
