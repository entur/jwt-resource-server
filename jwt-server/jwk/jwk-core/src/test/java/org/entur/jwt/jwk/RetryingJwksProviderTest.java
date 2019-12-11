package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RetryingJwksProviderTest extends AbstractDelegateProviderTest {

    private RetryingJwksProvider<JwkImpl> provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new RetryingJwksProvider<>(delegate);
    }

    @Test
    public void shouldReturnListOnSuccess() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks);
        assertThat(provider.getJwks(false), equalTo(jwks));
        verify(delegate, times(1)).getJwks(false);
    }

    @Test
    public void shouldRetryWhenUnavailable() throws Exception {
        when(delegate.getJwks(false)).thenThrow(new JwksUnavailableException("TEST!", null)).thenReturn(jwks);
        assertThat(provider.getJwks(false), equalTo(jwks));
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldNotRetryMoreThanOnce() throws Exception {
        when(delegate.getJwks(false)).thenThrow(new JwksUnavailableException("TEST!", null));

        assertThrows(JwksUnavailableException.class, () -> {
            try {
                provider.getJwks(false);
            } finally {
                verify(delegate, times(2)).getJwks(false);
            }
        });
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider(), equalTo(delegate));
    }
}
