package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultHealthAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private DefaultAccessTokenHealthProvider provider;
    private AccessTokenProvider refreshProvider;
    
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new DefaultAccessTokenHealthProvider(fallback);
        refreshProvider = mock(AccessTokenProvider.class);
        provider.setRefreshProvider(refreshProvider);
        when(refreshProvider.getAccessToken(false)).thenReturn(refreshedAccessToken);
        when(refreshProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);
    }
    
    @Test
    public void shouldSupportHealth() throws Exception {
        assertTrue(provider.supportsHealth());
    }
    
    @Test
    public void shouldReturnUnknownHealthIfNoPreviousStatusAndRefreshingIsNotAllowed() throws Exception {
        AccessTokenHealth health = provider.getHealth(false);
        assertNull(health);

        // expected behavior: the health provider did not attempt to refresh status.
        Mockito.verify(refreshProvider, times(0)).getAccessToken(false);
        Mockito.verify(fallback, times(0)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealth() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken);

        // attempt to get access-token
        provider.getAccessToken(false);

        AccessTokenHealth health1 = provider.getHealth(true);
        assertTrue(health1.isSuccess());

        AccessTokenHealth health2 = provider.getHealth(false);
        assertSame(health1, health2);

        // expected behavior: the health provider did not attempt to refresh
        // a good health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(0)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealthIfAccessTokenCouldBeRefreshedAfterBadStatus() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());

        // attempt to get access-token
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });

        AccessTokenHealth health = provider.getHealth(true);
        assertTrue(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }    

    @Test
    public void shouldReturnBadHealthIfAccessTokenCouldNotBeRefreshedAfterBadStatus() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());
        when(refreshProvider.getAccessToken(false)).thenThrow(new AccessTokenException());

        // attempt to get access-token
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });

        AccessTokenHealth health = provider.getHealth(true);
        assertFalse(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }    
  

    @Test
    public void shouldRecoverFromBadHealth() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException()) // fail
                .thenReturn(accessToken); // recover

        // attempt to get access-token
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        provider.getAccessToken(false);

        AccessTokenHealth health1 = provider.getHealth(false);
        assertTrue(health1.isSuccess());
        
        AccessTokenHealth health2 = provider.getHealth(true);
        assertSame(health1, health2);
        
        Mockito.verify(fallback, times(2)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(0)).getAccessToken(false);
    }

    @Test
    public void shouldReturnBadHealthWhenAccessTokenFetchFailsAfterRefreshedGoodHealth() throws Exception {
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        when(source.getAccessToken(false)).thenReturn(accessToken, accessToken).thenThrow(new AccessTokenException());
        DefaultAccessTokenHealthProvider health = new DefaultAccessTokenHealthProvider(source);
        health.setRefreshProvider(new DefaultCachedAccessTokenProvider(health, 0, 1000));

        // note: the cache minimum time to live is not configured on the health provider,
        // so a still-valid cached access-token does not make up for the failed fetch

        // health is refreshed by the indicator before any access-token has been requested
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        health.getAccessToken(false);
        assertTrue(health.getHealth(false).isSuccess());

        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));

        // expected behavior: the latest call to the underlying provider failed, so
        // the previously refreshed (good) status no longer applies
        assertFalse(health.getHealth(false).isSuccess());

        // a refresh via the top-level provider (served by the cache) is good, but does not change the
        // underlying outcome, since the cache minimum time to live is not known to the health provider
        assertTrue(health.getHealth(true).isSuccess());
        assertFalse(health.getHealth(false).isSuccess());

        Mockito.verify(source, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldNotKeepCacheDerivedGoodHealthAfterCachedAccessTokenExpired() throws Exception {
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        AccessToken expiring = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 300);
        when(source.getAccessToken(anyBoolean())).thenReturn(expiring).thenThrow(new AccessTokenException());
        DefaultAccessTokenHealthProvider health = new DefaultAccessTokenHealthProvider(source);
        health.setCacheMinimumTimeToLive(0);
        AccessTokenProvider cache = new DefaultCachedAccessTokenProvider(health, 0, 1000);
        health.setRefreshProvider(cache);

        cache.getAccessToken(false);
        // a later (preemptive) refresh fails, but the cache still holds the access-token
        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        Thread.sleep(400);

        // the access-token has expired and the source is still failing
        assertFalse(health.getHealth(false).isSuccess());
        assertFalse(health.getHealth(true).isSuccess());
    }

    @Test
    public void shouldReturnBadHealthWhenCacheRejectsAccessTokenFromSource() throws Exception {
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        // valid for less than the minimum time to live of the cache
        when(source.getAccessToken(false)).thenReturn(new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 5_000));
        DefaultAccessTokenHealthProvider health = new DefaultAccessTokenHealthProvider(source);
        health.setCacheMinimumTimeToLive(15_000);
        AccessTokenProvider cache = new DefaultCachedAccessTokenProvider(health, 15_000, 1000);
        health.setRefreshProvider(cache);

        // the source returns an access-token, but the cache (top-level provider) fails
        assertThrows(AccessTokenException.class, () -> cache.getAccessToken(false));
        assertFalse(health.getHealth(false).isSuccess());

        assertFalse(health.getHealth(true).isSuccess());
        assertFalse(health.getHealth(false).isSuccess());

        Mockito.verify(source, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealthIfRefreshFailedButCacheStillHoldsValidAccessToken() throws Exception {
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        AccessToken expiring = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 500);
        when(source.getAccessToken(false)).thenReturn(expiring).thenThrow(new AccessTokenException());
        DefaultAccessTokenHealthProvider health = new DefaultAccessTokenHealthProvider(source);
        // the cache serves the access-token until 100ms before it expires
        health.setCacheMinimumTimeToLive(100);

        health.getAccessToken(false);
        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));

        assertTrue(health.getHealth(false).isSuccess());

        // the cache would no longer return the access-token
        Thread.sleep(450);
        assertFalse(health.getHealth(false).isSuccess());
    }

}
