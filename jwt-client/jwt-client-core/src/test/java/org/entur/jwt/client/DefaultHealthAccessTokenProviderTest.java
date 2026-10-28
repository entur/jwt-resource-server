package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.entur.jwt.client.ScriptedAccessTokenProvider.failure;
import static org.entur.jwt.client.ScriptedAccessTokenProvider.tokenExpiringIn;
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
    public void shouldLetFailedAccessTokenFetchSupersedeRefreshedGoodHealth() throws Exception {
        ScriptedAccessTokenProvider source = new ScriptedAccessTokenProvider(tokenExpiringIn(600_000), tokenExpiringIn(600_000), failure());
        DefaultAccessTokenHealthProvider health = new DefaultAccessTokenHealthProvider(source);
        health.setRefreshProvider(new DefaultCachedAccessTokenProvider(health, 0, 1000));

        // health is refreshed by the indicator before any access-token has been requested
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        health.getAccessToken(false);
        assertTrue(health.getHealth(false).isSuccess());

        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));

        // expected behavior: the latest call to the underlying provider failed, so
        // the previously refreshed (good) status no longer applies
        assertFalse(health.getHealth(false).isSuccess());

        // a refresh via the top-level provider (served by the cache) recovers the health
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        assertEquals(3, source.getCalls());
    }

    @Test
    public void shouldReturnGoodHealthIfRefreshFailedButCacheStillHoldsValidAccessToken() throws Exception {
        ScriptedAccessTokenProvider source = new ScriptedAccessTokenProvider(tokenExpiringIn(500), failure());
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
