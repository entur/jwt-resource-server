package org.entur.jwt.client;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class EagerHealthAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private EagerAccessTokenHealthProvider provider;
    private AccessTokenProvider refreshProvider;
    
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new EagerAccessTokenHealthProvider(fallback);
        refreshProvider = mock(AccessTokenProvider.class);
        provider.setRefreshProvider(refreshProvider);
        when(refreshProvider.getAccessToken(false)).thenReturn(refreshedAccessToken);
        when(refreshProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);
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

        // attempt to get jwks
        provider.getAccessToken(false);

        AccessTokenHealth health1 = provider.getHealth(true);
        assertTrue(health1.isSuccess());

        AccessTokenHealth health2 = provider.getHealth(false);
        assertSame(health1, health2);

        // expected behavior: the health provider attempted to refresh
        // a good health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealthIfAccessTokenCouldBeRefreshedAfterBadStatus() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());

        // attempt to get jwks
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

        // trigger fail
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        provider.getAccessToken(false);

        AccessTokenHealth health2 = provider.getHealth(true);
        assertTrue(health2.isSuccess());

        AccessTokenHealth health1 = provider.getHealth(false);
        assertTrue(health1.isSuccess());
        
        Mockito.verify(fallback, times(2)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }

}
