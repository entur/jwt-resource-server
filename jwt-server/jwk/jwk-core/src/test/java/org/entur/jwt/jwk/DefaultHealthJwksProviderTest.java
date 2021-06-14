package org.entur.jwt.jwk;

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

public class DefaultHealthJwksProviderTest extends AbstractDelegateProviderTest {

    private DefaultHealthJwksProvider<JwkImpl> provider;
    private JwksProvider<JwkImpl> refreshProvider = mock(JwksProvider.class);
    
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new DefaultHealthJwksProvider<>(delegate);
        provider.setRefreshProvider(refreshProvider);
        
        when(refreshProvider.getJwks(false)).thenReturn(jwks);
        when(refreshProvider.getJwks(true)).thenReturn(jwks);
    }

    
    @Test
    public void shouldReturnUnknownHealthIfNoPreviousStatusAndRefreshingIsNotAllowed() throws Exception {
        JwksHealth health = provider.getHealth(false);
        assertNull(health);

        // expected behavior: the health provider did not attempt to refresh status.
        Mockito.verify(refreshProvider, times(0)).getJwks(false);
        Mockito.verify(delegate, times(0)).getJwks(false);
    }

    @Test
    public void shouldReturnGoodHealth() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks);

        // attempt to get access-token
        provider.getJwks(false);

        JwksHealth health1 = provider.getHealth(true);
        assertTrue(health1.isSuccess());

        JwksHealth health2 = provider.getHealth(false);
        assertSame(health1, health2);

        // expected behavior: the health provider did not attempt to refresh
        // a good health status.
        Mockito.verify(delegate, times(1)).getJwks(false);
        Mockito.verify(refreshProvider, times(0)).getJwks(false);
    }

    @Test
    public void shouldReturnGoodHealthIfJwksCouldBeRefreshedAfterBadStatus() throws Exception {
        when(delegate.getJwks(false)).thenThrow(new JwksException());

        // attempt to get jwks
        assertThrows(JwksException.class, () -> {
            provider.getJwks(false);
        });

        JwksHealth health = provider.getHealth(true);
        assertTrue(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(delegate, times(1)).getJwks(false);
        Mockito.verify(refreshProvider, times(1)).getJwks(false);
    }    

    @Test
    public void shouldReturnBadHealthIfJwksCouldNotBeRefreshedAfterBadStatus() throws Exception {
        when(delegate.getJwks(false)).thenThrow(new JwksException());
        when(refreshProvider.getJwks(false)).thenThrow(new JwksException());

        // attempt to get jwks
        assertThrows(JwksException.class, () -> {
            provider.getJwks(false);
        });

        JwksHealth health = provider.getHealth(true);
        assertFalse(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(delegate, times(1)).getJwks(false);
        Mockito.verify(refreshProvider, times(1)).getJwks(false);
    }    
  

    @Test
    public void shouldRecoverFromBadHealth() throws Exception {
        when(delegate.getJwks(false)).thenThrow(new JwksException()) // fail
                .thenReturn(jwks); // recover

        // attempt to get access-token
        assertThrows(JwksException.class, () -> {
            provider.getJwks(false);
        });
        provider.getJwks(false);

        JwksHealth health1 = provider.getHealth(false);
        assertTrue(health1.isSuccess());
        
        JwksHealth health2 = provider.getHealth(true);
        assertSame(health1, health2);
        
        Mockito.verify(delegate, times(2)).getJwks(false);
        Mockito.verify(refreshProvider, times(0)).getJwks(false);
    }    
    
    
    
}
