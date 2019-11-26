package org.entur.jwt.client;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class DefaultHealthAccessTokenProviderTest extends AbstractDelegateProviderTest {

	private DefaultAccessTokenHealthProvider provider;

	@BeforeEach
	public void setUp() throws Exception {
		super.setUp();
		provider = new DefaultAccessTokenHealthProvider(fallback);
	}

	@Test
	public void shouldReturnGoodHealthWhenUnderlyingProviderReturnsJwks() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken);

		// attempt to get jwks
		provider.getAccessToken(false);

		AccessTokenHealth health = provider.getHealth(false);
		assertTrue(health.isSuccess());

		// expected behavior: the health provider did not attempt to refresh
		// a good health status.
		Mockito.verify(fallback, times(1)).getAccessToken(false);        
	}

	@Test
	public void shouldReturnBadHealthWhenUnderlyingProviderThrowsException() throws Exception {
		when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());
		provider.setRefreshProvider(provider);

		// attempt to get jwks
		assertThrows(AccessTokenException.class,
				()->{
					provider.getAccessToken(false);
				});

		AccessTokenHealth health = provider.getHealth(true);
		assertFalse(health.isSuccess());
		Mockito.verify(fallback, times(2)).getAccessToken(false);
	}

	@Test
	public void shouldRecoverFromBadHealth() throws Exception {
		when(fallback.getAccessToken(false))
		.thenThrow(new AccessTokenException()) // fail
		.thenReturn(accessToken); // recover
		provider.setRefreshProvider(provider);

		// trigger fail
		assertThrows(AccessTokenException.class,
				()->{
					provider.getAccessToken(false);
				});

		AccessTokenHealth health = provider.getHealth(true); // trigger recover
		assertTrue(health.isSuccess());
		Mockito.verify(fallback, times(2)).getAccessToken(false);
	}

}
