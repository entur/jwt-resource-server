package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class DefaultHealthJwksProviderTest extends AbstractDelegateProviderTest {

	private DefaultHealthJwksProvider<JwkImpl> provider;

	@BeforeEach
	public void setUp() throws Exception {
		super.setUp();
		provider = new DefaultHealthJwksProvider<>(delegate);
	}

	@Test
	public void shouldReturnGoodHealthWhenUnderlyingProviderReturnsJwks() throws Exception {
		when(delegate.getJwks(false)).thenReturn(jwks);

		// attempt to get jwks
		provider.getJwks(false);

		JwksHealth health = provider.getHealth(false);
		assertThat(health.isSuccess(), equalTo(true));

		// expected behavior: the health provider did not attempt to refresh
		// a good health status.
		Mockito.verify(delegate, times(1)).getJwks(false);        
	}

	@Test
	public void shouldReturnBadHealthWhenUnderlyingProviderThrowsException() throws Exception {
		when(delegate.getJwks(false)).thenThrow(new JwksException());
		provider.setRefreshProvider(provider);

		// attempt to get jwks
		assertThrows(JwksException.class,
				()->{
					provider.getJwks(false);
				});

		JwksHealth health = provider.getHealth(true);
		assertThat(health.isSuccess(), equalTo(false));
		Mockito.verify(delegate, times(2)).getJwks(false);
	}

	@Test
	public void shouldRecoverFromBadHealth() throws Exception {
		when(delegate.getJwks(false))
		.thenThrow(new JwksException()) // fail
		.thenReturn(jwks); // recover
		provider.setRefreshProvider(provider);

		// trigger fail
		assertThrows(JwksException.class,
				()->{
					provider.getJwks(false);
				});

		JwksHealth health = provider.getHealth(true); // trigger recover
		assertThat(health.isSuccess(), equalTo(true));
		Mockito.verify(delegate, times(2)).getJwks(false);
	}

}
