package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


public class DefaultJwkProviderTest extends AbstractDelegateProviderTest {

	private DefaultJwkProvider<JwkImpl> jwkProvider;

	@BeforeEach
	public void setUp() throws Exception {
		super.setUp();
		jwkProvider = new DefaultJwkProvider<>(delegate, fieldExtractor);

		when(jwk.getId()).thenReturn(KID);
	}

	@Test
	public void shouldSucceedToGetJwtForKnownKeyId() throws JwksException {
		assertThat(jwkProvider.getJwk(KID), equalTo(jwk));
	}

	@Test
	public void shouldFailToGetJwtForUnknownKeyId() throws Exception {
		assertThrows(JwkNotFoundException.class,
				()->{
					jwkProvider.getJwk("unknown");
				} );
	}

	@Test
	public void shouldSucceedToGetJwtForKnownNullKeyId() throws Exception {
		JwkImpl jwk = mock(JwkImpl.class);

		when(delegate.getJwks(false)).thenReturn(Arrays.asList(jwk));

		when(jwk.getId()).thenReturn(null);

		assertThat(jwkProvider.getJwk(null), equalTo(jwk));
	}

	@Test
	public void shouldFailToGetJwtForUnknownNullKeyId() throws Exception {
		assertThrows(JwkNotFoundException.class,
				()->{
					jwkProvider.getJwk(null);
				} );    	
	}

}
