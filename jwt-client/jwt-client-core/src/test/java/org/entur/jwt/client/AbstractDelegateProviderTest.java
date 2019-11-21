package org.entur.jwt.client;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
public abstract class AbstractDelegateProviderTest {

	protected static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

	protected AccessTokenProvider fallback;
	protected AccessToken accessToken;
	protected AccessToken refreshedAccessToken;
	
	@BeforeEach
	public void setUp() throws Exception {
		fallback = mock(AccessTokenProvider.class);
		accessToken = mock(AccessToken.class);
		
		accessToken = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 10 * 60 * 1000);
		refreshedAccessToken = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 20 * 60 * 1000);
		
		when(fallback.getAccessToken(true)).thenReturn(refreshedAccessToken);
		when(fallback.getAccessToken(false)).thenReturn(accessToken);
	}

}
