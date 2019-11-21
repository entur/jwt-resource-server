package org.entur.jwt.client;


import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;

import org.entur.jwt.client.AbstractCachedAccessTokenProvider.AccessTokenCacheItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class PreemptivceCachedJwksProviderTest extends AbstractDelegateProviderTest {

	private Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if(!provider.getLazyLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			provider.getLazyLock().unlock();
		}
	}; 

	private PreemptiveCachedAccessTokenProvider provider;

	@BeforeEach
	public void setUp() throws Exception {
		super.setUp();
		provider = new PreemptiveCachedAccessTokenProvider(fallback, 10, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, 15, TimeUnit.SECONDS);
	}

	@Test
	public void shouldUseFallbackWhenNotCached() throws Exception {
		assertThat(provider.getAccessToken(false)).isEqualTo(accessToken);
	}

	@Test
	public void shouldUseCachedValue() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!", null));
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
		verify(fallback, only()).getAccessToken(false);
	}

	@Test
	public void shouldUseFallbackWhenExpiredCache() throws Exception {

		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

		// first
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
		verify(fallback, only()).getAccessToken(false);

		// second
		assertThat(provider.getAccessToken(provider.getExpires(1), false)).isSameInstanceAs(refreshedAccessToken);
		verify(fallback, times(2)).getAccessToken(false);
	}

	@Test
	public void shouldNotReturnExpiredValueWhenExpiredCacheAndRefreshFails() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!", null));
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);

		assertThrows(AccessTokenException.class,
				()->{
					provider.getAccessToken(provider.getExpires(1), false); 
				} );
	}

	@Test
	public void shouldGetBaseProvider() throws Exception {
		assertThat(provider.getProvider()).isSameInstanceAs(fallback);
	}

	@Test
	public void shouldPreemptivelyRefreshCache() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

		// first access-token
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
		verify(fallback, only()).getAccessToken(false);

		long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

		assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		verify(fallback, times(2)).getAccessToken(false);

		// second
		assertThat(provider.getAccessToken(false)).isEqualTo(refreshedAccessToken); // should already be in cache
		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(fallback, times(2)).getAccessToken(false);
	}

	@Test
	public void shouldNotPreemptivelyRefreshCacheIfRefreshAlreadyInProgress() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

		// first
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
		verify(fallback, only()).getAccessToken(false);

		AccessTokenCacheItem cache = provider.getCache();

		long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

		assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		provider.preemptiveUpdate(justBeforeExpiry, cache); // should not trigger a preemptive refresh attempt

		verify(fallback, times(2)).getAccessToken(false);

		// second
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken); // should already be in cache
		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(fallback, times(2)).getAccessToken(false);
	}

	@Test
	public void shouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailed() throws Exception {
		when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("TEST!")).thenReturn(refreshedAccessToken);

		// first
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
		verify(fallback, only()).getAccessToken(false);

		long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

		assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a another preemptive refresh attempt

		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		verify(fallback, times(3)).getAccessToken(false);

		// second
		assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken); // should already be in cache
		provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(fallback, times(3)).getAccessToken(false);
	}

	@Test
	public void shouldAccceptIfAnotherThreadPreemptivelyUpdatesCache() throws Exception {
		provider.getAccessToken(false);

		long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.begin();

			provider.getAccessToken(justBeforeExpiry, false); // wants to update, but can't get lock

			verify(fallback, only()).getAccessToken(false);
		} finally {
			helper.close();
		}
	}    


}

