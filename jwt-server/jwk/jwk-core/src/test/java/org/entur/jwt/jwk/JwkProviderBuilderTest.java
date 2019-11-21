package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.hasSize;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.bucket4j.Bucket;
@SuppressWarnings("rawtypes")
public class JwkProviderBuilderTest {

	private JwksProvider rootProvider;
	private JwkFieldExtractor fieldExtractor;

	@BeforeEach
	public void setUp() throws Exception {
		rootProvider = mock(JwksProvider.class);
	}

	@Test
	public void shouldCreateCachedProvider() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(true)
				.health(false)
				.build();
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		assertThat(jwksProviders.get(0), instanceOf(DefaultCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateCachedProviderWithCustomValues() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(24, TimeUnit.HOURS, 15, TimeUnit.SECONDS)
				.health(false)
				.build();

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		DefaultCachedJwksProvider<?> cachedJwksProvider = (DefaultCachedJwksProvider<?>) jwksProviders.get(0);

		assertThat(cachedJwksProvider.getTimeToLive(), is(TimeUnit.HOURS.toMillis(24)));
	}

	@Test
	public void shouldCreateRateLimitedProvider() {
		JwkProvider<?> provider = builder()
				.rateLimited(true)
				.build();

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		RateLimitedJwksProvider<?> rateLimitedJwksProvider = (RateLimitedJwksProvider<?>) jwksProviders.get(1);

		Bucket bucketImpl = (Bucket) rateLimitedJwksProvider.getBucket();
		assertThat(bucketImpl.getAvailableTokens(), is(10L));
	}

	@Test
	public void shouldCreateRateLimitedProviderWithCustomValues() {
		JwkProvider<?> provider = builder()
				.rateLimited(100, 24, TimeUnit.HOURS)
				.build();

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		RateLimitedJwksProvider<?> rateLimitedJwksProvider = (RateLimitedJwksProvider<?>) jwksProviders.get(1);

		Bucket bucketImpl = (Bucket ) rateLimitedJwksProvider.getBucket();
		assertThat(bucketImpl.getAvailableTokens(), is(100L));
	}

	@Test
	public void shouldCreateCachedAndRateLimitedProvider() {
		JwkProvider<?> provider = builder()
				.cached(true)
				.rateLimited(true)
				.build();

		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		assertThat(jwksProviders.get(0), instanceOf(DefaultCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(RateLimitedJwksProvider.class));
		assertThat(jwksProviders.get(2), instanceOf(DefaultHealthJwksProvider.class));
		assertThat(jwksProviders.get(3), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateCachedAndRateLimitedProviderWithCustomValues() {
		JwkProvider<?> provider = builder()
				.cached(24, TimeUnit.HOURS, 15, TimeUnit.SECONDS)
				.rateLimited(10, 24, TimeUnit.HOURS)
				.build();

		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		assertThat(jwksProviders.get(0), instanceOf(DefaultCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(RateLimitedJwksProvider.class));
		assertThat(jwksProviders.get(2), instanceOf(DefaultHealthJwksProvider.class));
		assertThat(jwksProviders.get(3), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateCachedAndRateLimitedProviderByDefault() {
		JwkProvider<?> provider = builder().build();
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		assertThat(jwksProviders.get(0), instanceOf(DefaultCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(RateLimitedJwksProvider.class));
		assertThat(jwksProviders.get(2), instanceOf(DefaultHealthJwksProvider.class));
		assertThat(jwksProviders.get(3), instanceOf(JwksProvider.class));
	}

	private List<JwksProvider<?>> jwksProviders(JwkProvider<?> jwkProvider) {
		JwksProvider<?> jwksProvider;
		if(jwkProvider instanceof DefaultJwkProvider) {
			DefaultJwkProvider<?> base = (DefaultJwkProvider<?>)jwkProvider;
			jwksProvider = (JwksProvider<?>) base.getProvider();
		} else {
			jwksProvider = (JwksProvider<?>) jwkProvider;
		}

		List<JwksProvider<?>> list = new ArrayList<>();

		list.add(jwksProvider);

		while(jwksProvider instanceof BaseJwksProvider) {
			BaseJwksProvider<?> baseJwksProvider = (BaseJwksProvider<?>)jwksProvider;

			jwksProvider = baseJwksProvider.getProvider();

			list.add(jwksProvider);
		}

		return list;
	}

	@Test
	public void shouldCreateRetryingProvider() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(false)
				.preemptiveCacheRefresh(false)
				.retrying(true)
				.health(false)
				.build();
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		assertThat(jwksProviders.get(0), instanceOf(RetryingJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateOutageCachedProvider() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(false)
				.preemptiveCacheRefresh(false)
				.outageCached(true)
				.health(false)
				.build();
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		assertThat(jwksProviders.get(0), instanceOf(OutageCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateOutageCachedProviderWithCustomValues() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(false)
				.health(false)
				.preemptiveCacheRefresh(false)
				.outageCached(24, TimeUnit.HOURS)
				.build();

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		OutageCachedJwksProvider<?> cachedJwksProvider = (OutageCachedJwksProvider<?>) jwksProviders.get(0);

		assertThat(cachedJwksProvider.getTimeToLive(), is(TimeUnit.HOURS.toMillis(24)));
	}

	@Test
	public void shouldCreateCachedAndRateLimitedAndOutageAndRetryingProvider() {
		JwkProvider<?> provider = builder()
				.cached(true)
				.rateLimited(true)
				.retrying(true)
				.outageCached(true)
				.health(true)
				.build();

		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(6));

		assertThat(jwksProviders.get(0), instanceOf(DefaultCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(RateLimitedJwksProvider.class));
		assertThat(jwksProviders.get(2), instanceOf(DefaultHealthJwksProvider.class));
		assertThat(jwksProviders.get(3), instanceOf(OutageCachedJwksProvider.class));
		assertThat(jwksProviders.get(4), instanceOf(RetryingJwksProvider.class));
		assertThat(jwksProviders.get(5), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldCreateWithCustomJwksProvider() {
		JwksProvider customJwksProvider = mock(JwksProvider.class);

		@SuppressWarnings("unchecked")
		JwkProvider<?> provider = new JwkProviderBuilder<>(customJwksProvider, fieldExtractor).build();

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(4));

		assertThat(jwksProviders.get(jwksProviders.size() - 1), sameInstance(customJwksProvider));
	}

	@Test
	public void shouldCreatePreemptiveCachedProvider() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.preemptiveCacheRefresh(10, TimeUnit.SECONDS)
				.health(false)
				.build();
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		assertThat(jwksProviders.get(0), instanceOf(PreemptiveCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(JwksProvider.class));
	}

	@Test
	public void shouldFailWhenRatelimitingWithoutCaching() {
		assertThrows(IllegalStateException.class,
				()->{
					builder().cached(false).rateLimited(true).build();
				} );
	}

	@Test
	public void shouldEnableCacheWhenPreemptiveCaching() {
		JwkProvider<?> provider = builder()
				.rateLimited(false)
				.cached(false)
				.health(false)
				.preemptiveCacheRefresh(true)
				.build();
		
		assertThat(provider, notNullValue());

		List<JwksProvider<?>> jwksProviders = jwksProviders(provider);
		assertThat(jwksProviders, hasSize(2));

		assertThat(jwksProviders.get(0), instanceOf(PreemptiveCachedJwksProvider.class));
		assertThat(jwksProviders.get(1), instanceOf(JwksProvider.class));		
	}

	@SuppressWarnings("unchecked")
	private <T> JwkProviderBuilder<T> builder() {
		return new JwkProviderBuilder<>(rootProvider, fieldExtractor);
	}

}
