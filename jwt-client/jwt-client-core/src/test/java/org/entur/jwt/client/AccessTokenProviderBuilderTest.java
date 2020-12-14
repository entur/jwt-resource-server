package org.entur.jwt.client;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AccessTokenProviderBuilderTest {

    private AccessTokenProvider rootProvider;

    @BeforeEach
    public void setUp() throws Exception {
        rootProvider = mock(AccessTokenProvider.class);
    }

    @Test
    public void shouldCreateCachedProvider() {
        AccessTokenProvider provider = builder().cached(true).health(false).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(3);

        assertThat(accessTokenProviders.get(0)).isInstanceOf(DefaultCachedAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(1)).isInstanceOf(AccessTokenProvider.class);
    }

    @Test
    public void shouldCreateCachedProviderWithCustomValues() {
        AccessTokenProvider provider = builder().cached(10, TimeUnit.SECONDS, 15, TimeUnit.SECONDS).health(false).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(3);

        DefaultCachedAccessTokenProvider cachedAccessTokenProvider = (DefaultCachedAccessTokenProvider) accessTokenProviders.get(0);

        assertThat(cachedAccessTokenProvider.getMinimumTimeToLive()).isEqualTo(TimeUnit.SECONDS.toMillis(10));
    }

    @Test
    public void shouldCreateCachedProviderByDefault() {
        AccessTokenProvider provider = builder().build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(4);

        assertThat(accessTokenProviders.get(0)).isInstanceOf(DefaultCachedAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(1)).isInstanceOf(DefaultAccessTokenHealthProvider.class);
        assertThat(accessTokenProviders.get(2)).isInstanceOf(RetryingAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(3)).isInstanceOf(AccessTokenProvider.class);
    }

    private List<AccessTokenProvider> accessTokenProviders(AccessTokenProvider accessTokenProvider) {
        List<AccessTokenProvider> list = new ArrayList<>();

        list.add(accessTokenProvider);

        while (accessTokenProvider instanceof BaseAccessTokenProvider) {
            BaseAccessTokenProvider baseAccessTokenProvider = (BaseAccessTokenProvider) accessTokenProvider;

            accessTokenProvider = baseAccessTokenProvider.getProvider();

            list.add(accessTokenProvider);
        }

        return list;
    }

    @Test
    public void shouldCreateRetryingProvider() {
        AccessTokenProvider provider = builder().cached(false).preemptiveCacheRefresh(false).retrying(true).health(false).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(2);

        assertThat(accessTokenProviders.get(0)).isInstanceOf(RetryingAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(1)).isInstanceOf(AccessTokenProvider.class);
    }

    @Test
    public void shouldCreateWithCustomAccessTokenProvider() {
        AccessTokenProvider customAccessTokenProvider = mock(AccessTokenProvider.class);

        AccessTokenProvider provider = new AccessTokenProviderBuilder(customAccessTokenProvider).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(4);

        assertThat(accessTokenProviders.get(accessTokenProviders.size() - 1)).isSameInstanceAs(customAccessTokenProvider);
    }

    @Test
    public void shouldCreatePreemptiveCachedProvider() {
        AccessTokenProvider provider = builder().preemptiveCacheRefresh(20, TimeUnit.SECONDS, false).health(false).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(3);

        assertThat(accessTokenProviders.get(0)).isInstanceOf(PreemptiveCachedAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(1)).isInstanceOf(RetryingAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(2)).isInstanceOf(AccessTokenProvider.class);
    }

    @Test
    public void shouldEnableCacheWhenPreemptiveCaching() {
        AccessTokenProvider provider = builder().cached(false).health(false).preemptiveCacheRefresh(true).build();

        List<AccessTokenProvider> accessTokenProviders = accessTokenProviders(provider);
        assertThat(accessTokenProviders).hasSize(3);

        assertThat(accessTokenProviders.get(0)).isInstanceOf(PreemptiveCachedAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(1)).isInstanceOf(RetryingAccessTokenProvider.class);
        assertThat(accessTokenProviders.get(2)).isInstanceOf(AccessTokenProvider.class);
    }

    private AccessTokenProviderBuilder builder() {
        return new AccessTokenProviderBuilder(rootProvider);
    }
}
