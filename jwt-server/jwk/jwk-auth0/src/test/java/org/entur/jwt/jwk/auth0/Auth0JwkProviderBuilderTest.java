package org.entur.jwt.jwk.auth0;

import java.net.MalformedURLException;
import java.net.URL;
import static com.google.common.truth.Truth.*;
import org.entur.jwt.jwk.JwkProvider;
import org.entur.jwt.jwk.JwkProviderBuilder;
import org.junit.jupiter.api.Test;

import com.auth0.jwk.Jwk;

public class Auth0JwkProviderBuilderTest {

    @Test
    public void testBuilder() throws Exception {
        JwkProviderBuilder<Jwk> builder = builderForResource("/jwks.json");

        JwkProvider<Jwk> provider = builder.build();

        assertThat(provider.getJwk("NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg")).isNotNull();
    }

    @Test
    public void testBuilderWithGarbage() throws Exception {
        JwkProviderBuilder<Jwk> builder = builderForResource("/jwksWithGarbage.json");

        JwkProvider<Jwk> provider = builder.build();

        assertThat(provider.getJwk("NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg")).isNotNull();
    }

    private JwkProviderBuilder<Jwk> builderForResource(String resource) throws MalformedURLException {
        URL url;
        if (resource.contains("://")) {
            url = new URL(resource);
        } else {
            url = getClass().getResource(resource);
        }
        return Auth0JwkProviderBuilder.newBuilder(url, 15000, 15000);
    }

}
