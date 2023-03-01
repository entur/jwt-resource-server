package org.entur.jwt.spring.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {


    private final Map<String, JWKSource> jwkSources;

    public EnturOauth2ResourceServerCustomizer(Map<String, JWKSource> jwkSources) {
        this.jwkSources = jwkSources;
    }

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {




    }
}
