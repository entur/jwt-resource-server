package org.entur.jwt.spring.demo;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
public class JwtClientTestConfiguration {

    @Bean
    @Profile("mockJwt")
    public AccessTokenProvider myClient() throws AccessTokenException {
        AccessTokenProvider mock = mock(AccessTokenProvider.class);
        AccessToken value = new AccessToken("x.y.z", "Bearer", Long.MAX_VALUE);
        when(mock.getAccessToken(false)).thenReturn(value);
        when(mock.getAccessToken(true)).thenReturn(value);
        
        when(mock.getHealth(true)).thenReturn(new AccessTokenHealth(0, true));
        return mock;
    }
}
