package org.entur.jwt.client;


import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

public class StatefulUrlAccessTokenProviderTest extends AbstractUrlAccessTokenProviderTest {

	@Test
    public void shouldFailHealthCheck() throws Exception {
    	try (UrlAccessTokenProvider urlProvider = new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), null, null, mockUrl, mockUrl)) {
	    	
		    assertThrows(AccessTokenHealthNotSupportedException.class,
				()->{
					urlProvider.getHealth(false);
				} );
    	}
    }

	private StatefulUrlAccessTokenProvider providerForResource(String resource) throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream(resource));

        Map<String, Object> headers = new HashMap<>();
        headers.put("Authorization", "abcdef");
        
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(AbstractClientCredentialsBuilder.KEY_GRANT_TYPE, AbstractClientCredentialsBuilder.KEY_CLIENT_CREDENTIALS);
		
		return new StatefulUrlAccessTokenProvider(mockUrl, parameters, headers, null, null, mockUrl, mockUrl);
	}

    @Test
    public void shouldReturnAccessToken() throws Exception {
    	AccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
        assertThat(provider.getAccessToken(false)).isNotNull();
    }
    
    @Test
    public void shouldUseRefreshTokenToRefreshExpiredAccessToken() throws Exception {
    	StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
    	AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();
        
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);

        AccessToken refreshedAccessToken = provider.getAccessToken(accessToken.getExpires() + 1);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(refreshedAccessToken).isNotSameInstanceAs(accessToken);
        
        String body = output.toString();
        assertThat(body).contains(StatefulUrlAccessTokenProvider.KEY_REFRESH_TOKEN);
    }
    
    @Test
    public void shouldUseClientCredentialsToRefreshExpiredRefreshToken() throws Exception {
    	StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
    	AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();
        
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);

        RefreshToken refreshToken = provider.getRefreshToken();
        
        AccessToken refreshedAccessToken = provider.getAccessToken(refreshToken.getExpires() + 1);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(refreshedAccessToken).isNotSameInstanceAs(accessToken);
        
        String body = output.toString();
        assertThat(body).contains(AbstractClientCredentialsBuilder.KEY_CLIENT_CREDENTIALS);
    }     
  
    @Test
    public void shouldFailToLoadSingleWhenUrlHasNothing() throws Exception {
    	
    	AccessTokenProvider provider = providerForResource("/");
        
	    assertThrows(AccessTokenException.class,
			()->{
				provider.getAccessToken(false);
			} );
    }

    @Test
    public void shouldFailWithNegativeConnectTimeout() throws MalformedURLException {
	    assertThrows(IllegalArgumentException.class,
			()->{
		        new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), -1, null, mockUrl, mockUrl);
			} );       	
    }

    @Test
    public void shouldFailWithNegativeReadTimeout() throws MalformedURLException {
	    assertThrows(IllegalArgumentException.class,
			()->{
		        new StatefulUrlAccessTokenProvider(new URL("https://localhost"), Collections.emptyMap(), Collections.emptyMap(), null, -1, mockUrl, mockUrl);
			} );       	
    }
    
    @Test
    public void shouldFailWithAccessTokenUnavailableExceptionWhenUnparsableEntity() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(new ByteArrayInputStream("{unaparsable}".getBytes(StandardCharsets.UTF_8)));

        try (DefaultAccessTokenHealthProvider provider = new DefaultAccessTokenHealthProvider(new StatefulUrlAccessTokenProvider(mockUrl, Collections.emptyMap(), Collections.emptyMap(), null, null, mockUrl, mockUrl))) {
	
		    assertThrows(AccessTokenUnavailableException.class,
				()->{
			        provider.getAccessToken(false);
				} );
        }
    }    

    @Test
    public void shouldConfigureURLConnection() throws Exception {
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));

        int connectTimeout = 10000;
        int readTimeout = 15000;

        try (DefaultAccessTokenHealthProvider urlJwkProvider = new DefaultAccessTokenHealthProvider(new StatefulUrlAccessTokenProvider(mockUrl, Collections.emptyMap(), Collections.emptyMap(), connectTimeout, readTimeout, mockUrl, mockUrl))) {
	        AccessToken token = urlJwkProvider.getAccessToken(false);
	        assertNotNull(token);
	
	        //Request Timeout assertions
	        ArgumentCaptor<Integer> connectTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
	        verify(urlConnection).setConnectTimeout(connectTimeoutCaptor.capture());
	        assertThat(connectTimeoutCaptor.getValue()).isEqualTo(connectTimeout);
	
	        ArgumentCaptor<Integer> readTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
	        verify(urlConnection).setReadTimeout(readTimeoutCaptor.capture());
	        assertThat(readTimeoutCaptor.getValue()).isEqualTo(readTimeout);
	
	        //Request Headers assertions
	        verify(urlConnection).setRequestProperty("Accept", "application/json");
        }
    }
    
    @Test
    public void shouldThrowAccessTokenExceptionOnUnknownStatusCode() throws Exception {
    	StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
    	AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();
        
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
    	when(urlConnection.getResponseCode()).thenReturn(999);

	    assertThrows(AccessTokenException.class,
			()->{
				provider.getAccessToken(accessToken.getExpires() + 1);
			} );
    }    

    @Test
    public void shouldThrowUnavailableAccessTokenExceptionOnHttp503() throws Exception {
    	StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
    	AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();
        
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
    	when(urlConnection.getResponseCode()).thenReturn(503);


    	assertThrows(AccessTokenUnavailableException.class,
			()->{
				provider.getAccessToken(accessToken.getExpires() + 1);
			} );
    }
    
    @Test
    public void shouldThrowAccessTokenUnavailableExceptionOnHttp429() throws Exception {
    	StatefulUrlAccessTokenProvider provider = providerForResource("/keycloakClientCredentialsResponse.json");
    	AccessToken accessToken = provider.getAccessToken(false);
        assertThat(accessToken).isNotNull();
        
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/keycloakClientCredentialsResponse.json"));
        when(urlConnection.getOutputStream()).thenReturn(output);
    	when(urlConnection.getResponseCode()).thenReturn(429);

	    assertThrows(AccessTokenUnavailableException.class,
			()->{
				provider.getAccessToken(accessToken.getExpires() + 1);
			} );
    }
    
}
