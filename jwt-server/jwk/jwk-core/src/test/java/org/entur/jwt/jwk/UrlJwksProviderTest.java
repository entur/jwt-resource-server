package org.entur.jwt.jwk;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

public class UrlJwksProviderTest {

	static final String WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json";

	private static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

	private JwkReaderImpl reader = new JwkReaderImpl();

	@Test
	public void shouldFailWithNullUrl() {
		assertThrows(IllegalArgumentException.class,
				()->{
					new UrlJwksProvider<>((URL) null, reader);
				} );
	}

	@Test
	public void shouldFailHealthCheck() throws Exception {
		UrlJwksProvider<JwkImpl> urlProvider = new UrlJwksProvider<>(new URL("https://localhost"), reader);

		assertThrows(JwksHealthNotSupportedException.class,
				()->{
					urlProvider.getHealth(false);
				} );
	}


	@Test
	public void shouldReturnByIdWhenSingleJwk() throws Exception {
		JwkProvider<?> provider = providerForResource("/jwks-single.json");
		assertThat(provider.getJwk(KID), notNullValue());
	}

	private JwkProvider<?> providerForResource(String resource) throws MalformedURLException {

		URL url;
		if(resource.contains("://")) {
			url = new URL(resource);
		} else {
			url = getClass().getResource(resource);
		}

		return new DefaultJwkProvider<>(new UrlJwksProvider<>(url, reader), new JwkFieldExtractorImpl());
	}

	@Test
	public void shouldReturnSingleJwkById() throws Exception {
		JwkProvider<?> provider = providerForResource("/jwks.json");
		assertThat(provider.getJwk(KID), notNullValue());
	}

	@Test
	public void shouldFailToLoadSingleWithoutIdWhenMultipleJwk() throws Exception {
		assertThrows(JwkNotFoundException.class,
				()->{
					JwkProvider<?> provider = providerForResource("/jwks.json");
					provider.getJwk(null);
				} );

	}

	@Test
	public void shouldFailToLoadByDifferentIdWhenSingleJwk() throws Exception {
		assertThrows(JwkNotFoundException.class,
				()->{
					JwkProvider<?> provider = providerForResource("/jwks-single-no-kid.json");
					provider.getJwk("wrong-kid");
				} );
	}

	@Test
	public void shouldFailToLoadSingleWhenUrlHasNothing() throws Exception {
		assertThrows(JwksUnavailableException.class,
				()->{
					JwkProvider<?> provider = providerForResource("file:///not_found.file");
					provider.getJwk(KID);
				} );
	}

	@Test
	public void shouldFailToLoadSingleWhenKeysIsEmpty() throws Exception {
		assertThrows(JwkNotFoundException.class,
				()->{
					JwkProvider<?> provider = providerForResource("/empty-jwks.json");
					provider.getJwk(KID);
				} );
	}

	@Test
	public void shouldFailWithNegativeConnectTimeout() throws MalformedURLException {
		assertThrows(IllegalArgumentException.class,
				()->{
					new UrlJwksProvider<>(new URL("https://localhost"), reader, -1, null);
				} );       	
	}

	@Test
	public void shouldFailWithNegativeReadTimeout() throws MalformedURLException {
		assertThrows(IllegalArgumentException.class,
				()->{
					new UrlJwksProvider<>(new URL("https://localhost"), reader, null, -1);
				} );       	

	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	public void shouldFailWithSigningKeyUnavailableExceptionWhenUnparsableEntity() throws Exception {

		JwksReader reader = mock(JwksReader.class);
		when(reader.readJwks(any(InputStream.class))).thenThrow(new InvalidSigningKeysException(""));

		URL url = getClass().getResource("/jwks.json");
		JwkProvider<?> provider = new DefaultJwkProvider<>(new UrlJwksProvider<>(url, reader), new JwkFieldExtractorImpl());

		assertThrows(JwksUnavailableException.class,
				()->{
					provider.getJwk(null);
				} );

	}    

	private static class MockURLStreamHandlerFactory implements URLStreamHandlerFactory {

		// The weak reference is just a safeguard against objects not being released
		// for garbage collection
		private final WeakReference<URLConnection> value;

		public MockURLStreamHandlerFactory(URLConnection urlConnection) {
			this.value = new WeakReference<URLConnection>(urlConnection);
		}

		@Override
		public URLStreamHandler createURLStreamHandler(String protocol) {
			return "mock".equals(protocol) ? new URLStreamHandler() {
				protected URLConnection openConnection(URL url) throws IOException {
					try {
						return value.get();
					} finally {
						value.clear();
					}
				}
			} : null;
		}
	}

	@Test
	public void shouldConfigureURLConnection() throws Exception {
		URLConnection urlConnection = mock(URLConnection.class);

		// Although somewhat of a hack, this approach gets the job done - this method can 
		// only be called once per virtual machine, but that is sufficient for now.
		URL.setURLStreamHandlerFactory(new MockURLStreamHandlerFactory(urlConnection));
		when(urlConnection.getInputStream()).thenReturn(getClass().getResourceAsStream("/jwks.json"));

		int connectTimeout = 10000;
		int readTimeout = 15000;

		JwkProvider<JwkImpl> urlJwkProvider = new DefaultJwkProvider<JwkImpl>(new UrlJwksProvider<>(new URL("mock://localhost"), reader, connectTimeout, readTimeout), new JwkFieldExtractorImpl());
		JwkImpl jwk = urlJwkProvider.getJwk("NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg");
		assertNotNull(jwk);

		//Request Timeout assertions
		ArgumentCaptor<Integer> connectTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
		verify(urlConnection).setConnectTimeout(connectTimeoutCaptor.capture());
		assertThat(connectTimeoutCaptor.getValue(), is(connectTimeout));

		ArgumentCaptor<Integer> readTimeoutCaptor = ArgumentCaptor.forClass(Integer.class);
		verify(urlConnection).setReadTimeout(readTimeoutCaptor.capture());
		assertThat(readTimeoutCaptor.getValue(), is(readTimeout));

		//Request Headers assertions
		verify(urlConnection).setRequestProperty("Accept", "application/json");
	}
}
