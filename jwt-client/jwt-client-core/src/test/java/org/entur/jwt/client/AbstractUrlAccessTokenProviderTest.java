package org.entur.jwt.client;


import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

public abstract class AbstractUrlAccessTokenProviderTest {

	protected static MockURLStreamHandlerFactory mockURLStreamHandlerFactory = new MockURLStreamHandlerFactory();

	static final String WELL_KNOWN_JWKS_PATH = "/.well-known/jwks.json";

	static class MockURLStreamHandlerFactory implements URLStreamHandlerFactory {

		// The weak reference is just a safeguard against objects not being released
		// for garbage collection
		private WeakReference<URLConnection> value;
		private boolean initialized = false;

		@Override
		public URLStreamHandler createURLStreamHandler(String protocol) {
			return "mock".equals(protocol) ? new URLStreamHandler() {
				protected URLConnection openConnection(URL url) throws IOException {
					try {
						return value.get();
					} finally {

					}
				}
			} : null;
		}

		public void setUrlConnection(URLConnection urlConnection) {
			this.value = new WeakReference<URLConnection>(urlConnection);
		}

		public void initialize() {
			if(!initialized) {
				this.initialized = true;
				// Although somewhat of a hack, this approach gets the job done - this method can 
				// only be called once per virtual machine, but that is sufficient for now.
				URL.setURLStreamHandlerFactory(mockURLStreamHandlerFactory);    	
			}
		}
	}    

	protected HttpURLConnection urlConnection;
	protected static URL mockUrl;

	@BeforeAll
	public static void beforeAll() throws MalformedURLException {
		mockURLStreamHandlerFactory.initialize();

		mockUrl = new URL("mock://localhost");
	}

	@BeforeEach
	public void beforeEach() throws IOException {
		urlConnection = mock(HttpURLConnection.class);
		when(urlConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());
		when(urlConnection.getResponseCode()).thenReturn(200);
		mockURLStreamHandlerFactory.setUrlConnection(urlConnection);
	}

}
