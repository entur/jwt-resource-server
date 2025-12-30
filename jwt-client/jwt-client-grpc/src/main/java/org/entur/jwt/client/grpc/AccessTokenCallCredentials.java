package org.entur.jwt.client.grpc;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.Status;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Executor;

public class AccessTokenCallCredentials extends CallCredentials {

	public static final Metadata.Key<String> KEY_AUTHORIZATION = Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);

	private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenCallCredentials.class);

	public static final String BEARER_PREFIX = "Bearer ";

	private final AccessTokenProvider accessTokenProvider;

	public AccessTokenCallCredentials(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
	}

	@Override
	public void applyRequestMetadata(RequestInfo requestInfo, Executor executor, MetadataApplier metadataApplier) {
		executor.execute(() -> {
			try {
				Metadata headers = new Metadata();
				AccessToken accessToken = accessTokenProvider.getAccessToken(false);
				headers.put(KEY_AUTHORIZATION, BEARER_PREFIX + accessToken.getValue());
				metadataApplier.apply(headers);
			} catch (Throwable e) {
				LOGGER.error("Failed to apply Authorization header to request: " + e.getMessage(), e);

				metadataApplier.fail(Status.UNAVAILABLE.withCause(e));
			}
		});
	}

	@Override
	public void thisUsesUnstableApi() {
		// Noop never called, indicating api might change
	}

	public AccessTokenProvider getAccessTokenProvider() {
		return accessTokenProvider;
	}

	public static String extractJwt(String header) {
		if(header != null && header.startsWith(BEARER_PREFIX)) {
			return header.substring(BEARER_PREFIX.length());
		}
		return null;
	}
}
