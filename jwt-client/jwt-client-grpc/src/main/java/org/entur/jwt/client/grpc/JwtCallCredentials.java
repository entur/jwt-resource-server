package org.entur.jwt.client.grpc;

import java.util.concurrent.Executor;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.Status;

public class JwtCallCredentials extends CallCredentials {

	private static final Metadata.Key<String> KEY_AUTHORIZATION = Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtCallCredentials.class);

	private final AccessTokenProvider accessTokenProvider;

	public JwtCallCredentials(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
	}

	@Override
	public void applyRequestMetadata(RequestInfo requestInfo, Executor executor, MetadataApplier metadataApplier) {
		executor.execute(() -> {
			try {
				Metadata headers = new Metadata();
				AccessToken accessToken = accessTokenProvider.getAccessToken(false);
				headers.put(KEY_AUTHORIZATION, "Bearer " + accessToken.getValue());
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
}
