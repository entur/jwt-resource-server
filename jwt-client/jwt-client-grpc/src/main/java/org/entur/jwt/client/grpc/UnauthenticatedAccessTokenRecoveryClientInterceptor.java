package org.entur.jwt.client.grpc;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.recovery.UnauthenticatedAccessTokenRecoveryHandler;

/**
 * Interceptor which detect an unauthorized response to outgoing calls.
 */

public class UnauthenticatedAccessTokenRecoveryClientInterceptor implements ClientInterceptor {

    public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private UnauthenticatedAccessTokenRecoveryHandler handler;

		public Builder withHandler(UnauthenticatedAccessTokenRecoveryHandler handler) {
			this.handler = handler;
			return this;
		}

		public UnauthenticatedAccessTokenRecoveryClientInterceptor build() {
			if(handler == null) {
				throw new IllegalStateException();
			}

			return new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);
		}
	}

	protected final UnauthenticatedAccessTokenRecoveryHandler handler;

	public UnauthenticatedAccessTokenRecoveryClientInterceptor(UnauthenticatedAccessTokenRecoveryHandler handler) {
		this.handler = handler;
	}

	@Override
	public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {

		AccessTokenCallCredentials credentials = callOptions.getCredentials() instanceof AccessTokenCallCredentials c ? c : null;
		AccessToken accessTokenAtStart = credentials != null ? credentials.getLastAccessToken() : null;

		ClientCall<ReqT, RespT> call = next.newCall(method, callOptions);

		return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(call) {

			@Override
			public void start(Listener<RespT> listener, Metadata headers) {
				Listener<RespT> responseListener = new Listener<RespT>() {

					@Override
					public void onHeaders(Metadata headers) {
						listener.onHeaders(headers);
					}

					@Override
					public void onMessage(RespT message) {
						listener.onMessage(message);
					}

					@Override
					public void onReady() {
						listener.onReady();
					}

					@Override
					public void onClose(Status status, Metadata trailers) {
						try {
							if(credentials != null && status.getCode() == Status.Code.UNAUTHENTICATED) {
								AccessToken accessToken = credentials.getLastAccessToken();
								// only recover if the credentials have not been given a new token since the call started
								if(accessToken != null && (accessTokenAtStart == null || accessTokenAtStart.equals(accessToken))) {
									handler.handle(credentials.getAccessTokenProvider(), AccessTokenCallCredentials.BEARER_PREFIX + accessToken.getValue(), System.currentTimeMillis());
								}
							}
						} finally {
							listener.onClose(status, trailers);
						}
					}
				};
				super.start(responseListener, headers);
			}

		};
	}
}
