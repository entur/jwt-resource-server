package org.entur.jwt.client.grpc;

import io.grpc.*;

/**
 * Interceptor which detect an unauthorized response to outgoing calls.
 */

public class JwkRotationAccessTokenRecoveryClientInterceptor implements ClientInterceptor {

    public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private JwkRotationAccessTokenRecoveryHandler handler;
		private JwtCallCredentials callCredentials;

		public Builder withCallCredentials(JwtCallCredentials callCredentials) {
			this.callCredentials = callCredentials;
			return this;
		}

		public Builder withHandler(JwkRotationAccessTokenRecoveryHandler handler) {
			this.handler = handler;
			return this;
		}

		public JwkRotationAccessTokenRecoveryClientInterceptor build() {
			if(handler == null) {
				throw new IllegalStateException();
			}
			if(callCredentials == null) {
				throw new IllegalStateException();
			}

			return new JwkRotationAccessTokenRecoveryClientInterceptor(callCredentials, handler);
		}
	}

	protected final JwtCallCredentials callCredentials;
	protected final JwkRotationAccessTokenRecoveryHandler handler;

	public JwkRotationAccessTokenRecoveryClientInterceptor(JwtCallCredentials callCredentials, JwkRotationAccessTokenRecoveryHandler handler) {
		this.callCredentials = callCredentials;
		this.handler = handler;
	}

	@Override
	public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {

		ClientCall<ReqT, RespT> call = next.newCall(method, callOptions);

		return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(call) {

			@Override
			public void start(Listener<RespT> listener, Metadata headers) {
				Listener<RespT> responseListener = new Listener<RespT>() {

					private String authorizationHeader;

					@Override
					public void onHeaders(Metadata headers) {
						super.onHeaders(headers);

						authorizationHeader = headers.get(JwtCallCredentials.KEY_AUTHORIZATION);
					}

					@Override
					public void onClose(Status status, Metadata trailers) {
						try {
							if(status.getCode() == Status.Code.UNAUTHENTICATED) {
								if(authorizationHeader != null) {
									CallCredentials credentials = callOptions.getCredentials();
									if(credentials instanceof JwtCallCredentials jwtCallCredentials) {
										handler.handle(jwtCallCredentials.getAccessTokenProvider(), authorizationHeader, System.currentTimeMillis());
									}
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
