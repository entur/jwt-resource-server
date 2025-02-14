package org.entur.jwt.client.grpc;

import io.grpc.*;
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

		ClientCall<ReqT, RespT> call = next.newCall(method, callOptions);

		return new ForwardingClientCall.SimpleForwardingClientCall<ReqT, RespT>(call) {

			@Override
			public void start(Listener<RespT> listener, Metadata headers) {
				Listener<RespT> responseListener = new Listener<RespT>() {

					private String authorizationHeader;

					@Override
					public void onHeaders(Metadata headers) {
						super.onHeaders(headers);

						authorizationHeader = headers.get(AccessTokenCallCredentials.KEY_AUTHORIZATION);

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
							if(status.getCode() == Status.Code.UNAUTHENTICATED) {
								if(authorizationHeader != null) {
									CallCredentials credentials = callOptions.getCredentials();
									if(credentials instanceof AccessTokenCallCredentials jwtCallCredentials) {
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
