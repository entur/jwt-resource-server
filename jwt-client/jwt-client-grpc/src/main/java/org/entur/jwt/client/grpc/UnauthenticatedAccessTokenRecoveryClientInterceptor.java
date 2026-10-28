package org.entur.jwt.client.grpc;

import io.grpc.CallCredentials;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
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

		CallCredentials credentials = callOptions.getCredentials();
		AtomicReference<String> authorization = new AtomicReference<>();
		if(credentials instanceof AccessTokenCallCredentials) {
			// capture the header as applied by the credentials; with retries enabled the metadata
			// is copied per attempt, so the request headers passed to start(..) cannot be relied on
			callOptions = callOptions.withCallCredentials(new CapturingCallCredentials(credentials, authorization));
		}

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
							if(status.getCode() == Status.Code.UNAUTHENTICATED) {
								String authorizationHeader = authorization.get();
								if(authorizationHeader != null && credentials instanceof AccessTokenCallCredentials jwtCallCredentials) {
									handler.handle(jwtCallCredentials.getAccessTokenProvider(), authorizationHeader, System.currentTimeMillis());
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

	private static class CapturingCallCredentials extends CallCredentials {

		private final CallCredentials delegate;
		private final AtomicReference<String> authorization;

		CapturingCallCredentials(CallCredentials delegate, AtomicReference<String> authorization) {
			this.delegate = delegate;
			this.authorization = authorization;
		}

		@Override
		public void applyRequestMetadata(RequestInfo requestInfo, Executor appExecutor, MetadataApplier applier) {
			delegate.applyRequestMetadata(requestInfo, appExecutor, new MetadataApplier() {
				@Override
				public void apply(Metadata headers) {
					authorization.set(headers.get(AccessTokenCallCredentials.KEY_AUTHORIZATION));
					applier.apply(headers);
				}

				@Override
				public void fail(Status status) {
					applier.fail(status);
				}
			});
		}
	}
}
