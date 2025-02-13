package org.entur.jwt.client.grpc;

/*-
 * #%L
 * abt-protobuf-client-utils
 * %%
 * Copyright (C) 2019 - 2021 Entur
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.ThreadFactoryBuilder;

import io.grpc.*;

/**
 * Based on https://github.com/facebook/buck/tree/master/src/com/facebook/buck/remoteexecution/grpc/retry Interceptor for retrying client calls. Only retries in
 * the following circumstances:
 *
 * <ul>
 * <li>An UNAVAILABLE error is returned
 * <li>The client only has a single request (there can be multiple responses from the server)
 * <li>No responses in a stream have been received from the server.
 * </ul>
 */
public class RetryClientInterceptor implements ClientInterceptor {
	private final int maxRetries;
	private final long backoffDelayMilliseconds;
	private final boolean restartAllStreamingCalls = false;
	private final ScheduledExecutorService executorService;

	public RetryClientInterceptor(int maxRetries, long backoffDelayMilliseconds) {
		this.maxRetries = maxRetries;
		this.backoffDelayMilliseconds = backoffDelayMilliseconds;
		executorService = Executors.newSingleThreadScheduledExecutor(new ThreadFactoryBuilder().setNameFormat("retryer-%s").setDaemon(true).build());
	}

	@PreDestroy
	public void shutdown() {
		if (null != executorService) {
			executorService.shutdown();
		}
	}

	@Override
	public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(final MethodDescriptor<ReqT, RespT> method, final CallOptions callOptions, final Channel next) {
		if (!method.getType().clientSendsOneMessage()) {
			return next.newCall(method, callOptions);
		}

		// TODO: Check if the method is immutable and retryable
		return new ReplayingSingleSendClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
			private int attemptNumber = 0;
			private Future<?> future = null;

			@Override
			public void start(Listener<RespT> responseListener, Metadata headers) {
				super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<RespT>(responseListener) {
					private boolean receivedAResponse = false;

					@Override
					public void onClose(Status status, Metadata trailers) {
						cancelAttempt();

						if (status.getCode() != Status.Code.UNAVAILABLE || (receivedAResponse && !restartAllStreamingCalls) || attemptNumber >= maxRetries) {
							super.onClose(status, trailers);
							return;
						}
						attemptNumber++;
						final Runnable runnable = Context.current().wrap(() -> replay(next.newCall(method, callOptions)));
						future = backoffDelayMilliseconds == 0 ? executorService.submit(runnable)
								: executorService.schedule(runnable, backoffDelayMilliseconds, TimeUnit.MILLISECONDS);
					}

					@Override
					public void onMessage(RespT message) {
						receivedAResponse = true;
						super.onMessage(message);
					}
				}, headers);
			}

			@Override
			public void cancel(String message, Throwable cause) {
				cancelAttempt();
				super.cancel(message, cause);
			}

			private void cancelAttempt() {
				if (future != null) {
					future.cancel(true);
				}
			}
		};

	}

	static class ReplayingSingleSendClientCall<ReqT, RespT> extends ClientCall<ReqT, RespT> {
		private Metadata.Key<String> jwtKey = Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);
		private ClientCall<ReqT, RespT> delegate;
		private Listener<RespT> responseListener;
		private Metadata headers;
		private ReqT message;
		private int numMessages;
		private boolean messageCompressionEnabled = false;

		public ReplayingSingleSendClientCall(ClientCall<ReqT, RespT> delegate) {
			this.delegate = delegate;
		}

		@Override
		public void start(Listener<RespT> responseListener, Metadata headers) {
			this.responseListener = responseListener;
			this.headers = headers;
			this.delegate.start(responseListener, headers);
		}

		@Override
		public void request(int numMessages) {
			this.numMessages = numMessages;
			this.delegate.request(numMessages);
		}

		@Override
		public void cancel(String message, Throwable cause) {
			this.delegate.cancel(message, cause);
		}

		@Override
		public void halfClose() {
			this.delegate.halfClose();
		}

		@Override
		public void sendMessage(ReqT message) {
			this.message = message;
			this.delegate.sendMessage(message);
		}

		@Override
		public void setMessageCompression(boolean enabled) {
			this.messageCompressionEnabled = enabled;
		}

		@Override
		public boolean isReady() {
			return delegate.isReady();
		}

		public void replay(ClientCall<ReqT, RespT> delegate) {
			this.delegate = delegate;
			try {
				this.delegate.start(responseListener, new Metadata());
				this.delegate.setMessageCompression(messageCompressionEnabled);
				this.delegate.request(numMessages);
				this.delegate.sendMessage(message);
				this.delegate.halfClose();
			} catch (Throwable t) {
				this.delegate.cancel(t.getMessage(), t);
			}
		}
	}
}
