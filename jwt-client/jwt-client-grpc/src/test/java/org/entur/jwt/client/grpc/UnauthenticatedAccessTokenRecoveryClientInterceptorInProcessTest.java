package org.entur.jwt.client.grpc;

import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.recovery.UnauthenticatedAccessTokenRecoveryHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercise the interceptor together with {@linkplain AccessTokenCallCredentials} over a real (in-process) channel,
 * so that the Authorization header is added by gRPC itself and not by the test.
 */

public class UnauthenticatedAccessTokenRecoveryClientInterceptorInProcessTest {

    private static final MethodDescriptor.Marshaller<String> STRING_MARSHALLER = new MethodDescriptor.Marshaller<>() {
        @Override
        public InputStream stream(String value) {
            return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public String parse(InputStream stream) {
            try {
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    };

    private static final MethodDescriptor<String, String> METHOD = MethodDescriptor.<String, String>newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName(MethodDescriptor.generateFullMethodName("test.Greeter", "Greet"))
            .setRequestMarshaller(STRING_MARSHALLER)
            .setResponseMarshaller(STRING_MARSHALLER)
            .build();

    private final AtomicReference<Status> serverStatus = new AtomicReference<>();
    private final AtomicReference<String> receivedAuthorization = new AtomicReference<>();

    private String serverName;
    private Server server;
    private ManagedChannel channel;
    private UnauthenticatedAccessTokenRecoveryHandler handler;
    private AccessTokenProvider accessTokenProvider;

    private ManagedChannel newChannel(boolean retry) {
        InProcessChannelBuilder builder = InProcessChannelBuilder.forName(serverName).directExecutor();
        if (retry) {
            builder.enableRetry();
        }
        return builder.intercept(new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler)).build();
    }

    @BeforeEach
    public void setUp() throws Exception {
        ServerServiceDefinition service = ServerServiceDefinition.builder("test.Greeter")
                .addMethod(METHOD, ServerCalls.asyncUnaryCall((request, responseObserver) -> {
                    Status status = serverStatus.get();
                    if (status.isOk()) {
                        responseObserver.onNext("Hello " + request);
                        responseObserver.onCompleted();
                    } else {
                        responseObserver.onError(status.asRuntimeException());
                    }
                }))
                .build();

        ServerInterceptor captureAuthorization = new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                receivedAuthorization.set(headers.get(AccessTokenCallCredentials.KEY_AUTHORIZATION));
                return next.startCall(call, headers);
            }
        };

        serverName = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(ServerInterceptors.intercept(service, captureAuthorization))
                .build()
                .start();

        handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);

        channel = newChannel(false);

        accessTokenProvider = mock(AccessTokenProvider.class);
        when(accessTokenProvider.getAccessToken(false)).thenReturn(new AccessToken("a.b.c", "Bearer", System.currentTimeMillis() + 60_000));
    }

    @Test
    public void testRecoveryHandlerInvokedWhenRetryIsEnabled() {
        channel.shutdownNow();
        channel = newChannel(true);
        serverStatus.set(Status.UNAUTHENTICATED);

        assertThrows(StatusRuntimeException.class, this::call);

        verify(handler).handle(eq(accessTokenProvider), eq(receivedAuthorization.get()), anyLong());
    }

    @AfterEach
    public void tearDown() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    private String call() {
        CallOptions callOptions = CallOptions.DEFAULT.withCallCredentials(new AccessTokenCallCredentials(accessTokenProvider));
        return ClientCalls.blockingUnaryCall(channel, METHOD, callOptions, "world");
    }

    @Test
    public void testRecoveryHandlerInvokedWithTheRejectedAuthorizationHeader() {
        serverStatus.set(Status.UNAUTHENTICATED);

        StatusRuntimeException e = assertThrows(StatusRuntimeException.class, this::call);
        assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());

        assertEquals("Bearer a.b.c", receivedAuthorization.get());
        verify(handler).handle(eq(accessTokenProvider), eq("Bearer a.b.c"), anyLong());
    }

    @Test
    public void testRecoveryHandlerNotInvokedWhenTokenWasRefreshedSinceTheCallStarted() throws Exception {
        // the first two lookups are the interceptor's and the call credentials', then the token is refreshed
        when(accessTokenProvider.getAccessToken(false)).thenReturn(
                new AccessToken("a.b.c", "Bearer", System.currentTimeMillis() + 60_000),
                new AccessToken("a.b.c", "Bearer", System.currentTimeMillis() + 60_000),
                new AccessToken("d.e.f", "Bearer", System.currentTimeMillis() + 60_000));
        serverStatus.set(Status.UNAUTHENTICATED);

        assertThrows(StatusRuntimeException.class, this::call);

        verify(handler, never()).handle(any(), any(), anyLong());
    }

    @Test
    public void testRecoveryHandlerNotInvokedOnSuccess() {
        serverStatus.set(Status.OK);

        assertEquals("Hello world", call());

        assertEquals("Bearer a.b.c", receivedAuthorization.get());
        verify(handler, never()).handle(any(), any(), anyLong());
    }

    @Test
    public void testRecoveryHandlerNotInvokedOnOtherErrors() {
        serverStatus.set(Status.PERMISSION_DENIED);

        StatusRuntimeException e = assertThrows(StatusRuntimeException.class, this::call);
        assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());

        verify(handler, never()).handle(any(), any(), anyLong());
    }
}
