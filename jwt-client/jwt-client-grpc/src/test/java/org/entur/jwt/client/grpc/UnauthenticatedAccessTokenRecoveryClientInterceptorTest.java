package org.entur.jwt.client.grpc;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import org.entur.jwt.client.recovery.UnauthenticatedAccessTokenRecoveryHandler;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UnauthenticatedAccessTokenRecoveryClientInterceptorTest {

    @SuppressWarnings("unchecked")
    private ClientCall<Object, Object> newMockCall() {
        return mock(ClientCall.class);
    }

    @Test
    public void testBuilderRequiresHandler() {
        assertThrows(IllegalStateException.class, () -> UnauthenticatedAccessTokenRecoveryClientInterceptor.newBuilder().build());
    }

    @Test
    public void testBuilderBuildsWithHandler() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);

        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = UnauthenticatedAccessTokenRecoveryClientInterceptor.newBuilder()
                .withHandler(handler)
                .build();

        assertNotNull(interceptor);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRecoveryHandlerNotInvokedWithoutAccessTokenCredentials() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);
        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);

        Channel channel = mock(Channel.class);
        ClientCall<Object, Object> delegateCall = newMockCall();
        MethodDescriptor<Object, Object> method = mock(MethodDescriptor.class);
        when(channel.newCall(method, CallOptions.DEFAULT)).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, CallOptions.DEFAULT, channel);
        wrappedCall.start(mock(ClientCall.Listener.class), new Metadata());

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), any());
        listenerCaptor.getValue().onClose(Status.UNAUTHENTICATED, new Metadata());

        verify(handler, never()).handle(any(), any(), anyLong());
    }
}
