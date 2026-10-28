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
    public void testRecoveryHandlerInvokedOnUnauthenticatedCloseWithCredentials() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);
        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);

        Channel channel = mock(Channel.class);
        ClientCall<Object, Object> delegateCall = newMockCall();
        MethodDescriptor<Object, Object> method = mock(MethodDescriptor.class);

        org.entur.jwt.client.AccessTokenProvider accessTokenProvider = mock(org.entur.jwt.client.AccessTokenProvider.class);
        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);
        CallOptions callOptions = CallOptions.DEFAULT.withCallCredentials(credentials);

        when(channel.newCall(method, callOptions)).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, callOptions, channel);

        ClientCall.Listener<Object> outerListener = mock(ClientCall.Listener.class);
        Metadata startHeaders = new Metadata();
        wrappedCall.start(outerListener, startHeaders);

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), org.mockito.ArgumentMatchers.eq(startHeaders));
        ClientCall.Listener<Object> innerListener = listenerCaptor.getValue();

        // the call credentials add the Authorization header to the request headers once the call has started
        startHeaders.put(AccessTokenCallCredentials.KEY_AUTHORIZATION, "Bearer a.b.c");

        // the server typically rejects unauthenticated calls with a trailers-only response, i.e. without headers
        Metadata trailers = new Metadata();
        innerListener.onClose(Status.UNAUTHENTICATED, trailers);

        verify(handler).handle(org.mockito.ArgumentMatchers.eq(accessTokenProvider), org.mockito.ArgumentMatchers.eq("Bearer a.b.c"), org.mockito.ArgumentMatchers.anyLong());
        verify(outerListener).onClose(Status.UNAUTHENTICATED, trailers);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRecoveryHandlerNotInvokedWhenStatusOk() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);
        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);

        Channel channel = mock(Channel.class);
        ClientCall<Object, Object> delegateCall = newMockCall();
        MethodDescriptor<Object, Object> method = mock(MethodDescriptor.class);

        org.entur.jwt.client.AccessTokenProvider accessTokenProvider = mock(org.entur.jwt.client.AccessTokenProvider.class);
        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);
        CallOptions callOptions = CallOptions.DEFAULT.withCallCredentials(credentials);

        when(channel.newCall(method, callOptions)).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, callOptions, channel);

        ClientCall.Listener<Object> outerListener = mock(ClientCall.Listener.class);
        Metadata startHeaders = new Metadata();
        wrappedCall.start(outerListener, startHeaders);

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), any());
        ClientCall.Listener<Object> innerListener = listenerCaptor.getValue();

        startHeaders.put(AccessTokenCallCredentials.KEY_AUTHORIZATION, "Bearer a.b.c");

        Metadata responseHeaders = new Metadata();
        innerListener.onHeaders(responseHeaders);
        verify(outerListener).onHeaders(responseHeaders);

        innerListener.onClose(Status.OK, new Metadata());

        verify(handler, never()).handle(any(), any(), org.mockito.ArgumentMatchers.anyLong());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRecoveryHandlerNotInvokedWithoutCapturedAuthorizationHeader() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);
        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);

        Channel channel = mock(Channel.class);
        ClientCall<Object, Object> delegateCall = newMockCall();
        MethodDescriptor<Object, Object> method = mock(MethodDescriptor.class);

        org.entur.jwt.client.AccessTokenProvider accessTokenProvider = mock(org.entur.jwt.client.AccessTokenProvider.class);
        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);
        CallOptions callOptions = CallOptions.DEFAULT.withCallCredentials(credentials);

        when(channel.newCall(method, callOptions)).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, callOptions, channel);

        ClientCall.Listener<Object> outerListener = mock(ClientCall.Listener.class);
        wrappedCall.start(outerListener, new Metadata());

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), any());
        ClientCall.Listener<Object> innerListener = listenerCaptor.getValue();

        // no authorization header was added to the request
        innerListener.onClose(Status.UNAUTHENTICATED, new Metadata());

        verify(handler, never()).handle(any(), any(), org.mockito.ArgumentMatchers.anyLong());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testRecoveryHandlerNotInvokedForAuthorizationHeaderInResponse() {
        UnauthenticatedAccessTokenRecoveryHandler handler = mock(UnauthenticatedAccessTokenRecoveryHandler.class);
        UnauthenticatedAccessTokenRecoveryClientInterceptor interceptor = new UnauthenticatedAccessTokenRecoveryClientInterceptor(handler);

        Channel channel = mock(Channel.class);
        ClientCall<Object, Object> delegateCall = newMockCall();
        MethodDescriptor<Object, Object> method = mock(MethodDescriptor.class);

        org.entur.jwt.client.AccessTokenProvider accessTokenProvider = mock(org.entur.jwt.client.AccessTokenProvider.class);
        CallOptions callOptions = CallOptions.DEFAULT.withCallCredentials(new AccessTokenCallCredentials(accessTokenProvider));

        when(channel.newCall(method, callOptions)).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, callOptions, channel);
        wrappedCall.start(mock(ClientCall.Listener.class), new Metadata());

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), any());
        ClientCall.Listener<Object> innerListener = listenerCaptor.getValue();

        // a header returned by the server says nothing about which token the client sent
        Metadata responseHeaders = new Metadata();
        responseHeaders.put(AccessTokenCallCredentials.KEY_AUTHORIZATION, "Bearer x.y.z");
        innerListener.onHeaders(responseHeaders);
        innerListener.onClose(Status.UNAUTHENTICATED, new Metadata());

        verify(handler, never()).handle(any(), any(), org.mockito.ArgumentMatchers.anyLong());
    }
}
