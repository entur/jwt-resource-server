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

        when(channel.newCall(org.mockito.ArgumentMatchers.eq(method), any(CallOptions.class))).thenReturn(delegateCall);

        ClientCall<Object, Object> wrappedCall = interceptor.interceptCall(method, callOptions, channel);

        ClientCall.Listener<Object> outerListener = mock(ClientCall.Listener.class);
        Metadata startHeaders = new Metadata();
        wrappedCall.start(outerListener, startHeaders);

        var listenerCaptor = forClass(ClientCall.Listener.class);
        verify(delegateCall).start(listenerCaptor.capture(), org.mockito.ArgumentMatchers.eq(startHeaders));
        ClientCall.Listener<Object> innerListener = listenerCaptor.getValue();

        // the call credentials apply the Authorization header (to a per-attempt copy of the headers) once the call has started
        var optionsCaptor = forClass(CallOptions.class);
        verify(channel).newCall(org.mockito.ArgumentMatchers.eq(method), optionsCaptor.capture());
        try {
            when(accessTokenProvider.getAccessToken(false)).thenReturn(new org.entur.jwt.client.AccessToken("a.b.c", "Bearer", System.currentTimeMillis() + 60_000));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        optionsCaptor.getValue().getCredentials().applyRequestMetadata(mock(io.grpc.CallCredentials.RequestInfo.class), Runnable::run, new io.grpc.CallCredentials.MetadataApplier() {
            @Override
            public void apply(Metadata headers) {
            }

            @Override
            public void fail(Status status) {
                throw new AssertionError(status.getCause());
            }
        });

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

        when(channel.newCall(org.mockito.ArgumentMatchers.eq(method), any(CallOptions.class))).thenReturn(delegateCall);

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

        when(channel.newCall(org.mockito.ArgumentMatchers.eq(method), any(CallOptions.class))).thenReturn(delegateCall);

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
}
