package org.entur.jwt.client.grpc;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import io.grpc.Status;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.junit.jupiter.api.Test;

import java.util.concurrent.Executor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AccessTokenCallCredentialsTest {

    private final Executor sameThreadExecutor = Runnable::run;

    @Test
    public void testApplyRequestMetadataAddsBearerHeader() throws AccessTokenException {
        AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
        when(accessTokenProvider.getAccessToken(false)).thenReturn(AccessToken.newInstance("a.b.c", "bearer", Long.MAX_VALUE));

        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);

        CallCredentials.MetadataApplier metadataApplier = mock(CallCredentials.MetadataApplier.class);

        credentials.applyRequestMetadata(mock(CallCredentials.RequestInfo.class), sameThreadExecutor, metadataApplier);

        var headersCaptor = org.mockito.ArgumentCaptor.forClass(Metadata.class);
        verify(metadataApplier).apply(headersCaptor.capture());

        assertEquals("Bearer a.b.c", headersCaptor.getValue().get(AccessTokenCallCredentials.KEY_AUTHORIZATION));
    }

    @Test
    public void testApplyRequestMetadataFailsOnProviderException() throws AccessTokenException {
        AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
        AccessTokenException exception = new AccessTokenException("boom");
        when(accessTokenProvider.getAccessToken(false)).thenThrow(exception);

        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);

        CallCredentials.MetadataApplier metadataApplier = mock(CallCredentials.MetadataApplier.class);

        credentials.applyRequestMetadata(mock(CallCredentials.RequestInfo.class), sameThreadExecutor, metadataApplier);

        var statusCaptor = org.mockito.ArgumentCaptor.forClass(Status.class);
        verify(metadataApplier).fail(statusCaptor.capture());

        assertEquals(Status.Code.UNAVAILABLE, statusCaptor.getValue().getCode());
        assertSame(exception, statusCaptor.getValue().getCause());
    }

    @Test
    public void testGetAccessTokenProvider() {
        AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
        AccessTokenCallCredentials credentials = new AccessTokenCallCredentials(accessTokenProvider);

        assertSame(accessTokenProvider, credentials.getAccessTokenProvider());
    }

    @Test
    public void testExtractJwtWithBearerPrefix() {
        assertEquals("a.b.c", AccessTokenCallCredentials.extractJwt("Bearer a.b.c"));
    }

    @Test
    public void testExtractJwtWithoutBearerPrefix() {
        assertNull(AccessTokenCallCredentials.extractJwt("a.b.c"));
    }

    @Test
    public void testExtractJwtWithNullHeader() {
        assertNull(AccessTokenCallCredentials.extractJwt(null));
    }
}
