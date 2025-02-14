package org.entur.jwt.client.grpc;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadPoolExecutor;

import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RatelimitedJwkRotationAccessTokenRecoveryHandlerTest {

    @Test
    public void testForceRefresh() throws Exception {
        RatelimitedJwkRotationAccessTokenRecoveryHandler handler = new RatelimitedJwkRotationAccessTokenRecoveryHandler(30_000L);

        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken accessToken = new AccessToken(authorizationHeader, "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(accessToken);

            AccessToken refreshedAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            ThreadPoolExecutor executor = handler.getExecutor();
            long deadline = System.currentTimeMillis() + 1000;
            while (System.currentTimeMillis() < deadline && (executor.getActiveCount() > 0 || executor.getQueue().size() > 0))
                ;

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(1)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }

    @Test
    public void testAlreadyRefreshed() throws Exception {
        RatelimitedJwkRotationAccessTokenRecoveryHandler handler = new RatelimitedJwkRotationAccessTokenRecoveryHandler(30_000L);
        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken otherAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(otherAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            ThreadPoolExecutor executor = handler.getExecutor();
            long deadline = System.currentTimeMillis() + 1000;
            while(System.currentTimeMillis() < deadline && (executor.getActiveCount() > 0 || executor.getQueue().size() > 0) );

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(0)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }
}
