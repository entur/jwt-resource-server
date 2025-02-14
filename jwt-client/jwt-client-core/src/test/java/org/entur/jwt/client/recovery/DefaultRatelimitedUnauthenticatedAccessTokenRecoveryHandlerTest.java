package org.entur.jwt.client.recovery;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.concurrent.ThreadPoolExecutor;

import static org.mockito.Mockito.*;

public class DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandlerTest {

    @Test
    public void testForceRefresh() throws Exception {
        DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler = new DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(30_000L);

        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken accessToken = new AccessToken(authorizationHeader, "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(accessToken);

            AccessToken refreshedAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            wait(handler);

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(1)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }

    @Test
    public void testAlreadyRefreshed() throws Exception {
        DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler = new DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(30_000L);
        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken otherAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(otherAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            wait(handler);

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(0)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }

    @Test
    public void testRatelimited() throws Exception {
        DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler = new DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(30_000L);

        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken accessToken = new AccessToken(authorizationHeader, "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(accessToken);

            AccessToken refreshedAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            wait(handler);

            // handle again, assume rate-limited
            handler.handle(accessTokenProvider, authorizationHeader, timestamp + 1);

            wait(handler);

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(1)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }

    @Test
    public void testWaitForRatelimit() throws Exception {
        DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler = new DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(30_000L);

        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken accessToken = new AccessToken(authorizationHeader, "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(accessToken);

            AccessToken refreshedAccessToken = new AccessToken("a.b.c", "bearer", 0);
            when(accessTokenProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);

            long timestamp = System.currentTimeMillis();
            handler.handle(accessTokenProvider, authorizationHeader, timestamp);

            wait(handler);

            // handle again, assume rate-limited
            handler.handle(accessTokenProvider, authorizationHeader, timestamp + 1);

            wait(handler);

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(1)).getAccessToken(true);

            // handle again, assume no longer rate-limited
            handler.handle(accessTokenProvider, authorizationHeader, timestamp + 30_000L + 1000);

            wait(handler);

            verify(accessTokenProvider, times(2)).getAccessToken(false);
            verify(accessTokenProvider, times(2)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }


    @Test
    public void testRatelimitedWithHeavyLoad() throws Exception {
        DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler = new DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(30_000L);

        try {
            AccessTokenProvider accessTokenProvider = mock(AccessTokenProvider.class);
            String authorizationHeader = "Bearer x.y.z";

            AccessToken accessToken = new AccessToken(authorizationHeader, "bearer", 0);
            when(accessTokenProvider.getAccessToken(false)).thenReturn(accessToken);

            AccessToken refreshedAccessToken = new AccessToken("a.b.c", "bearer", 0);
            doAnswer(new Answer() {
                @Override
                public Object answer(InvocationOnMock invocation) throws Throwable {
                    Thread.sleep(250);
                    return refreshedAccessToken;
                }
            }).when(accessTokenProvider).getAccessToken(true);

            long timestamp = System.currentTimeMillis();

            for(int i = 0; i < 1000; i++) {
                handler.handle(accessTokenProvider, authorizationHeader, timestamp + i);
            }

            wait(handler);

            verify(accessTokenProvider, times(1)).getAccessToken(false);
            verify(accessTokenProvider, times(1)).getAccessToken(true);
        } finally {
            handler.close();
        }
    }


    private static void wait(DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler handler) throws InterruptedException {
        ThreadPoolExecutor executor = handler.getExecutor();
        long deadline = System.currentTimeMillis() + 1000;
        Thread.sleep(10);
        while (System.currentTimeMillis() < deadline && (executor.getActiveCount() > 0 || executor.getQueue().size() > 0)) {
            Thread.yield();
        }
    }

}