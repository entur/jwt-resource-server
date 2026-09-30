package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RetryingJWKSetSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import java.util.List;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DecodedJwtCacheJwkEventListenerTest {

    private final DecodedJwtCacheJwtDecoder decoder = mock(DecodedJwtCacheJwtDecoder.class);
    private final DecodedJwtCacheJwkEventListener listener = new DecodedJwtCacheJwkEventListener(decoder);

    private final JWKSet jwkSet = new JWKSet();

    private final ListAppender<ILoggingEvent> logAppender = new ListAppender<>();

    @SuppressWarnings("unchecked")
    private CachingJWKSetSource.RefreshCompletedEvent<?> refreshCompleted() {
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        return event;
    }

    private OutageTolerantJWKSetSource.OutageEvent<?> outage(long remainingTime) {
        return outage(100_000, remainingTime);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private OutageTolerantJWKSetSource.OutageEvent<?> outage(long timeToLive, long remainingTime) {
        OutageTolerantJWKSetSource source = mock(OutageTolerantJWKSetSource.class);
        when(source.getTimeToLive()).thenReturn(timeToLive);

        OutageTolerantJWKSetSource.OutageEvent event = mock(OutageTolerantJWKSetSource.OutageEvent.class);
        when(event.getRemainingTime()).thenReturn(remainingTime);
        when(event.getSource()).thenReturn(source);
        return event;
    }

    private List<String> warnings() {
        return logAppender.list.stream().filter(e -> e.getLevel().isGreaterOrEqual(Level.WARN)).map(ILoggingEvent::getFormattedMessage).toList();
    }

    @BeforeEach
    void setUpLogCapture() {
        logAppender.start();
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwkEventListener.class)).addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwkEventListener.class)).detachAppender(logAppender);
    }

    @Test
    void testWarnsAtHalfAndThreeQuartersOfJwkOutageCacheTimeToLive() {
        listener.notify(outage(1000, 900)); // 10%
        assertThat(warnings()).isEmpty();

        listener.notify(outage(1000, 500)); // 50%
        assertThat(warnings()).hasSize(1);
        assertThat(warnings().get(0)).contains("50%", "500 ms left");

        listener.notify(outage(1000, 400)); // 60%, already warned
        assertThat(warnings()).hasSize(1);

        listener.notify(outage(1000, 200)); // 80%
        assertThat(warnings()).hasSize(2);
        assertThat(warnings().get(1)).contains("75%", "200 ms left");

        listener.notify(outage(1000, 100));
        assertThat(warnings()).hasSize(2);
    }

    @Test
    void testWarnsBothWhenFirstOutageEventIsLate() {
        listener.notify(outage(1000, 100)); // 90%
        assertThat(warnings()).hasSize(2);
    }

    @Test
    void testRefreshResetsWarnings() {
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(outage(1000, 100));
        listener.notify(refreshCompleted());
        assertThat(warnings()).hasSize(2);

        // successful refresh
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(refreshCompleted());

        // new outage
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(outage(1000, 500));
        assertThat(warnings()).hasSize(3);
    }

    @Test
    void testRefreshUpdatesKeysAndResumes() {
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(refreshCompleted());

        var order = inOrder(decoder);
        order.verify(decoder).updateKeys(jwkSet);
        order.verify(decoder).resume();
        verify(decoder, never()).suspendAt(anyLong());
    }

    @Test
    void testRefreshServedFromJwkOutageCacheSuspendsWhenOutageCacheExpires() {
        long before = System.currentTimeMillis();

        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(mock(RetryingJWKSetSource.RetrialEvent.class));
        listener.notify(outage(60_000));
        listener.notify(refreshCompleted());

        ArgumentCaptor<Long> suspendAt = ArgumentCaptor.forClass(Long.class);
        verify(decoder).suspendAt(suspendAt.capture());
        assertThat(suspendAt.getValue()).isBetween(before + 60_000, System.currentTimeMillis() + 60_000);

        verify(decoder).updateKeys(jwkSet);
        verify(decoder, never()).resume();
    }

    @Test
    void testRefreshAfterOutageResumes() {
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(outage(60_000));
        listener.notify(refreshCompleted());

        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(refreshCompleted());

        verify(decoder, times(1)).suspendAt(anyLong());
        verify(decoder, times(1)).resume();
    }

    @Test
    void testFailureWithoutOutageCacheSuspendsNow() {
        listener.notify(mock(CachingJWKSetSource.UnableToRefreshEvent.class));
        listener.notify(mock(RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent.class));
        listener.notify(mock(RefreshAheadCachingJWKSetSource.ScheduledRefreshFailed.class));

        ArgumentCaptor<Long> suspendAt = ArgumentCaptor.forClass(Long.class);
        verify(decoder, times(3)).suspendAt(suspendAt.capture());
        assertThat(suspendAt.getAllValues()).allMatch(t -> t <= System.currentTimeMillis());
    }

    @Test
    void testIgnoresOtherEvents() {
        listener.notify(mock(CachingJWKSetSource.RefreshInitiatedEvent.class));
        listener.notify(mock(CachingJWKSetSource.WaitingForRefreshEvent.class));
        listener.notify(mock(CachingJWKSetSource.RefreshTimedOutEvent.class));
        listener.notify(mock(RefreshAheadCachingJWKSetSource.ScheduledRefreshInitiatedEvent.class));

        verifyNoInteractions(decoder);
    }
}
