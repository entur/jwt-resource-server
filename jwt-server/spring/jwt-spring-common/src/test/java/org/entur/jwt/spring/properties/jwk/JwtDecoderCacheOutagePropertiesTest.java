package org.entur.jwt.spring.properties.jwk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JwtDecoderCacheOutagePropertiesTest {

    @Test
    public void testDefaultTimeToLiveIsTenHoursInSeconds() {
        JwtDecoderCacheOutageProperties properties = new JwtDecoderCacheOutageProperties();

        assertEquals(10 * 60 * 60L, properties.getTimeToLive());
    }

    @Test
    public void testSetTimeToLiveAcceptsNonNegativeValue() {
        JwtDecoderCacheOutageProperties properties = new JwtDecoderCacheOutageProperties();

        properties.setTimeToLive(3600L);

        assertEquals(3600L, properties.getTimeToLive());
    }

    @Test
    public void testSetTimeToLiveAcceptsNegativeOneForIndefiniteTolerance() {
        JwtDecoderCacheOutageProperties properties = new JwtDecoderCacheOutageProperties();

        properties.setTimeToLive(-1L);

        assertEquals(-1L, properties.getTimeToLive());
    }

    @Test
    public void testSetTimeToLiveRejectsValuesLessThanNegativeOne() {
        JwtDecoderCacheOutageProperties properties = new JwtDecoderCacheOutageProperties();

        assertThrows(IllegalArgumentException.class, () -> properties.setTimeToLive(-2L));
        assertThrows(IllegalArgumentException.class, () -> properties.setTimeToLive(Long.MIN_VALUE));
    }
}
