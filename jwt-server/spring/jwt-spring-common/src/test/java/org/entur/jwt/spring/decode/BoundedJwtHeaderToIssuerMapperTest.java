package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BoundedJwtHeaderToIssuerMapperTest {

    // A minimal fake JWT token: header.payload.signature
    private static String token(String header) {
        return header + ".payload.signature";
    }

    // -----------------------------------------------------------------------
    // Constructor / initial state
    // -----------------------------------------------------------------------

    @Test
    void initiallyEnabled() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        assertFalse(mapper.isDisabled());
    }

    // -----------------------------------------------------------------------
    // Normal operation (within bounds)
    // -----------------------------------------------------------------------

    @Test
    void addAndGetWithinBounds() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        String tok = token("headerA");
        mapper.add("https://issuer.example.com", tok);
        assertEquals("https://issuer.example.com", mapper.get(tok));
    }

    @Test
    void getReturnsNullForUnknownHeader() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        assertNull(mapper.get(token("unknownHeader")));
    }

    @Test
    void getReturnsNullForMalformedToken() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        assertNull(mapper.get("notAJwtToken"));
    }

    // -----------------------------------------------------------------------
    // Disabled state (via setDisabled)
    // -----------------------------------------------------------------------

    @Test
    void getReturnsNullWhenDisabled() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        String tok = token("headerA");
        mapper.add("https://issuer.example.com", tok);
        mapper.setDisabled(true);
        assertNull(mapper.get(tok));
    }

    @Test
    void addIsNoOpWhenDisabled() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        mapper.setDisabled(true);
        mapper.add("https://issuer.example.com", token("headerA"));
        assertTrue(mapper.getHeaderToIssuer().isEmpty());
    }

    @Test
    void setDisabledFalseReenablesLookups() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(5);
        String tok = token("headerA");
        mapper.add("https://issuer.example.com", tok);
        mapper.setDisabled(true);
        mapper.setDisabled(false);
        assertEquals("https://issuer.example.com", mapper.get(tok));
    }

    // -----------------------------------------------------------------------
    // Automatic disabling when maxSize is exceeded
    // -----------------------------------------------------------------------

    @Test
    void disablesWhenMaxSizeExceeded() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(2);

        mapper.add("issuer1", token("h1"));
        mapper.add("issuer2", token("h2"));
        assertFalse(mapper.isDisabled(), "should still be enabled at exactly maxSize");

        mapper.add("issuer3", token("h3"));
        assertTrue(mapper.isDisabled(), "should be disabled after exceeding maxSize");
    }

    @Test
    void getReturnsNullAfterAutoDisable() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(1);
        String tok1 = token("h1");
        String tok2 = token("h2");
        mapper.add("issuer1", tok1);
        mapper.add("issuer2", tok2); // triggers disable

        assertNull(mapper.get(tok1));
        assertNull(mapper.get(tok2));
    }

    // -----------------------------------------------------------------------
    // Unlimited mode (maxSize = -1)
    // -----------------------------------------------------------------------

    @Test
    void unlimitedModeNeverDisables() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(-1);

        for (int i = 0; i < 1000; i++) {
            mapper.add("issuer" + i, token("h" + i));
        }
        assertFalse(mapper.isDisabled());
        assertEquals("issuer42", mapper.get(token("h42")));
    }

    // -----------------------------------------------------------------------
    // maxSize = 0 edge case
    // -----------------------------------------------------------------------

    @Test
    void maxSizeZeroDisablesOnFirstAdd() {
        BoundedJwtHeaderToIssuerMapper mapper = new BoundedJwtHeaderToIssuerMapper(0);
        mapper.add("issuer1", token("h1"));
        assertTrue(mapper.isDisabled());
    }
}
