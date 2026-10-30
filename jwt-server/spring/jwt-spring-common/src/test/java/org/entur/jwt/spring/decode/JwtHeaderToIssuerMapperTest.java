package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtHeaderToIssuerMapperTest {

    private static final String ISSUER_A = "https://issuer.a";
    private static final String ISSUER_B = "https://issuer.b";

    // A minimal fake JWT token: header.payload.signature
    private static String token(String header) {
        return header + ".payload.signature";
    }

    @Test
    void addSameIssuerAgainKeepsMapping() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(ISSUER_A, token("h1"));
        mapper.add(ISSUER_A, token("h1"));

        assertThat(mapper.get(token("h1"))).isEqualTo(ISSUER_A);
        assertThat(mapper.getHeaderToIssuer()).hasSize(1);
        assertThat(mapper.getSharedHeaders()).isEmpty();
    }

    @Test
    void addOtherIssuerForSameHeaderRemovesMapping() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(ISSUER_A, token("h1"));
        mapper.add(ISSUER_A, token("h2"));

        mapper.add(ISSUER_B, token("h1"));

        assertThat(mapper.get(token("h1"))).isNull();
        assertThat(mapper.getSharedHeaders()).containsExactly("h1");
        // other headers are still mapped
        assertThat(mapper.get(token("h2"))).isEqualTo(ISSUER_A);
    }

    @Test
    void sharedHeaderIsNotMappedAgain() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(ISSUER_A, token("h1"));
        mapper.add(ISSUER_B, token("h1"));

        mapper.add(ISSUER_A, token("h1"));
        mapper.add(ISSUER_B, token("h1"));

        assertThat(mapper.get(token("h1"))).isNull();
        assertThat(mapper.getHeaderToIssuer()).isEmpty();
        assertThat(mapper.getSharedHeaders()).containsExactly("h1");
    }

    @Test
    void clearRemovesSharedHeaders() {
        JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
        mapper.add(ISSUER_A, token("h1"));
        mapper.add(ISSUER_B, token("h1"));

        mapper.clear();
        mapper.add(ISSUER_B, token("h1"));

        assertThat(mapper.get(token("h1"))).isEqualTo(ISSUER_B);
        assertThat(mapper.getSharedHeaders()).isEmpty();
    }
}
