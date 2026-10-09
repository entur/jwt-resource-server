package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class IssuerJwtDecoderFactoryTest {

    private static final JwtDecoder A = token -> {
        throw new IllegalStateException("Not used");
    };
    private static final JwtDecoder B = token -> {
        throw new IllegalStateException("Not used");
    };

    @Test
    public void testSingleIssuerReturnsDecoderDirectly() {
        assertThat(IssuerJwtDecoderFactory.create(Map.of("a", A), true, null, null)).isSameAs(A);
    }

    @Test
    public void testMultipleIssuers() {
        JwtDecoder decoder = IssuerJwtDecoderFactory.create(Map.of("a", A, "b", B), false, null, null);

        assertThat(decoder).isExactlyInstanceOf(IssuerJwtDecoder.class);
        assertThat(((IssuerJwtDecoder) decoder).getJwtDecoders()).containsEntry("a", A).containsEntry("b", B);
    }

    @Test
    public void testMultipleIssuersWithHeaderToIssuerMapping() {
        JwtDecoder decoder = IssuerJwtDecoderFactory.create(Map.of("a", A, "b", B), true, new JwtHeaderToIssuerMapper(), new DefaultJwtHeaderToIssuerMapperDecider());

        assertThat(decoder).isExactlyInstanceOf(FastIssuerJwtDecoder.class);
    }

    @Test
    public void testHeaderToIssuerMappingRequiresMapperAndDecider() {
        Map<String, JwtDecoder> decoders = Map.of("a", A, "b", B);

        assertThatThrownBy(() -> IssuerJwtDecoderFactory.create(decoders, true, null, new DefaultJwtHeaderToIssuerMapperDecider()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JwtHeaderToIssuerMapper");
        assertThatThrownBy(() -> IssuerJwtDecoderFactory.create(decoders, true, new JwtHeaderToIssuerMapper(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JwtHeaderToIssuerMapperDecider");
    }
}
