package org.entur.jwt.spring.filter.log;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultJwtMappedDiagnosticContextMapperTest {

	@AfterEach
	public void clearMdc() {
		MDC.clear();
	}

	@Test
	public void testMapping() throws Exception {
		List<String> claims = Arrays.asList("azp", "sub");
		List<String> keys = Arrays.asList("clientId", "userId");

		Jwt token = mock(Jwt.class);
		when(token.getClaim("azp")).thenReturn("123");
		when(token.getClaim("sub")).thenReturn("456");

		DefaultJwtMappedDiagnosticContextMapper mapper = new DefaultJwtMappedDiagnosticContextMapper(claims, keys);

		Map<String, String> context = mapper.getContext(token);
		assertThat(context).containsKeys("clientId", "userId");
	}

	@Test
	public void testMappingOfNonStringClaims() throws Exception {
		List<String> claims = Arrays.asList("https://entur.io/organisationID", "aud", "missing");
		List<String> keys = Arrays.asList("organisationId", "audience", "missing");

		Jwt token = Jwt.withTokenValue("token")
				.header("alg", "RS256")
				.claim("https://entur.io/organisationID", 123L)
				.claim("aud", List.of("https://my.audience"))
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(60))
				.build();

		DefaultJwtMappedDiagnosticContextMapper mapper = new DefaultJwtMappedDiagnosticContextMapper(claims, keys);

		Map<String, String> context = mapper.getContext(token);
		assertThat(context).containsOnly(Map.entry("organisationId", "123"), Map.entry("audience", "[https://my.audience]"));

		mapper.addContext(token);
		assertThat(MDC.get("organisationId")).isEqualTo("123");
		assertThat(MDC.get("audience")).isEqualTo("[https://my.audience]");
		assertThat(MDC.get("missing")).isNull();
	}

}
