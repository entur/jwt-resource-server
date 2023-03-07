package org.entur.jwt.spring.filter.log;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultJwtMappedDiagnosticContextMapperTest {

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

}
