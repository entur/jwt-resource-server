package org.entur.jwt.spring.filter.log;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.entur.jwt.verifier.JwtClaimException;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.junit.jupiter.api.Test;

public class DefaultJwtMappedDiagnosticContextMapperTest {
	
	@Test
	public void testMapping() throws JwtClaimException {
		List<String> claims = Arrays.asList("azp", "sub");
		List<String> keys = Arrays.asList("clientId", "userId");
		
		Object token = new Object();
		
		JwtClaimExtractor<Object> extractor = mock(JwtClaimExtractor.class);
		when(extractor.getClaim(token, "azp", String.class)).thenReturn("myClientId");
		when(extractor.getClaim(token, "sub", String.class)).thenReturn("myUserId");
		
		DefaultJwtMappedDiagnosticContextMapper<Object> mapper = new DefaultJwtMappedDiagnosticContextMapper<>(claims, keys, extractor);
		
		Map<String, String> context = mapper.getContext(token);
		assertThat(context).containsKeys("clientId", "userId");
	}

}
