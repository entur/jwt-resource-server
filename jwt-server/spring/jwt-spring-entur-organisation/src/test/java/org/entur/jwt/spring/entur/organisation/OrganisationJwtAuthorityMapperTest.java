package org.entur.jwt.spring.entur.organisation;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.security.core.GrantedAuthority;

import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;

public class OrganisationJwtAuthorityMapperTest {

	private OrganisationJwtAuthorityMapper mapper = new OrganisationJwtAuthorityMapper();

	@Test
	public void testMapper() throws Exception {
		List<GrantedAuthority> grantedAuthorities = mapper.getGrantedAuthorities(getToken());

		List<String> authorities = grantedAuthorities.stream().map(g -> g.getAuthority()).collect(Collectors.toList());

		assertThat(authorities).containsExactly(
				"adminEditRouteData", 
				"editOrganisation",
				"editStops",
				"deleteStops",
				"editStops",
				"deleteStops"
				);
	}

	public DecodedJWT getToken() throws Exception {
		String body = IOUtils.resourceToString("/jwt.txt", StandardCharsets.UTF_8);
		JWTParser parser = new JWTParser();
		Payload payload = parser.parsePayload(body);

		DecodedJWT jwt = mock(DecodedJWT.class);
		when(jwt.getClaim("roles")).then(new Answer<Claim>() {

			@Override
			public Claim answer(InvocationOnMock invocation) throws Throwable {
				return payload.getClaim("roles");
			}
		});
		return jwt;
	}
}
