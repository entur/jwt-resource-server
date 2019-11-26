package org.entur.jwt.spring.entur.organisation;

import java.util.ArrayList;
import java.util.List;

import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.verifier.JwtClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class OrganisationJwtAuthorityMapper implements JwtAuthorityMapper<DecodedJWT> {

	protected static final Logger logger = LoggerFactory.getLogger(OrganisationJwtAuthorityMapper.class);

	private final ObjectMapper mapper = new ObjectMapper();

	@Override
	public List<GrantedAuthority> getGrantedAuthorities(DecodedJWT token) throws JwtClientException {
		List<GrantedAuthority> authorities = new ArrayList<>();

		// granting a few authorities for framework support, although
		// more detailed check can be performed later.

		Claim claim = token.getClaim("roles");
		String[] rolesJson = claim.as(String[].class);

		// json per role
		for(String roleJson : rolesJson) {
			try {
				JsonNode node = mapper.readTree(roleJson);

				JsonNode jsonNode = node.get("r");
				authorities.add(new SimpleGrantedAuthority(jsonNode.textValue()));
			} catch (Exception e) {
				throw new JwtClientException(e);
			}
		}

		return authorities;
	}



}
