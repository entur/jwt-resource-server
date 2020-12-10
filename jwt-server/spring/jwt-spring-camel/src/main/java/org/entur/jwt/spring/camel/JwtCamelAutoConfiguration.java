package org.entur.jwt.spring.camel;

import java.util.ArrayList;
import java.util.List;

import org.apache.camel.component.spring.security.SpringSecurityAccessPolicy;
import org.apache.camel.component.spring.security.SpringSecurityAuthorizationPolicy;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.spring.filter.JwtDetailsMapper;
import org.entur.jwt.spring.filter.JwtPrincipalMapper;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;

//  http://fusetoolbox.blogspot.com/2015/06/camel-spring-security-and-oauth.html

@Configuration
public class JwtCamelAutoConfiguration {

	@Bean(name = "validTokenAccessPolicy")
	public SpringSecurityAuthorizationPolicy validTokenAccessPolicy() {
		SpringSecurityAuthorizationPolicy policy = new SpringSecurityAuthorizationPolicy();
		policy.setAccessDecisionManager(accessDecisionManager());
		policy.setAuthenticationManager(new JwtAuthenticationManager());
		policy.setUseThreadSecurityContext(false); // rather set authentication on message

		SpringSecurityAccessPolicy p = new SpringSecurityAccessPolicy(AuthenticatedVoter.IS_AUTHENTICATED_FULLY);
		policy.setSpringSecurityAccessPolicy(p);

		return policy;
	}

	protected AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<?>> voters = new ArrayList<>();
		voters.add(authenticatedVoter());
		return new AffirmativeBased(voters);
	}

	@Bean
	@ConditionalOnMissingBean(AuthenticatedVoter.class)
	public AuthenticatedVoter authenticatedVoter() {
		return new AuthenticatedVoter();
	}

	@Bean
	@ConditionalOnMissingBean(JwtAuthenticationProcessor.class)
	@ConditionalOnProperty(name = { "entur.jwt.enabled" }, havingValue = "true", matchIfMissing = false)
	public <T> JwtAuthenticationProcessor jwtAuthenticationProcessor(JwtVerifier<T> verifier, JwtAuthorityMapper<T> authorityMapper, JwtClaimExtractor<T> extractor, JwtPrincipalMapper jwtPrincipalMapper, JwtDetailsMapper detailsMapper) {
		return new DefaultJwtAuthenticationProcessor(verifier, authorityMapper, extractor, jwtPrincipalMapper, detailsMapper);
	}

}
