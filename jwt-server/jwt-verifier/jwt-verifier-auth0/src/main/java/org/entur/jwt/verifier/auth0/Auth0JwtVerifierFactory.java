package org.entur.jwt.verifier.auth0;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.entur.jwt.jwk.JwkProvider;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.jwk.UrlJwksProvider;
import org.entur.jwt.jwk.auth0.Auth0JwkProviderBuilder;
import org.entur.jwt.jwk.auth0.Auth0JwkReader;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtClaimVerifier;
import org.entur.jwt.verifier.JwtVerifier;
import org.entur.jwt.verifier.JwtVerifierFactory;
import org.entur.jwt.verifier.config.JwkProperties;
import org.entur.jwt.verifier.config.JwkCacheProperties;
import org.entur.jwt.verifier.config.JwtClaimConstraintProperties;
import org.entur.jwt.verifier.config.JwtClaimsProperties;
import org.entur.jwt.verifier.config.JwkLocationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.entur.jwt.verifier.config.JwkOutageCacheProperties;
import org.entur.jwt.verifier.config.JwkPreemptiveCacheProperties;
import org.entur.jwt.verifier.config.JwkRateLimitProperties;
import org.entur.jwt.verifier.config.JwkRetryProperties;
import org.entur.jwt.verifier.config.JwtTenantProperties;

import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Verification;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class Auth0JwtVerifierFactory implements JwtVerifierFactory<DecodedJWT>{

    private static Logger log = LoggerFactory.getLogger(Auth0JwtVerifierFactory.class);
    
	private final JwtClaimExtractor<DecodedJWT> extractor;

	public Auth0JwtVerifierFactory(JwtClaimExtractor<DecodedJWT> extractor) {
		this.extractor = extractor;
	}

	@Override
	public JwtVerifier<DecodedJWT> getVerifier(Map<String, JwtTenantProperties> tenants, JwkProperties jwkConfiguration, JwtClaimsProperties claims) {
		Map<String, JWTVerifier> verifiers = new HashMap<>(); // thread safe for read access
		
		boolean healthIndicator = jwkConfiguration.getHealthIndicator().isEnabled();
		
		List<JwksProvider<?>> statusProviders = new ArrayList<>();
		
		List<JwtClaimConstraintProperties> required = claims.getRequire();
		List<JwtClaimConstraintProperties> dataTypeConstraints = new ArrayList<>();
		List<JwtClaimConstraintProperties> dataValueConstraints = new ArrayList<>();
		for(JwtClaimConstraintProperties r : required) {
			if(r.getValue() == null) {
				log.info("Require claim {} value {} of type {}", r.getName(), r.getValue(), r.getType());
				
				dataTypeConstraints.add(r);
				
			} else {
				log.info("Require claim {} of type {}", r.getName() + r.getType());
				
				dataValueConstraints.add(r);
			}
		}
		
		for (Entry<String, JwtTenantProperties> entry : tenants.entrySet()) {
			JwtTenantProperties tenantConfiguration = entry.getValue();
			
			log.info("Configure tenant '{}' with issuer '{}'", entry.getKey(), tenantConfiguration.getIssuer());
			
			JwkLocationProperties tenantJwkConfiguration = tenantConfiguration.getJwk();
			if(tenantJwkConfiguration == null) {
				throw new IllegalStateException("Missing JWK location for " + entry.getKey());
			}
			
			String location = tenantJwkConfiguration.getLocation();
			if(location == null) {
				throw new IllegalStateException("Missing JWK location for " + entry.getKey());
			}
			
			URL url;
			try {
				url = new URL(location);
			} catch (MalformedURLException e) {
				throw new IllegalArgumentException("Invalid location " + tenantJwkConfiguration.getLocation() + " for " + entry.getKey());
			}
			
			UrlJwksProvider<Jwk> urlProvider = new UrlJwksProvider<>(url, new Auth0JwkReader(), jwkConfiguration.getConnectTimeout(), jwkConfiguration.getReadTimeout());
			
			Auth0JwkProviderBuilder builder = new Auth0JwkProviderBuilder(urlProvider);
			
			JwkRateLimitProperties rateLimiting = jwkConfiguration.getRateLimit();
			if(rateLimiting != null && rateLimiting.isEnabled()) {
				int refillRatePerDay = (int) (rateLimiting.getRefillRate() * (24 * 3600));
				
				builder.rateLimited(rateLimiting.getBucketSize(), refillRatePerDay, TimeUnit.DAYS);
			} else {
				builder.rateLimited(false);
			}

			JwkCacheProperties cache = jwkConfiguration.getCache();
			if(cache != null && cache.isEnabled()) {
				builder.cached(cache.getTimeToLive(), TimeUnit.SECONDS, cache.getRefreshTimeout(), TimeUnit.SECONDS);
				
				JwkPreemptiveCacheProperties preemptive = cache.getPreemptive();
				if(preemptive != null && preemptive.isEnabled()) {
					builder.preemptiveCacheRefresh(preemptive.getTimeToExpires(), TimeUnit.SECONDS);
				} else {
					builder.preemptiveCacheRefresh(false);
				}
			} else {
				builder.cached(false);
				builder.preemptiveCacheRefresh(false);
			}

			JwkRetryProperties retrying = jwkConfiguration.getRetry();
			builder.retrying(retrying != null && retrying.isEnabled());

			JwkOutageCacheProperties outageCache = jwkConfiguration.getOutageCache();
			if(outageCache != null && outageCache.isEnabled()) {
				builder.outageCached(outageCache.getTimeToLive(), TimeUnit.SECONDS);
			} else {
				builder.outageCached(false);
			}
			
			builder.health(healthIndicator);
			
			JwkProvider<Jwk> jwkProvider = builder.build();
			
			if(healthIndicator) {
				jwkProvider.getHealth(false); // verify that health is supported
				statusProviders.add(jwkProvider);
			}
			
			JwtKeyProvider keyProvider = new JwtKeyProvider(jwkProvider);
			
			Verification jwtBuilder = JWT
				.require(Algorithm.RSA256(keyProvider))
				.withIssuer(tenantConfiguration.getIssuer()) // strictly not necessary, but lets add it anyways
				.acceptExpiresAt(claims.getExpiresAtLeeway())
				.acceptIssuedAt(claims.getIssuedAtLeeway());
			
			// value verification directly supported by auth0
			for(JwtClaimConstraintProperties r : dataValueConstraints) {
				switch(r.getType()) {
					case "integer": {
						parseInteger(jwtBuilder, r);
						break;
					} 
					case "boolean" : {
						jwtBuilder.withClaim(r.getName(), Boolean.parseBoolean(r.getValue()));
						break;
					}
					case "string" : {
						jwtBuilder.withClaim(r.getName(), r.getValue());
						break;
					}
					case "double" : {
						jwtBuilder.withClaim(r.getName(), Double.parseDouble(r.getValue()));
						break;
					}
					default : {
						throw new IllegalArgumentException("Unexpected claim type '" + r.getType() + "'");
					}
				}
			}
			
			JWTVerifier verifier = new AudienceJWTVerifier(jwtBuilder.build(), claims.getAudiences());
			verifiers.put(tenantConfiguration.getIssuer(), verifier);
		}
		
		JwtVerifier<DecodedJWT> verifier;
		if(!statusProviders.isEmpty()) {
			verifier = new MultiTenantJwtVerifier(verifiers, statusProviders);
		} else {
			verifier = new MultiTenantJwtVerifier(verifiers);
		}
		
		if(!dataTypeConstraints.isEmpty()) {
			// add claim-verifying wrapper 
			Map<String, Class<?>> types = new HashMap<>(dataTypeConstraints.size() * 2);
			
			for (JwtClaimConstraintProperties r : dataTypeConstraints) {
				switch(r.getType()) {
					case "integer": {
						types.put(r.getName(), Long.class); // integers can be cast to long, so should not be a problem.
						break;
					} 
					case "boolean" : {
						types.put(r.getName(), Boolean.class);
						break;
					}
					case "string" : {
						types.put(r.getName(), String.class);
						break;
					}
					case "double" : {
						types.put(r.getName(), Double.class);
						break;
					}
					default : {
						throw new IllegalArgumentException("Unexpected claim type '" + r.getType() + "'");
					}
				}
			}
			
			verifier = new JwtClaimVerifier<>(verifier, extractor, types, Collections.emptyMap());
		}
		return verifier;

	}

	private void parseInteger(Verification jwtBuilder, JwtClaimConstraintProperties r) {
		Long l = Long.parseLong(r.getValue());
		if(l <= Integer.MAX_VALUE) {
			jwtBuilder.withClaim(r.getName(), l.intValue());
		} else {
			jwtBuilder.withClaim(r.getName(), l);
		}
	}



}
