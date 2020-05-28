package org.entur.jwt.spring.camel;

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksServiceException;
import org.entur.jwt.spring.filter.JwtAuthenticationServiceUnavailableException;
import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtServiceException;
import org.entur.jwt.verifier.JwtVerifier;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * A {@linkplain Processor} which, if present, extracts the Json Web Token from
 * the message {@linkplain HttpServletRequest} Authorization header and saves it
 * to the message {@linkplain Exchange#AUTHENTICATION}. If not present, an
 * anonymous authentication object is used. <br>
 * This implementation assumes that
 * SpringSecurityAuthorizationPolicy#setUseThreadSecurityContext is used to
 * disable thread local authentication.
 * 
 */

@SuppressWarnings("rawtypes")
public class DefaultJwtAuthenticationProcessor implements JwtAuthenticationProcessor {

    private static Authentication anonymous = new AnonymousAuthenticationToken("anonymous", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";

    private final JwtVerifier verifier;
    private final JwtAuthorityMapper authorityMapper;
    private final JwtClaimExtractor extractor;

    public <T> DefaultJwtAuthenticationProcessor(JwtVerifier<T> verifier, JwtAuthorityMapper<T> authorityMapper, JwtClaimExtractor<T> extractor) {
        super();
        this.verifier = verifier;
        this.authorityMapper = authorityMapper;
        this.extractor = extractor;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void process(Exchange exchange) {
        // implementation note: Must add anon authentication or else
        // SpringSecurityAuthorizationPolicy blows up

        Message in = exchange.getIn();
        if (in.getHeader(Exchange.AUTHENTICATION) == null) {
            // https://camel.apache.org/components/latest/http-component.html
            HttpServletRequest request = in.getBody(HttpServletRequest.class);

            Authentication authentication;
            if (request != null) {
                String header = request.getHeader(AUTHORIZATION);
                if (header != null && header.startsWith(BEARER)) {
                    String bearerToken = header.substring(BEARER.length());
                    
                    // if a token is present, it must be valid regardless of whether the end-point
                    // requires authorization or not
                    try {
                        Object token = verifier.verify(bearerToken); // note: can return null
                        if (token != null) {
                            List<GrantedAuthority> authorities = authorityMapper.getGrantedAuthorities(token);

                            Map<String, Object> claims = extractor.getClaims(token);

                            authentication = new JwtAuthenticationToken(claims, bearerToken, authorities);
                        } else {
                            throw new BadCredentialsException("Unknown issuer");
                        }
                    } catch (JwksServiceException | JwtServiceException e) {
                        throw new JwtAuthenticationServiceUnavailableException("Unable to process token", e);
                    } catch (JwtException | JwksException e) {
                        // assume client issue
                        throw new BadCredentialsException("Problem verifying token", e);
                    }
                } else {
                    authentication = anonymous;
                }
            } else {
                authentication = anonymous;
            }
            Subject subject = new Subject();
            subject.getPrincipals().add(authentication);
            in.setHeader(Exchange.AUTHENTICATION, subject);
        }
    }

}
