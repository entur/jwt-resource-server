package org.entur.jwt.junit5.entur.test;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.entur.jwt.junit5.impl.DefaultAccessTokenEncoder;
import org.junit.jupiter.api.extension.ParameterContext;

import java.util.Map;
import java.util.Optional;

public class PartnerAuth0TokenEncoder extends DefaultAccessTokenEncoder {

    @Override
    protected void encodeCustomClaims(ParameterContext parameterContext, Map<String, Object> result, ResourceServerConfiguration resolver) {
        super.encodeCustomClaims(parameterContext, result, resolver);

        Optional<PartnerAuth0Token> a = parameterContext.findAnnotation(PartnerAuth0Token.class);
        if (a.isPresent()) {
            encode(result, a.get());
        }
    }
    
    protected void encode(Map<String, Object> encode, PartnerAuth0Token partnerAccessToken) {
        encode.put("organisationID", partnerAccessToken.organisationId());
        String[] permissions = partnerAccessToken.permissions();
        if (permissions.length > 0) {
            encode.put("permissions", permissions);
        }
        String[] scope = partnerAccessToken.scopes();
        if (scope.length > 0) {
            encode.put("scope", toString(scope));
        }

        // these fields might have already been populated.
        // but ignore the existing values
        if (!isBlank(partnerAccessToken.subject())) {
            encode.put(SUB, partnerAccessToken.subject());
        }

        String[] audience = partnerAccessToken.audience();
        if (audience != null && audience.length > 0) {
            encode.put(AUD, audience);
        }
    }

    private String toString(String[] scopes) {
        StringBuilder builder = new StringBuilder();
        for (String scope : scopes) {
            builder.append(scope);
            builder.append(' ');
        }
        if (builder.length() > 0) {
            builder.setLength(builder.length() - 1);
        }
        return builder.toString();
    }
}
