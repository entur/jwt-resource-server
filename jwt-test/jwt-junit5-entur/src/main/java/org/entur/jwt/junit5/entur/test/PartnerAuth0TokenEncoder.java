package org.entur.jwt.junit5.entur.test;

import java.util.Map;
import java.util.Optional;

import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
import org.entur.jwt.junit5.entur.test.auth0.PartnerAuth0Token;
import org.entur.jwt.junit5.impl.DefaultAccessTokenEncoder;
import org.junit.jupiter.api.extension.ParameterContext;

public class PartnerAuth0TokenEncoder extends DefaultAccessTokenEncoder {

    @Override
    public Map<String, Object> encodeClaims(ParameterContext parameterContext, ResourceServerConfiguration resolver) {
        Map<String, Object> encode = super.encodeClaims(parameterContext, resolver);

        Optional<PartnerAuth0Token> a = parameterContext.findAnnotation(PartnerAuth0Token.class);
        if (a.isPresent()) {
            encode(encode, a.get());
        }

        return encode;
    }

    private void encode(Map<String, Object> encode, PartnerAuth0Token partnerAccessToken) {
        encode.put("organisationID", partnerAccessToken.organisationId());
        String[] permissions = partnerAccessToken.permissions();
        if (permissions.length > 0) {
            encode.put("permissions", permissions);
        }
        String[] scope = partnerAccessToken.scopes();
        if (scope.length > 0) {
            encode.put("scope", toString(scope));
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
