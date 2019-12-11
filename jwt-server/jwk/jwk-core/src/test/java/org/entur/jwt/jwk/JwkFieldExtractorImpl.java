package org.entur.jwt.jwk;

public class JwkFieldExtractorImpl implements JwkFieldExtractor<JwkImpl> {

    @Override
    public String getJwkId(JwkImpl jwk) {
        return jwk.getId();
    }

}
