package org.entur.jwt.jwk.connect2id;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksProvider;
import org.entur.jwt.jwk.JwksUnavailableException;

import java.util.LinkedList;
import java.util.List;

public class EnturJWKSource<C extends SecurityContext> implements JWKSource<C> {

    private final JwksProvider<JWK> provider;

    public EnturJWKSource(JwksProvider<JWK> provider) {
        super();
        this.provider = provider;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {

        JWKMatcher matcher = jwkSelector.getMatcher();

        try {
            List<JWK> select = select(provider.getJwks(false), matcher);
            if (select.isEmpty()) {
                select = select(provider.getJwks(true), matcher);
            }
            return select;
        } catch (JwksUnavailableException e) {
            throw new RemoteKeySourceException("Unable to get keys", e);
        } catch (JwksException e) {
            throw new KeySourceException("Unable to get keys", e);
        }
    }

    public List<JWK> select(List<JWK> list, JWKMatcher matcher) {
        List<JWK> selectedKeys = new LinkedList();
        if (list == null) {
            return selectedKeys;
        } else {
            for (JWK jwk : list) {
                if (matcher.matches(jwk)) {
                    selectedKeys.add(jwk);
                }
            }
            return selectedKeys;
        }
    }

}
