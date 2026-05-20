package org.entur.jwt.spring.issuer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * Simple accumulator which checks that all JWKs KIDs are present before
 * determining whether there are duplicates.
 *
 */

public class JwkHeaderToIssuerContexts {

    protected final int requiredSize;
    protected final ConcurrentHashMap<String, Set<String>> issuerKids = new ConcurrentHashMap<>();
    protected final JwtHeaderToIssuerMapper mapper;

    public JwkHeaderToIssuerContexts(int requiredSize, JwtHeaderToIssuerMapper mapper) {
        this.requiredSize = requiredSize;
        this.mapper = mapper;
    }

    public void setIssuerJwkKids(String issuer, Set<String> kids) {
        issuerKids.put(issuer, kids);

        if(issuerKids.size() == requiredSize) {
            Set<String> issuers = issuersWithUniqueKids();
            mapper.setIssuers(issuers);
        }
    }

    protected Set<String> issuersWithUniqueKids() {
        List<String> issuers = new ArrayList<>(issuerKids.keySet());
        for(int i = 0; i < issuers.size(); i++) {
            String issuer = issuers.get(i);

            Set<String> kids = issuerKids.get(issuers.get(i));

            for (Map.Entry<String, Set<String>> stringSetEntry : issuerKids.entrySet()) {
                if(stringSetEntry.getKey().equals(issuer)) {
                    continue;
                }
                if(!Collections.disjoint(stringSetEntry.getValue(), kids)) {
                    issuers.remove(i);
                    i--;
                    break;
                }
            }
        }
        return new HashSet<>(issuers);
    }

}
