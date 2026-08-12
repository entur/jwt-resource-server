package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extension of {@link JwtHeaderToIssuerMapper} that disables the optimization once the
 * number of distinct cached headers exceeds {@code maxSize}, guarding against unexpected
 * entropy in JWT headers (e.g. random/dynamic values).
 *
 * <p>Use {@code maxSize = -1} to disable the limit.
 */
public class BoundedJwtHeaderToIssuerMapper extends JwtHeaderToIssuerMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(BoundedJwtHeaderToIssuerMapper.class);

    protected final int maxSize;
    private boolean disabled = false;

    public BoundedJwtHeaderToIssuerMapper(int maxSize) {
        this.maxSize = maxSize;
    }

    @Override
    public String get(String jwtToken) {
        if (disabled) {
            return null;
        }
        return super.get(jwtToken);
    }

    @Override
    public void add(String issuer, String jwtToken) {
        if (disabled) {
            return;
        }
        super.add(issuer, jwtToken);

        int size = headerToIssuer.size();
        if (maxSize != -1 && size > maxSize) {
            setDisabled(true);
            LOGGER.warn("JWT header-to-issuer cache exceeded max size of {}; disabling header-to-issuer optimization", maxSize);
        }
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

}
