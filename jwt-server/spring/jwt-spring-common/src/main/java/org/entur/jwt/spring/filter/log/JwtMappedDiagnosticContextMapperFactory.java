package org.entur.jwt.spring.filter.log;

import org.entur.jwt.spring.properties.MdcPair;
import org.entur.jwt.spring.properties.MdcProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class JwtMappedDiagnosticContextMapperFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtMappedDiagnosticContextMapperFactory.class);

    public JwtMappedDiagnosticContextMapper mapper(MdcProperties mdc) {
        List<MdcPair> items = mdc.getMappings();
        List<String> to = new ArrayList<>();
        List<String> from = new ArrayList<>();

        // note: possible to map the same claim to different values
        for (int i = 0; i < items.size(); i++) {
            MdcPair item = items.get(i);
            validate(item, i);

            to.add(item.getTo());
            from.add(item.getFrom());

            if(LOGGER.isDebugEnabled()) LOGGER.debug("Map JWT claim '{}' to MDC key '{}'", item.getFrom(), item.getTo());
        }
        return new DefaultJwtMappedDiagnosticContextMapper(from, to);
    }

    // a missing key would otherwise only surface as an error for each authenticated request
    private static void validate(MdcPair item, int index) {
        String property = "entur.jwt.mdc.mappings[" + index + "]";
        if (item == null) {
            throw new IllegalStateException("MDC mapping " + property + " is empty: set both 'from' (JWT claim) and 'to' (MDC key), or remove the mapping.");
        }
        if (isBlank(item.getFrom())) {
            throw new IllegalStateException("MDC mapping " + property + ".from must not be blank (mapping to MDC key '" + item.getTo() + "'): set the JWT claim to copy, or remove it.");
        }
        if (isBlank(item.getTo())) {
            throw new IllegalStateException("MDC mapping " + property + ".to must not be blank (mapping from JWT claim '" + item.getFrom() + "'): set the MDC key to copy the claim to, or remove it.");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}
