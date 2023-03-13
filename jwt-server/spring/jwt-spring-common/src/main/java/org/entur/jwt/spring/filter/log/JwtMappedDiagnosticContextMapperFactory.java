package org.entur.jwt.spring.filter.log;

import org.entur.jwt.spring.auth0.properties.MdcPair;
import org.entur.jwt.spring.auth0.properties.MdcProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class JwtMappedDiagnosticContextMapperFactory {

    private static final Logger LOG = LoggerFactory.getLogger(JwtMappedDiagnosticContextMapperFactory.class);

    public JwtMappedDiagnosticContextMapper mapper(MdcProperties mdc) {
        List<MdcPair> items = mdc.getMappings();
        List<String> to = new ArrayList<>();
        List<String> from = new ArrayList<>();

        // note: possible to map the same claim to different values
        for (MdcPair item : items) {
            to.add(item.getTo());
            from.add(item.getFrom());

            LOG.info("Map JWT claim '{}' to MDC key '{}'", item.getFrom(), item.getTo());
        }
        return new DefaultJwtMappedDiagnosticContextMapper(from, to);
    }

}
