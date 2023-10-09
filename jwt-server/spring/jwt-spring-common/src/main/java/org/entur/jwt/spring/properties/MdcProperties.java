package org.entur.jwt.spring.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "entur.jwt.mdc")
public class MdcProperties {

    private boolean enabled = true;

    private List<MdcPair> mappings = new ArrayList<>();

    public List<MdcPair> getMappings() {
        return mappings;
    }

    public void setMappings(List<MdcPair> items) {
        this.mappings = items;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
