package org.entur.jwt.spring.properties;

public class JwtDecodeProperties {

    private JwtHeaderDecodeProperties header = new JwtHeaderDecodeProperties();

    public void setHeader(JwtHeaderDecodeProperties header) {
        this.header = header;
    }

    public JwtHeaderDecodeProperties getHeader() {
        return header;
    }
}
