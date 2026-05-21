package org.entur.jwt.spring.properties;

public class JwtHeaderDecodeProperties {

    private JwtHeaderDecodeMapHeaderToIssuerProperties mapToIssuer = new JwtHeaderDecodeMapHeaderToIssuerProperties();

    public void setMapToIssuer(JwtHeaderDecodeMapHeaderToIssuerProperties mapToIssuer) {
        this.mapToIssuer = mapToIssuer;
    }

    public JwtHeaderDecodeMapHeaderToIssuerProperties getMapToIssuer() {
        return mapToIssuer;
    }
}
