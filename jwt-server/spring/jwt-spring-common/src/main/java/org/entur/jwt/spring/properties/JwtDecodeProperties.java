package org.entur.jwt.spring.properties;

public class JwtDecodeProperties {

    private JwtHeaderDecodeProperties header = new JwtHeaderDecodeProperties();

    /**
     * Whether to fail startup if there is a {@code JwtDecoder} or {@code ReactiveJwtDecoder} bean, which would be
     * ignored, as JWTs are decoded by the per-issuer decoders configured under {@code entur.jwt.tenants}. Default true.
     */
    private boolean failOnJwtDecoderBean = true;

    public boolean isFailOnJwtDecoderBean() {
        return failOnJwtDecoderBean;
    }

    public void setFailOnJwtDecoderBean(boolean failOnJwtDecoderBean) {
        this.failOnJwtDecoderBean = failOnJwtDecoderBean;
    }

    public void setHeader(JwtHeaderDecodeProperties header) {
        this.header = header;
    }

    public JwtHeaderDecodeProperties getHeader() {
        return header;
    }
}
