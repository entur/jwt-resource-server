package org.entur.jwt.client.springcloud;

import org.entur.jwt.client.properties.JwtClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 *
 * Extend properties to get the tooling working for Spring properties.
 *
 */

@ConfigurationProperties(prefix = "entur.jwt.clients")
public class SpringJwtClientProperties extends JwtClientProperties {

}
