package org.entur.jwt.spring.actuate.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.TenantProperties;
import org.entur.jwt.spring.TenantsProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
/**
 * 
 * Test specifying additional properties for tenants
 * 
 */
@TestPropertySource(properties = { 
        "entur.jwt.tenants.myServer.properties.myParameter=myValue",
})

@AuthorizationServer("myServer")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class TenantProperitesTest {

    @Value("${entur.jwt.tenants.myServer.issuer}")
    private String issuer;

    @Autowired
    private TenantsProperties tenantsProperties;
    
    @Test 
    public void testPropertyPresent() {
        TenantProperties properties = tenantsProperties.getByIssuer(issuer);
        assertEquals("myValue", properties.getProperty("myParameter"));
    }

}