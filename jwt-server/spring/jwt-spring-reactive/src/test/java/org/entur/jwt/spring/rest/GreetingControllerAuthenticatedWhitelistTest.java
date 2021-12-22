package org.entur.jwt.spring.rest;

import org.springframework.test.context.TestPropertySource;

/**
 *
 * Test accessing methods with a valid bearer token, and a whitelist.
 *
 */

@TestPropertySource(properties = { "entur.authorization.permit-all.ant-matcher.patterns=/actuator/health,/unprotected" })
public class GreetingControllerAuthenticatedWhitelistTest extends GreetingControllerAuthenticatedTest{


}
