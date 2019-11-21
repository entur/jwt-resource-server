package org.entur.jwt.junit5.impl;

import java.util.Map;

public interface AccessTokenEncoder {

	String encode(Map<String, Object> claims);
}
