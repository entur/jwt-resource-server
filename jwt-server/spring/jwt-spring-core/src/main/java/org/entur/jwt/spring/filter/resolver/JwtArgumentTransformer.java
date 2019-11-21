package org.entur.jwt.spring.filter.resolver;

public interface JwtArgumentTransformer {

	Object transform(Object token);
}
