package org.entur.jwt.spring;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.ClassUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * Fails startup if the application context contains a {@link JwtDecoder} or (with Reactor present)
 * {@code ReactiveJwtDecoder} bean.
 * Such a bean is never used: the web, webflux and gRPC modules decode JWTs using their own per-issuer decoders.
 * To customize JWT decoding (web and gRPC), provide a {@link org.entur.jwt.spring.decode.ClosableJwtDecoders} bean instead.
 *
 */

public class UnsupportedJwtDecoderGuard implements SmartInitializingSingleton {

    private static final String REACTIVE_JWT_DECODER = "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder";
    private static final String MONO = "reactor.core.publisher.Mono";

    private final ListableBeanFactory beanFactory;
    private final boolean enabled;

    /**
     * @param beanFactory bean factory to inspect
     * @param enabled whether to fail startup; if false, the guard does nothing
     */
    public UnsupportedJwtDecoderGuard(ListableBeanFactory beanFactory, boolean enabled) {
        this.beanFactory = beanFactory;
        this.enabled = enabled;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!enabled) {
            return;
        }
        List<String> beanNames = new ArrayList<>();
        // do not initialize lazy beans / factory beans just to check their type
        beanNames.addAll(Arrays.asList(beanFactory.getBeanNamesForType(JwtDecoder.class, true, false)));
        // the reactive decoder references Reactor, which is not present in servlet applications
        ClassLoader classLoader = getClass().getClassLoader();
        if (ClassUtils.isPresent(MONO, classLoader) && ClassUtils.isPresent(REACTIVE_JWT_DECODER, classLoader)) {
            beanNames.addAll(Arrays.asList(beanFactory.getBeanNamesForType(ClassUtils.resolveClassName(REACTIVE_JWT_DECODER, classLoader), true, false)));
        }

        if (!beanNames.isEmpty()) {
            throw new IllegalStateException("Unsupported JwtDecoder / ReactiveJwtDecoder bean(s) " + beanNames + ": JWTs are decoded using the per-issuer decoders configured under 'entur.jwt.tenants', so such a bean would be ignored. "
                    + "Remove the bean(s), or provide a " + org.entur.jwt.spring.decode.ClosableJwtDecoders.class.getName() + " bean to customize JWT decoding (web and gRPC). "
                    + "Note that Spring Boot creates a JwtDecoder bean if 'spring.security.oauth2.resourceserver.jwt.*' properties are set. "
                    + "To ignore the bean(s), set 'entur.jwt.decode.fail-on-jwt-decoder-bean=false'.");
        }
    }
}
