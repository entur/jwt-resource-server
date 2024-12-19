package org.entur.jwt.spring.grpc.lognet.annotate;


import org.springframework.context.annotation.Conditional;

import java.lang.annotation.*;


/**
 *
 * The regular {@linkplain org.lognet.springboot.grpc.autoconfigure.ConditionalOnMissingErrorHandler} also checks for handling of the subtree,
 * but we don't want that since this will result in incorrect return codes.
 *
 */

@Target({ ElementType.TYPE , ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(OnMissingErrorHandlerForExactExceptionCondition.class)
public @interface ConditionalOnMissingErrorHandlerForExactException {
    Class<? extends Throwable> value();
}
