package org.entur.jwt.spring.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
public class MyConfig {

    public static class DefaultEnturGlobalMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

        private PermissionEvaluator permissionEvaluator;

        @Autowired
        public DefaultEnturGlobalMethodSecurityConfig(PermissionEvaluator permissionEvaluator) {
            this.permissionEvaluator = permissionEvaluator;
        }

        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(permissionEvaluator);

            return expressionHandler;
        }
    }

    
}
