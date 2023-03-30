package org.entur.jwt.spring.grpc;

import io.grpc.BindableService;
import io.grpc.MethodDescriptor;
import io.grpc.ServerServiceDefinition;
import io.grpc.ServiceDescriptor;
import io.grpc.util.TransmitStatusRuntimeExceptionInterceptor;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.grpc.exception.ServerCallSecurityExceptionTranslator;
import org.entur.jwt.spring.grpc.exception.ServerCallStatusRuntimeExceptionTranslator;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.lognet.springboot.grpc.GRpcServicesRegistry;
import org.lognet.springboot.grpc.security.GrpcSecurity;
import org.lognet.springboot.grpc.security.GrpcSecurityConfigurerAdapter;
import org.lognet.springboot.grpc.security.GrpcServiceAuthorizationConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableConfigurationProperties({GrpcPermitAll.class})
@ConditionalOnProperty(name = {"entur.jwt.authorization"}, havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration.class})
public class GrpcAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(GrpcAutoConfiguration.class);

    @Configuration
    public static class GrpcSecurityConfiguration extends GrpcSecurityConfigurerAdapter {

        @Autowired
        private JwtDecoder jwtDecoder;

        @Autowired
        private GrpcPermitAll permitAll;

        @Override
        public void configure(GrpcSecurity grpcSecurity) throws Exception {
            if (permitAll.isActive()) {
                configureGrpcServiceMethodFilter(permitAll.getGrpc(), grpcSecurity);
            } else {
                // default to authenticated
                grpcSecurity.authorizeRequests().anyMethod().authenticated();
            }
        }

        private void configureGrpcServiceMethodFilter(GrpcServicesConfiguration grpc, GrpcSecurity grpcSecurity) throws Exception {

            GrpcServiceAuthorizationConfigurer.Registry registry = grpcSecurity.authorizeRequests();

            Map<String, List<String>> serviceNameMethodName = new HashMap<>();
            for (ServiceMatcherConfiguration configuration : grpc.getServices()) {
                if(!configuration.isEnabled()) {
                    continue;
                }

                List<String> methods = configuration.getMethods();

                if(methods.contains("*")) {
                    log.info("Allow anonymous access to all methods of GRPC service " + configuration.getName());
                } else {
                    log.info("Allow anonymous access to methods " + configuration.getMethods() + " of GRPC service " + configuration.getName());
                }
                List<String> lowercaseMethodNames = new ArrayList<>();

                for (String method : methods) {
                    lowercaseMethodNames.add(method.toLowerCase());
                }

                serviceNameMethodName.put(configuration.getName().toLowerCase(), lowercaseMethodNames);
            }

            // service name is included in method name
            registry.anyMethodExcluding((method) -> {
                String lowerCaseServiceName = method.getServiceName().toLowerCase();
                List<String> methodNames = serviceNameMethodName.get(lowerCaseServiceName);
                if(methodNames == null) {
                    return false;
                }

                if(methodNames.contains("*")) {
                    return true;
                }

                String lowerCaseBareMethodName = method.getBareMethodName().toLowerCase();
                String lowerCaseFullMethodName = method.getFullMethodName().toLowerCase();

                return methodNames.contains(lowerCaseBareMethodName) || methodNames.contains(lowerCaseFullMethodName);
            }).authenticated();


        }
    }



}
