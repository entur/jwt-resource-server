package org.entur.jwt.spring.grpc.lognet;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class DemoApplication extends SpringBootServletInitializer {
    public static void main(String[] args) {
        new DemoApplication().configure(new SpringApplicationBuilder(DemoApplication.class)).run(args);
    }
}


