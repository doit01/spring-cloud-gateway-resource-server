package com.javaak.examples.apigateway;

import com.javaak.examples.apigateway.security.SecurityProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({SecurityProperties.class})
@SpringBootApplication
public class JavaakGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(JavaakGatewayApplication.class, args);
    }

}
