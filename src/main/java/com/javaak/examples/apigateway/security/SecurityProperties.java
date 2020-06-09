package com.javaak.examples.apigateway.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.List;

@Data
@ConfigurationProperties(prefix = "gwsecurity", ignoreUnknownFields = false)
public class SecurityProperties {
    private String issuerUri;
    private List<String> audience;
}
