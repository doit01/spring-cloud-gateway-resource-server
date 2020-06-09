package com.javaak.examples.apigateway.gw;

import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class SecurityHeadersGatewayFilterFactory extends AbstractGatewayFilterFactory<SecurityHeadersGatewayFilterFactory.Config> {

    public static final String EMAIL_CLAIM = "email";
    public static final String CLIENT_SPECIFIC_CLAIM = "resource_access";
    public static final String ROLES_CLAIM = "roles";
    private final ReactiveJwtDecoder jwtDecoder;
    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;

    public SecurityHeadersGatewayFilterFactory(ReactiveJwtDecoder jwtDecoder,
                                               OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {
        super(Config.class);
        this.jwtDecoder = jwtDecoder;
        this.oAuth2ResourceServerProperties = oAuth2ResourceServerProperties;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (exchange.getRequest().getHeaders()
                .get(HttpHeaders.AUTHORIZATION).isEmpty()) {
                return chain.filter(exchange);
            }

            //TODO AK read from ReactiveSecurityContextHolder instead of decoding the JWT again.
//            SecurityUtils.getCurrentUserLogin().subscribe(s -> System.out.println("Current user : " + s),
//                err -> System.out.println("Err: " + err),
//                () -> System.out.printf("Current user ogin consumed."));

            // populate the authorization headers for downstream microservices
            String jwtString = exchange.getRequest().getHeaders()
                .get(HttpHeaders.AUTHORIZATION).get(0);

            jwtString = jwtString.startsWith("Bearer ") ? jwtString.substring(7) : jwtString;
            Mono<Jwt> jwt = jwtDecoder.decode(jwtString);
            jwt.subscribe(j -> {
                        String sub = j.getClaim(JwtClaimNames.SUB).toString();
                        String email = j.getClaim(EMAIL_CLAIM).toString();
                        String rolesString = getClientRolesAsString(j);
                        LOGGER.debug("Setting HTTP Headers for downstream service calls: Subject: {}, Email: {}, Roles: {}.",
                                sub, email, rolesString);
                        exchange.getRequest().mutate().header(HttpHeaders.SECURITY_USER_IDENTIFIER, sub)
                                .header(HttpHeaders.SECURITY_USERNAME, email)
                                .header(HttpHeaders.SECURITY_USER_GROUPS, rolesString);
                },
                err -> LOGGER.error("Error while setting the HTTP security headers for downstream requests: "
                        + err.getMessage(), err)
            );

            return chain.filter(exchange);
        };
    }

    private String getClientRolesAsString(Jwt jwt) {
        JSONObject clientClaims = (JSONObject) ((JSONObject) jwt.getClaim(CLIENT_SPECIFIC_CLAIM)).
                get(oAuth2ResourceServerProperties.getOpaquetoken().getClientId());
        JSONArray jsonArray = (JSONArray) clientClaims.get(ROLES_CLAIM);
        List<String> roles = new ArrayList();
        for (Object s : jsonArray) {
            roles.add(s.toString());
        }
        return roles.stream().collect(Collectors.joining(","));
    }

    public static class Config {
    }
}
