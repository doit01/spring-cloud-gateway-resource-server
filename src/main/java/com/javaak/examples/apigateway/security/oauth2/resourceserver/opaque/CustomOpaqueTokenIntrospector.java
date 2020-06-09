package com.javaak.examples.apigateway.security.oauth2.resourceserver.opaque;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;

@RequiredArgsConstructor
@Slf4j
@Component
public class CustomOpaqueTokenIntrospector implements ReactiveOpaqueTokenIntrospector {

    private final OAuth2ResourceServerProperties oAuth2ResourceServerProperties;

    private NimbusReactiveOpaqueTokenIntrospector introspector;

    @PostConstruct
    public void initializeCachingOpaqueTokenIntrospector() {
        this.introspector = new NimbusReactiveOpaqueTokenIntrospector(
        oAuth2ResourceServerProperties.getOpaquetoken().getIntrospectionUri(),
        oAuth2ResourceServerProperties.getOpaquetoken().getClientId(),
        oAuth2ResourceServerProperties.getOpaquetoken().getClientSecret());
    }

    @Override
    public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
        Mono<OAuth2AuthenticatedPrincipal> principal = introspector.introspect(token);
        //TODO next line is only for debug until storing data in reactive security context
        principal.subscribe(successValue -> LOGGER.debug("Oauth2 token validated for principal: {}.",
                successValue.getName()),
            error -> LOGGER.error(error.getMessage(), error));

        //TODO set details on ReactiveSecurityContextHolder
//        List<String> authorities = Arrays.asList("ROLE_USER");
//        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("username", null,
//            authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
//        ReactiveSecurityContextHolder.withAuthentication(auth);
//        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(new SecurityContextImpl(auth)));

//        SecurityUtils.getCurrentUserLogin().subscribe(s -> System.out.println("Current user : " + s),
//            err -> System.out.println("Err: " + err),
//            () -> System.out.printf("Current user ogin consumed."));

//        principal.block();
        return principal;
    }
}
