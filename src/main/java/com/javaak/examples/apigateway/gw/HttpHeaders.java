package com.javaak.examples.apigateway.gw;

public class HttpHeaders extends org.springframework.http.HttpHeaders {

    public static final String SECURITY_USERNAME = "X-Custom-ApplicationUsername";
    public static final String SECURITY_USER_IDENTIFIER = "X-Custom-UserId";
    public static final String SECURITY_USER_GROUPS = "X-Custom-UserGroups";


}
