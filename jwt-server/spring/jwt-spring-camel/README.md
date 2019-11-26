# jwt-spring-camel
Basic support for Apache Camel. Adds a policy that can be used to verifies that the Json Web Token is valid (i.e. the user is authenticated).

```
@Autowired
@Qualifier("validTokenAccessPolicy")
private SpringSecurityAuthorizationPolicy validAccessTokenPolicy;

@Autowired
private JwtAuthenticationProcessor<?> jwtAuthenticationProcessor;

@Override
public void configure() throws Exception {
    super.configure();

    // set authentication on the message (the Exchange.AUTHENTICATION header)
    JwtAuthenticationRoutePolicyFactory factory = new JwtAuthenticationRoutePolicyFactory(jwtAuthenticationProcessor);
    getContext().addRoutePolicyFactory(factory);

    // later enforce at authentication is present using the policy
   rest("/my")
      .get("/rest-route") 
      .route()
      .policy(validAccessTokenPolicy)
      . // your code here
      .endRest();
}


```

Detailed permission checking must be done seperately.
