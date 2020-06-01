# custom-assertion-builder for WSO2 Identity Server.

## Instructions to Configure the Custom Assertion Builder
* The tenant domain, user store domain, The SP(Issuer) & the list of claims where the custome attribute value should be present can be configured
with the following,
```
private String targetUserStoreDomain="TEST";
private String targetTenantDomain="testing.com";
private String targetIssuer="travelocity.com";
private String [] targetClaimUris = {"http://wso2.org/claims/role"};
```

## Instructions to Build
* Checkout The repository
* Move to the custome-assertion-builder folder
* run `mvn clean install`
* Copy the jar file in target folder and paste it inside <IS_HOME>/repository/components/lib folder.
* Change the default assertion builder configuration found in `<SAMLSSOAssertionBuilder>` tag, from 
`org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder` to `com.sample.builder.CustomAssertionBuilder`
* Save and Re-start the IS.
