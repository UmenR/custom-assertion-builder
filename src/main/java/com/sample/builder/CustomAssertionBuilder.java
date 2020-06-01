package com.sample.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

public class CustomAssertionBuilder extends DefaultSAMLAssertionBuilder {
    private static Log log = LogFactory.getLog(CustomAssertionBuilder.class);
    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
    private String requestUserStoreDomain=null;
    private String requestTenantDomain=null;
    private String requestIssuer=null;
    private String targetUserStoreDomain="TEST";
    private String targetTenantDomain="testing.com";
    private String targetIssuer="travelocity.com";
    private String [] targetClaimUris = {"http://wso2.org/claims/role"};

    public Assertion buildAssertion(SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, String sessionId) throws IdentityException {
        try {
            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();
            requestUserStoreDomain = authReqDTO.getUser().getUserStoreDomain();
            requestTenantDomain=authReqDTO.getTenantDomain();
            requestIssuer=authReqDTO.getIssuer();

            this.setBasicInfo(samlAssertion, currentTime);

            this.setSubject(authReqDTO, notOnOrAfter, samlAssertion);

            this.addAuthStatement(authReqDTO, sessionId, samlAssertion);
            /*
             * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
             * the spec 2.0 the subject MUST be in the assertion
             */

            this.addAttributeStatements(authReqDTO, samlAssertion);

            this.setConditions(authReqDTO, currentTime, notOnOrAfter, samlAssertion);

            this.setSignature(authReqDTO, samlAssertion);

            return samlAssertion;

        } catch (Exception e) {
            log.error("Error when reading claim values for generating SAML Response", e);
            throw IdentityException.error(
                    "Error when reading claim values for generating SAML Response", e);
        } finally {
            resetRequestInfo();
        }
    }

    protected AttributeStatement buildAttributeStatement(Map<String, String> claims) {
        String claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            userAttributeSeparator = claimSeparator;
        }
        claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);

        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        Iterator<Map.Entry<String, String>> iterator = claims.entrySet().iterator();
        boolean atLeastOneNotEmpty = false;
        for (int i = 0; i < claims.size(); i++) {
            Map.Entry<String, String> claimEntry = iterator.next();
            String claimUri = claimEntry.getKey();
            String claimValue = claimEntry.getValue();
            if (claimUri != null && !claimUri.trim().isEmpty() && claimValue != null && !claimValue.trim().isEmpty()) {
                atLeastOneNotEmpty = true;
                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setName(claimUri);
                //setting NAMEFORMAT attribute value to basic attribute profile
                attribute.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().
                        getBuilder(XSString.TYPE_NAME);
                XSString stringValue;

                //Need to check if the claim has multiple values
                if (userAttributeSeparator != null && claimValue.contains(userAttributeSeparator)) {
                    if(shouldReturnCustomValue(claimUri)){
                        StringTokenizer st = new StringTokenizer(claimValue, userAttributeSeparator);
                        String customClaimValue = "";
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            attValue=removeUserStoreDomainPrefix(attValue,requestUserStoreDomain);
                            if (attValue != null && attValue.trim().length() > 0) {
                                customClaimValue=customClaimValue+"["+attValue+"]"+userAttributeSeparator;
                            }
                        }
                        customClaimValue = customClaimValue.substring(0, customClaimValue.length() - 1);
                        stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                        stringValue.setValue(customClaimValue);
                        attribute.getAttributeValues().add(stringValue);
                    } else {
                        StringTokenizer st = new StringTokenizer(claimValue, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            if (attValue != null && attValue.trim().length() > 0) {
                                stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                                stringValue.setValue(attValue);
                                attribute.getAttributeValues().add(stringValue);
                            }
                        }
                    }
                } else {
                    stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    stringValue.setValue(claimValue);
                    attribute.getAttributeValues().add(stringValue);
                }

                attStmt.getAttributes().add(attribute);
            }
        }
        if (atLeastOneNotEmpty) {
            return attStmt;
        } else {
            return null;
        }
    }

    private String removeUserStoreDomainPrefix(String attrVal,String userStoreDomain){
        String domainPrefix = userStoreDomain+"/";
        return StringUtils.removeStart(attrVal,domainPrefix);
    }

    private Boolean shouldReturnCustomValue(String claimUri){
        if(requestUserStoreDomain.equals(targetUserStoreDomain) && requestIssuer.equals(targetIssuer) &&
           requestTenantDomain.equals(targetTenantDomain) && Arrays.asList(targetClaimUris).contains(claimUri)) {
            return  true;
        }
        return false;
    }

    private void resetRequestInfo(){
        requestUserStoreDomain=null;
        requestTenantDomain=null;
        requestIssuer=null;
    }
}
