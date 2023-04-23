package example.saml.sp;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.filter.GenericFilterBean;


public class SamlSsoEntryPoint extends GenericFilterBean implements AuthenticationEntryPoint{
    
    @Value("${sp.entity_id}")
    protected String entityId;
	
    @Value("${sp.acs}")
    private String acs;
    
    @Value("${sp.single_sign_on_service_location}")
    private String ssoLocation;

    @Value("${sp.login_url}")
    private String loginUrl;

	
	private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
	
	protected static final Logger logger = LoggerFactory.getLogger(SamlSsoEntryPoint.class);

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        if (!isLoginUrl(fi.getRequest())) {
            chain.doFilter(request, response);
            return;
        }
        commence(fi.getRequest(), fi.getResponse(), null);
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws ServletException {
        try {
        	AuthnRequest authnRequest = buildAuthnRequest(entityId + acs, SAMLConstants.SAML2_POST_BINDING_URI, buildIssuer(entityId));
        	logger.info("Created AuthnRequest[{}]", SamlUtil.samlObjectToString(authnRequest));
        	
            BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<>();
            HttpServletResponseAdapter transport = new HttpServletResponseAdapter(response, false);
            context.setOutboundMessageTransport(transport);
            context.setPeerEntityEndpoint(getIDPEndpoint(SingleSignOnService.DEFAULT_ELEMENT_NAME, ssoLocation));
            context.setOutboundSAMLMessage(authnRequest);
            HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.encode(context);
        } catch (MessageEncodingException e) {
        	logger.error("Error initializing SAML SSO Request", e);
            throw new ServletException(e);
        }
    }

    private boolean isLoginUrl(HttpServletRequest request) {
        return request.getRequestURI().contains(loginUrl);
    }

    private AuthnRequest buildAuthnRequest(String acsUrl, String protocolBinding, Issuer issuer) {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setIsPassive(true);
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setAssertionConsumerServiceURL(acsUrl);
        authnRequest.setProtocolBinding(protocolBinding);
        authnRequest.setIssuer(issuer);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setID(UUID.randomUUID().toString());
        return authnRequest;
    }
    
	protected Issuer buildIssuer(String issuingEntityName) {
        Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(issuingEntityName);
        issuer.setFormat(NameIDType.ENTITY);
        return issuer;
    }

	protected Endpoint getIDPEndpoint(QName qName, String location) {
        Endpoint samlEndpoint = buildSAMLObject(Endpoint.class, qName);
        samlEndpoint.setLocation(location);
        return samlEndpoint;
    }
	
    @SuppressWarnings("unchecked")
    static <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
        return (T) builderFactory.getBuilder(qName).buildObject(qName);
    }

}