package example.saml.idp;

import static example.saml.idp.SamlBuilder.buildAssertion;
import static example.saml.idp.SamlBuilder.buildIssuer;
import static example.saml.idp.SamlBuilder.buildSAMLObject;
import static example.saml.idp.SamlBuilder.buildStatus;
import static example.saml.idp.SamlBuilder.signAssertion;
import static java.util.Arrays.asList;
import static org.opensaml.xml.Configuration.getValidatorSuite;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;

import example.saml.idp.princial.SamlPrincipalImpl;

public class SamlMessageHandler {
	
	private static final Logger logger = LoggerFactory.getLogger(SamlMessageHandler.class);
	
    private final KeyManager keyManager;
    private final SAMLMessageDecoder decoder;
    private final SecurityPolicyResolver resolver;
    private final List<ValidatorSuite> validatorSuites;
    private final SAMLMessageEncoder encoder;
    private final String entityId;

    public SamlMessageHandler(String entityId,
                              KeyManager keyManager,
                              SAMLMessageDecoder decoder,
                              SAMLMessageEncoder encoder,
                              SecurityPolicyResolver securityPolicyResolver) {
        this.entityId = entityId;
        this.keyManager = keyManager;
        this.decoder = decoder;
        this.encoder = encoder;
        this.resolver = securityPolicyResolver;
        this.validatorSuites = asList(getValidatorSuite("saml2-core-schema-validator")
                , getValidatorSuite("saml2-core-spec-validator"));
    }

    public SAMLMessageContext extractSAMLMessageContext(HttpServletRequest request,
                                                        HttpServletResponse response)
            throws ValidationException, SecurityException, MessageDecodingException {
        SAMLMessageContext messageContext = new SAMLMessageContext();
        HttpServletRequestAdapter inTransport = new HttpServletRequestAdapter(request);
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, request.isSecure());
        request.setAttribute(org.springframework.security.saml.SAMLConstants.LOCAL_CONTEXT_PATH, request.getContextPath());
        messageContext.setInboundMessageTransport(inTransport);
        messageContext.setOutboundMessageTransport(outTransport);
        messageContext.setSecurityPolicyResolver(resolver);
        decoder.decode(messageContext);

        SAMLObject inboundSAMLMessage = messageContext.getInboundSAMLMessage();
        
        if (inboundSAMLMessage instanceof AuthnRequest) {
        	 System.out.println("###################### is login request");
        }else if(inboundSAMLMessage instanceof LogoutRequest) {
        	 System.out.println("###################### is logout request");
        }
        
        
        AuthnRequest authnRequest = (AuthnRequest) inboundSAMLMessage;
        for (ValidatorSuite validatorSuite : validatorSuites) {
            validatorSuite.validate(authnRequest);
        }
        return messageContext;
    }

    public void sendAuthnResponse(SamlPrincipalImpl principal, HttpServletResponse response)
            throws MarshallingException, SignatureException, MessageEncodingException {
        Status status = buildStatus(StatusCode.SUCCESS_URI);
        Credential signingCredential = resolveCredential(entityId);
        Response authResponse = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
        Issuer issuer = buildIssuer(entityId);
        authResponse.setIssuer(issuer);
        authResponse.setID(SamlBuilder.randomSAMLId());
        authResponse.setIssueInstant(new DateTime());
        authResponse.setInResponseTo(principal.getRequestID());

        Assertion assertion = buildAssertion(principal, status, entityId);
        signAssertion(assertion, signingCredential);
        authResponse.getAssertions().add(assertion);
        authResponse.setDestination(principal.getAssertionConsumerServiceUrl());
        authResponse.setStatus(status);

        Endpoint endpoint = buildSAMLObject(Endpoint.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        endpoint.setLocation(principal.getAssertionConsumerServiceUrl());
        HttpServletResponseAdapter outTransport = new HttpServletResponseAdapter(response, false);

        BasicSAMLMessageContext<SAMLObject, Response, SAMLObject> context = new BasicSAMLMessageContext<>();
        context.setOutboundMessageTransport(outTransport);
        context.setPeerEntityEndpoint(endpoint);
        context.setOutboundSAMLMessage(authResponse);
        context.setOutboundSAMLMessageSigningCredential(signingCredential);
        context.setOutboundMessageIssuer(entityId);
        context.setRelayState(principal.getRelayState());
        SamlUtil.samlObjectToString(authResponse);
        logger.info("Created AuthnResponse[{}]", SamlUtil.samlObjectToString(authResponse));
        encoder.encode(context);
    }

    private Credential resolveCredential(String entityId) {
        try {
            return keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(entityId)));
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        }
    }
}