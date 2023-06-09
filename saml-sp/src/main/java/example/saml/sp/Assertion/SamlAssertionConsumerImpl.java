package example.saml.sp.Assertion;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import example.saml.sp.SamlUserDetailsImpl;
import example.saml.sp.SamlUtil;

public class SamlAssertionConsumerImpl implements SamlAssertionConsumer {

    private static final Logger logger = LoggerFactory.getLogger(SamlAssertionConsumerImpl.class);
    /**
     * SAML assertion valid time(minute)
     */
    private static final int ASSERTION_VALID_TIME = 30;
    
    public UserDetails consume(Response samlResponse) throws AuthenticationException {
        validateSignature(samlResponse);
        checkAuthnInstant(samlResponse);
        Assertion assertion = samlResponse.getAssertions().get(0);
        logger.debug("Assertion[{}]", SamlUtil.samlObjectToString(assertion));
        return createUser(assertion);
    }

    private SamlUserDetailsImpl createUser(Assertion assertion) {
        String nameID = assertion.getSubject().getNameID().getValue();
        AttributeStatement attributeStatement = assertion.getAttributeStatements().get(0);
        List<Attribute> attributes = attributeStatement.getAttributes();
        return new SamlUserDetailsImpl(nameID, attributes);
    }

    private void validateSignature(Response samlResponse) throws AuthenticationException {
        try {
            Signature signature = samlResponse.getSignature();
            PublicKey publicKey = extractPublicKey(signature);
            SignatureValidator validator = createValidator(publicKey);
            validator.validate(samlResponse.getSignature());
            logger.debug("Signature validation success");
        } catch (CertificateException e) {
        	logger.error("Invalid certification(public key)", e);
            throw new BadCredentialsException("Invalid certification(public key)", e);
        } catch (ValidationException e) {
        	logger.error("Signature validation fail.", e);
            throw new BadCredentialsException("Signature validation fail", e);
        }
    }

    private PublicKey extractPublicKey(Signature signature) throws CertificateException {
        X509Data x509Data = signature.getKeyInfo().getX509Datas().get(0);
        X509Certificate cert = x509Data.getX509Certificates().get(0);
        String wrappedCert = wrapBase64String(cert.getValue());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
        return certificate.getPublicKey();
    }

    private String wrapBase64String(String base64String) {
        int lineLength = 64;
        char[] rawArr = base64String.toCharArray();
        int wrappedArrLength = rawArr.length + (int)Math.ceil(rawArr.length / 64d) - 1;
        char[] wrappedArr = new char[wrappedArrLength];

        int destPosition = 0;
        for (int i = 0; i < rawArr.length; i += lineLength) {
            if (rawArr.length - i > lineLength) {
                System.arraycopy(rawArr, i, wrappedArr, destPosition, lineLength);
                destPosition += lineLength;
                wrappedArr[destPosition] = '\n';
                destPosition += 1;
            } else {
                System.arraycopy(rawArr, i, wrappedArr, destPosition, rawArr.length - i);
            }
        }
        return "-----BEGIN CERTIFICATE-----\n" + String.valueOf(wrappedArr) + "\n-----END CERTIFICATE-----";
    }

    private SignatureValidator createValidator(PublicKey publicKey) {
        BasicCredential credential = new BasicCredential();
        credential.setPublicKey(publicKey);
        return new SignatureValidator(credential);
    }

    private void checkAuthnInstant(Response samlResponse) throws AuthenticationException {
        Assertion assertion = samlResponse.getAssertions().get(0);
        AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
        DateTime authnInstant = authnStatement.getAuthnInstant();
        logger.debug("AuthnInstant[{}]", authnInstant);

        DateTime validTime = authnInstant.plusMinutes(ASSERTION_VALID_TIME);
        if (DateTime.now().compareTo(validTime) > 0) {
            throw new CredentialsExpiredException("AuthnInstant time out : " + authnInstant);
        }
    }
}