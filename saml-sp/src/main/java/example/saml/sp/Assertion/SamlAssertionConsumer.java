package example.saml.sp.Assertion;

import org.opensaml.saml2.core.Response;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * A SAML assertion(SAML response) consumer.
 */
public interface SamlAssertionConsumer {

    UserDetails consume(Response samlResponse) throws AuthenticationException;
}
