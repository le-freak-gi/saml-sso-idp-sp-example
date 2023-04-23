package example.saml.sp.Assertion;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import example.saml.sp.SamlContext;
import example.saml.sp.SamlContextProvider;
import example.saml.sp.Authentication.SamlPreAuthenticationToken;

/**
 * SAML assertion consume url filter
 */
public final class SamlAssertionConsumeFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(SamlAssertionConsumeFilter.class);

    private SamlContextProvider samlContextProvider;

    public SamlAssertionConsumeFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
    	logger.debug("Attempt authentication...");
        SamlContext samlContext = samlContextProvider.getLocalContext(request, response);
        SamlPreAuthenticationToken token = new SamlPreAuthenticationToken(samlContext);
        return getAuthenticationManager().authenticate(token);
    }

    public SamlAssertionConsumeFilter samlContextProvider(SamlContextProvider samlContextProvider) {
        this.samlContextProvider = samlContextProvider;
        return this;
    }
}
