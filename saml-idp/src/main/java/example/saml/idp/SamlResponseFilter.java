package example.saml.idp;

import static java.util.Objects.isNull;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.binding.SAMLMessageContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import example.saml.idp.princial.AbstractSamlPrincipalFactory;
import example.saml.idp.princial.SamlPrincipalImpl;

public class SamlResponseFilter extends OncePerRequestFilter {

    private final String ssoUrl;
    private SamlMessageHandler samlMessageHandler;
    private AbstractSamlPrincipalFactory samlPrincipalFactory;

    public SamlResponseFilter(String ssoUrl) {
        this.ssoUrl = ssoUrl;
    }

    @Autowired
    public void setSamlMessageHandler(SamlMessageHandler samlMessageHandler) {
        this.samlMessageHandler = samlMessageHandler;
    }

    @Autowired
    public void setSamlMessageHandler(AbstractSamlPrincipalFactory samlPrincipalFactory) {
        this.samlPrincipalFactory = samlPrincipalFactory;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException {
        try {
            if (!request.getRequestURI().startsWith(ssoUrl)) {
                filterChain.doFilter(request, response);
                return;
            }
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (isNull(authentication)
                    || authentication instanceof AnonymousAuthenticationToken
                    || !authentication.isAuthenticated()) {
                filterChain.doFilter(request, response);
                return;
            }
            @SuppressWarnings("rawtypes")
            SAMLMessageContext messageContext = samlMessageHandler.extractSAMLMessageContext(request, response);
            
            
            SamlPrincipalImpl principal = samlPrincipalFactory.createSamlPrincipal(messageContext, authentication);
            samlMessageHandler.sendAuthnResponse(principal, response);
            
            
        } catch (Exception e) {
            throw new ServletException("Failed to send saml response.", e);
        }
    }
}
