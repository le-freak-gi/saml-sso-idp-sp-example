package example.saml.sp.Authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import example.saml.sp.SamlContext;

public class SamlPreAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1938956501819417019L;
	private SamlContext samlContext;

    public SamlPreAuthenticationToken(SamlContext samlContext) {
        super(null);
        this.samlContext = samlContext;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    public SamlContext samlContext() {
        return samlContext;
    }

    public SamlPreAuthenticationToken samlContext(SamlContext samlContext) {
        this.samlContext = samlContext;
        return this;
    }
}
