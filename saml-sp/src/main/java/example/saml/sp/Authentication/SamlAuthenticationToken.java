package example.saml.sp.Authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class SamlAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -6564964338541714005L;
	private final String principal;

    public SamlAuthenticationToken(String principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
