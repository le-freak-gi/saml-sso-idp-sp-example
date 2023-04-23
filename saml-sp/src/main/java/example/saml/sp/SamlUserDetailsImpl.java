package example.saml.sp;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.opensaml.saml2.core.Attribute;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
@Setter
@ToString
public class SamlUserDetailsImpl implements UserDetails {

    private static final long serialVersionUID = -2427639188304357098L;
	private String username;
    private String email;
    private String role;
    private List<GrantedAuthority> authorities = new ArrayList<>();

    public SamlUserDetailsImpl(String username, List<Attribute> samlAttributes) {
        this.username = username;
        
        for (Attribute attr : samlAttributes) {
            String attrName  = attr.getName();
            switch (attrName) {
                case "User.Email":
                    email = SamlUtil.getStringFromXMLObject(attr.getAttributeValues().get(0));
                    break;
                case "User.Role":
                	role = SamlUtil.getStringFromXMLObject(attr.getAttributeValues().get(0));
                    break;
            }
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

	@Override
	public String getUsername() {
		return this.username;
	}
}