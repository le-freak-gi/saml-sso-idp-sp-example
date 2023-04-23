package example.saml.idp.princial;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;

import example.saml.idp.SamlAttribute;

public class SamlPrincipalFactoryEx extends AbstractSamlPrincipalFactory {

    public SamlPrincipalFactoryEx(String nameIdType) {
        super(nameIdType);
    }

    @Override
    protected List<SamlAttribute> createAttributes(Authentication authentication) {
    	@SuppressWarnings("unchecked")
		Map<String, Object> userMap = (Map<String, Object>)authentication.getDetails(); 
        return Arrays.asList(
                new SamlAttribute("User.Username", (String)userMap.get("username")),
                new SamlAttribute("User.Email", (String)userMap.get("email")),
                new SamlAttribute("User.Role", (String)userMap.get("role"))
        );
    }
}