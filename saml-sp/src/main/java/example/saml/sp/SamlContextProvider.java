package example.saml.sp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SamlContextProvider {

    public SamlContext getLocalContext(HttpServletRequest request, HttpServletResponse response) {
        return new SamlContext(request, response);
    }
}
