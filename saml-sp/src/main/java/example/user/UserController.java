package example.user;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {
    @GetMapping("/user")
    public String user(Model model, Authentication authentication) {
        model.addAttribute("samlUser", authentication.getDetails());
        return "user";
    }
}
