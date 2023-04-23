package example.controller;

import org.owasp.esapi.User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

	@GetMapping("/")
	public String home(Model model) {
	    String username = SecurityContextHolder.getContext().getAuthentication().getName();
	    model.addAttribute("username", username);
	    return "index";
	}
	@GetMapping("/login")
	public String loginView(Model model) {
		System.out.println("#####################"+User.ANONYMOUS.getAccountName());
		if(!SecurityContextHolder.getContext().getAuthentication().getName().equals("anonymousUser")) {
			return "redirect:/";
		}
	    return "login";
	}
}

