package mx.m3security.multiva.gestionldap.controller;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.LdapToken;
import mx.m3security.multiva.gestionldap.model.LdapUser;
import mx.m3security.multiva.gestionldap.repository.LdapTokenRepository;
import mx.m3security.multiva.gestionldap.repository.LdapUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@Slf4j
@Controller
public class HomeController {
    @Autowired
    private LdapUserRepository repository;
    @Autowired
    private LdapTokenRepository tokenRepository;

    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/error")
    public String loginError(Model model){
        model.addAttribute("Error","Credenciales Incorrectas");
        return "login";
    }

    @GetMapping("/index")
    public String index(Model model, HttpSession session){
        model.addAttribute("user",new LdapUser());
        session.setAttribute("downloadFlag","false");
        session.setAttribute("tokenFlag","false");
        return "index";
    }

    @GetMapping("/indexToken")
    public String indexToken(Model model, HttpSession session){
        model.addAttribute("token",new LdapToken());
        session.setAttribute("downloadFlag","false");
        session.setAttribute("userFlag","false");
        return "indexToken";
    }

    @GetMapping("/logout2")
    public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        // .. perform logout
        logoutHandler.logout(request,response,authentication);
        //logoutHandler.doLogout(request, response, authentication);
        return "redirect:/login";
    }


    @GetMapping("/version")
    public ResponseEntity<String> version() {
        String response = "Gestion LDAP V-1.0";
        return ResponseEntity.ok(response);
    }

}
