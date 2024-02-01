package mx.m3security.multiva.gestionldap.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {

	@PostMapping(value = "/csrf")
	public CsrfToken csrf(CsrfToken token) {
		return token;
	}
}