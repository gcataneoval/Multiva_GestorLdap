package mx.m3security.multiva.gestionldap.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import mx.m3security.multiva.gestionldap.model.Cuenta;
import mx.m3security.multiva.gestionldap.model.LdapToken;
import mx.m3security.multiva.gestionldap.repository.LdapTokenRepository;
import mx.m3security.multiva.gestionldap.service.IsamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.LdapUser;
import mx.m3security.multiva.gestionldap.repository.LdapUserRepository;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
public class LdapUserController {

	private static final String CUENTAS_ASOCIADAS = "cuentasasociadas";
	private static final String MODULO = "modul";
	private static final String USER = "user";
	private static final String USER_INFO = "userInfo";
	private static final String DOWNLOAD_FLAG = "downloadFlag";
	private static final String TOKENS = "tokens";
	private static final String VALID_INFO = "validInfo";
	private static final String MSG_ERROR = "msgError";
	private static final String ERROR = "error";
	private static final String VISTA_INDEX = "index";
	private static final String VISTA_BUSQUEDA_USUARIOS = "busquedausuarios";
	
	@Autowired
	private LdapUserRepository repository;

	@Autowired
	private LdapTokenRepository tokenRepository;

	@Autowired
	private IsamService service;

	@GetMapping(value = "/findUser")
	public String findUser(Model model, @ModelAttribute("user") LdapUser userInfo, HttpSession session){
		log.info("Starting getUser()");
		LdapUser user = null;
		try{
			user = repository.findLdapUser(userInfo.getUid());
		}catch (Exception e){
			log.info("Error al buscar usuario");
			log.error(e.getMessage());
		}

		if (user != null) {
			getModel(model,user, session);
		} else {
			model.addAttribute(USER,new LdapUser());
			model.addAttribute(MSG_ERROR,"Error: Usuario Invalido");
			return VISTA_INDEX;
		}
		return VISTA_BUSQUEDA_USUARIOS;
	}

	@PostMapping("/cambiarEmail")
	public String changeEmail(Model model,@ModelAttribute LdapUser userInfo, HttpSession session){

		LdapUser user = repository.findLdapUser(userInfo.getUid());

		if (user != null) {
			log.info("Mail "+userInfo.getMail());
			user.setMail(userInfo.getMail());
			repository.modifyLdapUserMail(user);
			getModel(model,user, session);
			model.addAttribute("success","Operacion realizada con exito");
		} else {
			model.addAttribute(USER,new LdapUser());
			model.addAttribute(MSG_ERROR,"Error: Usuario Invalido");
		}

		return VISTA_BUSQUEDA_USUARIOS;
	}

	@PostMapping("/cambiarToken")
	public String changeToken(@ModelAttribute LdapUser userInfo, Model model, HttpSession session){

		LdapToken token = tokenRepository.findLdapToken(userInfo.getVascoTokenSerialNumber());

		if (token != null) {
			if(token.getUsuarioAsignado() == null || token.getUsuarioAsignado().equals("")){
				LdapUser user = repository.findLdapUser(userInfo.getUid());
				if (!user.getVascoTokenSerialNumber().isEmpty()){
					LdapToken tokenAnt = tokenRepository.findLdapToken(userInfo.getVascoTokenSerialNumber());
					tokenAnt.setUsuarioAsignado("");
					tokenAnt.setTipoToken("");
					tokenAnt.setVascoTokenSerialNumber(user.getVascoTokenSerialNumber());
					tokenRepository.modifyUserAsignado(tokenAnt);
				}
				userInfo.setTipoToken("1");
                token.setUsuarioAsignado("uid="+user.getUid()+",ou=people,O=MULTIVA,C=MX");
				token.setTipoToken("1");
				repository.modifyLdapUserToken(userInfo);
                tokenRepository.modifyUserAsignado(token);
				model.addAttribute("success","Operacion realizada con exito");
			}else{
				log.info("El token ya tiene usuario asignado");
				model.addAttribute(ERROR,"El token ya tiene usuario asignado");
			}

		} else {
			model.addAttribute(ERROR,"Error: ID Token no existe");
		}
		LdapUser user = repository.findLdapUser(userInfo.getUid());
		getModel(model,user, session);

		return VISTA_BUSQUEDA_USUARIOS;
	}

	@PostMapping("/cambiarTipoToken")
	public String changeTipoToken(@ModelAttribute LdapUser userInfo, Model model, HttpSession session){

		LdapToken token = tokenRepository.findLdapToken(userInfo.getVascoTokenSerialNumber());

		if (token != null) {
			repository.modifyLdapUserTipoToken(userInfo.getUid(),userInfo.getTipoToken());
			tokenRepository.modifyLdapTipoToken(token.getVascoTokenSerialNumber(),userInfo.getTipoToken());
			model.addAttribute("success","Operacion realizada con exito");
		} else {
			model.addAttribute(ERROR,"Error: ID Token no existe");
		}
		LdapUser user = repository.findLdapUser(userInfo.getUid());

		getModel(model,user, session);

		return VISTA_BUSQUEDA_USUARIOS;
	}

	@PostMapping("/delete")
	public String deleteUser(@ModelAttribute LdapUser userInfo){

		LdapUser user = repository.findLdapUser(userInfo.getUid());

		if (user != null) {
			log.info("User was found");
			service.deleteUser(user.getUid());
		} else {
			log.info("User wasn't found");
		}

		return "redirect:/index";
	}

	@GetMapping("/download")
	public void download(@ModelAttribute LdapUser userInfo, HttpServletResponse response, HttpSession session,Model model) throws IOException {

		LdapUser user = repository.findLdapUser(userInfo.getUid());
		if (user != null){

			getModel(model,user, session);
			session.setAttribute(DOWNLOAD_FLAG,"true");
			response.setContentType("text/plain");
			response.setHeader("Content-Disposition","attachment; filename = " + user.getUid() + ".ldif");
			OutputStream outputStream = response.getOutputStream();
			outputStream.write(service.getDataUser(user).getBytes());
			outputStream.close();

		}
	}

	@GetMapping("/validateUSer")
	public String validateUser(@ModelAttribute LdapUser userInfo, Model model, HttpSession session){
		log.info("Usuario: "+userInfo.getUid());
		LdapUser user = repository.findLdapUser(userInfo.getUid());

		getModel(model,user, session);

		return VISTA_BUSQUEDA_USUARIOS;
	}

	private void getModel(Model model,LdapUser user, HttpSession session){
		if (user.getVascoTokenSerialNumber().isEmpty()){
			session.setAttribute("tokenFlag","false");
			model.addAttribute(MSG_ERROR,"EL USUARIO DEBE TENER UN TOKEN ASIGNADO");
		}else{
			session.setAttribute("tokenFlag","true");
		}
		session.setAttribute("tokenFlag",session.getAttribute("tokenFlag"));
		model.addAttribute(CUENTAS_ASOCIADAS, repository.getList(user.getNumeroCliente()));
		model.addAttribute(MODULO+1,user.getParams1());
		model.addAttribute(MODULO+2,user.getParams2());
		model.addAttribute(MODULO+3,user.getParams3());
		model.addAttribute(USER,user);
		model.addAttribute(USER_INFO,new LdapUser());
		session.setAttribute(DOWNLOAD_FLAG,session.getAttribute(DOWNLOAD_FLAG));
		model.addAttribute(TOKENS,tokenRepository.getTokensAsociados(user.getVascoTokenSerialNumber()));
		model.addAttribute(VALID_INFO,service.validateUser("uid="+user.getUid()));
	}

}
