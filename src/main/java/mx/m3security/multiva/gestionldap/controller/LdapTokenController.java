package mx.m3security.multiva.gestionldap.controller;

import mx.m3security.multiva.gestionldap.model.LdapUser;
import mx.m3security.multiva.gestionldap.repository.LdapUserRepository;
import mx.m3security.multiva.gestionldap.service.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.LdapToken;
import mx.m3security.multiva.gestionldap.model.Response;
import mx.m3security.multiva.gestionldap.repository.LdapTokenRepository;

import javax.servlet.http.HttpSession;
import java.util.*;

@Slf4j
@Controller
public class LdapTokenController {

	private static final String TIPO_TOKEN = "Tipo Token";
	private static final String ESTADO_TOKEN = "Estado Token";
	private static final String VASCO_TOKEN_SERIAL_NUMBER = "VascoTokenSerialNumber";
	private static final String USUARIO_ASIGNADO = "UsuarioAsignado";
	private static final String BLOB_RO = "Blob RO";
	private static final String VASCO_APP = "Vasco App";
	private static final String VASCO_MODEL = "Vasco Model";
	private static final String INFO_TOKEN = "infoToken";
	private static final String NEW_INFO = "newInfo";
	private static final String TOKEN = "token";
	private static final String ERROR = "error";
	private static final String VISTA_BUSQUEDA_TOKENS = "busquedaTokens";
	
	@Autowired
	private LdapTokenRepository repository;
	@Autowired
	private LdapUserRepository userRepository;
	@Autowired
	private OtpService otpService;

	@GetMapping(value = "/findToken")
	public String getToken(Model model, @ModelAttribute("token") LdapToken info, HttpSession session) {
		log.info("Starting getToken()");
		LdapToken token = null;
		try{
			token = repository.findLdapToken(info.getVascoTokenSerialNumber());
		}catch (Exception e){
			log.info("Error al buscar token");
			log.error(e.getMessage());
		}

		Map<String,Object> tokenMap = new HashMap<>();

		if (token != null) {
			log.info("token was found");
			if (token.getUsuarioAsignado().isEmpty()){
				session.setAttribute("userFlag","false");
				model.addAttribute("msgError","El token no tiene usuario asignado");
			}else{
				session.setAttribute("userFlag","true");
			}
			tokenMap.put(TIPO_TOKEN, token.getTipoToken());
			tokenMap.put(ESTADO_TOKEN, token.getEstadoToken());
			tokenMap.put(VASCO_TOKEN_SERIAL_NUMBER, token.getVascoTokenSerialNumber());
			tokenMap.put(USUARIO_ASIGNADO, token.getUsuarioAsignado());
			tokenMap.put(BLOB_RO, token.getBlobRO());
			tokenMap.put(VASCO_APP, token.getVascoApp());
			tokenMap.put(VASCO_MODEL, token.getVascoModel());
			session.setAttribute("userFlag",session.getAttribute("userFlag"));

			model.addAttribute(INFO_TOKEN,token);
			model.addAttribute(NEW_INFO,new LdapToken());
			model.addAttribute(TOKEN,tokenMap);
		} else {
			log.info("token wasn't found");
			model.addAttribute("user",new LdapToken());
			model.addAttribute("msgError","Error: Token Invalido");
			return "indexToken";
		}
		return VISTA_BUSQUEDA_TOKENS;
	}
	@PostMapping("/addUser")
	public String addUser(@ModelAttribute LdapToken infoToken, Model model, HttpSession session){
		LdapUser user = null;
		try{
			user = userRepository.findLdapUser(infoToken.getUsuarioAsignado());
		}catch (Exception e){
			log.error("Error al obtener usuario");
			e.getMessage();
		}

		if (user != null){
			LdapToken token = repository.findLdapToken(infoToken.getVascoTokenSerialNumber());

			if (user.getVascoTokenSerialNumber() == null || user.getVascoTokenSerialNumber().equals("")){
				if (!token.getUsuarioAsignado().isEmpty()){
					String usuarioAsignado = token.getUsuarioAsignado();
					String[] uid = usuarioAsignado.split(",");
					String[] id = uid[0].split("=");
					LdapUser userAnt = userRepository.findLdapUser(id[1]);
					//Usuario anterior
					userAnt.setTipoToken("");
					userAnt.setVascoTokenSerialNumber("");
					userRepository.modifyLdapUserToken(userAnt);
				}
				//Asignando usuario a token
				token.setUsuarioAsignado("uid="+infoToken.getUsuarioAsignado()+",ou=people,O=MULTIVA,C=MX");
				repository.modifyUserAsignado(token);

				//Asignando Token a Usuario
				user.setVascoTokenSerialNumber(token.getVascoTokenSerialNumber());
				user.setTipoToken(token.getTipoToken());
				userRepository.modifyLdapUserToken(user);
				model.addAttribute("success","Operacion realizada con exito");
			}else{
				model.addAttribute(ERROR,"El usuario ya cuenta con token");

			}
		}else{
			model.addAttribute(ERROR,"Error: UID no existe");
		}
		LdapToken token = repository.findLdapToken(infoToken.getVascoTokenSerialNumber());
		if (token.getUsuarioAsignado().isEmpty()){
			session.setAttribute("userFlag","false");
			model.addAttribute("msgError","El token no tiene usuario asignado");
		}else{
			session.setAttribute("userFlag","true");
		}
		Map<String,Object> tokenMap = new HashMap<>();
		tokenMap.put(TIPO_TOKEN, token.getTipoToken());
		tokenMap.put(ESTADO_TOKEN, token.getEstadoToken());
		tokenMap.put(VASCO_TOKEN_SERIAL_NUMBER, token.getVascoTokenSerialNumber());
		tokenMap.put(USUARIO_ASIGNADO, token.getUsuarioAsignado());
		tokenMap.put(BLOB_RO, token.getBlobRO());
		tokenMap.put(VASCO_APP, token.getVascoApp());
		tokenMap.put(VASCO_MODEL, token.getVascoModel());
		session.setAttribute("userFlag",session.getAttribute("userFlag"));

		model.addAttribute(INFO_TOKEN,token);
		model.addAttribute(TOKEN,tokenMap);
		model.addAttribute(NEW_INFO,new LdapToken());
		return VISTA_BUSQUEDA_TOKENS;
	}

	@PostMapping("/removerUsuario")
	public String removerUsuario(@ModelAttribute LdapToken infoToken, Model model, HttpSession session){
		String usuarioAsingado = infoToken.getUsuarioAsignado();
		String[] usuario = usuarioAsingado.split(",");
		String[] uid = usuario[0].split("=");

		try{
			LdapToken token = repository.findLdapToken(infoToken.getVascoTokenSerialNumber());
			repository.removeUserAsignado(token);

			//removiendo token asignado al usuario
			LdapUser user = userRepository.findLdapUser(uid[1]);
			userRepository.removeLdapUserToken(user);
			model.addAttribute("success","Operacion realizada con exito");
		}catch (Exception e){
			log.error("Error remover usuario");
			model.addAttribute(ERROR,"Error al remover usuario");
			e.getMessage();
		}
		LdapToken token = repository.findLdapToken(infoToken.getVascoTokenSerialNumber());
		if (token.getUsuarioAsignado().isEmpty()){
			session.setAttribute("userFlag","false");
			model.addAttribute("msgError","El token no tiene usuario asignado");
		}else{
			session.setAttribute("userFlag","true");
		}
		Map<String,Object> tokenMap = new HashMap<>();
		tokenMap.put(TIPO_TOKEN, token.getTipoToken());
		tokenMap.put(ESTADO_TOKEN, token.getEstadoToken());
		tokenMap.put(VASCO_TOKEN_SERIAL_NUMBER, token.getVascoTokenSerialNumber());
		tokenMap.put(USUARIO_ASIGNADO, token.getUsuarioAsignado());
		tokenMap.put(BLOB_RO, token.getBlobRO());
		tokenMap.put(VASCO_APP, token.getVascoApp());
		tokenMap.put(VASCO_MODEL, token.getVascoModel());
		session.setAttribute("userFlag",session.getAttribute("userFlag"));

		model.addAttribute(INFO_TOKEN,token);
		model.addAttribute(TOKEN,tokenMap);
		model.addAttribute(NEW_INFO,new LdapToken());
		return VISTA_BUSQUEDA_TOKENS;
	}
	
	@PutMapping
	public ResponseEntity<Response> updateToken(@RequestBody LdapToken request) {

		LdapToken token = repository.findLdapToken(request.getVascoTokenSerialNumber());

		if (token != null) {
			repository.modifyLdapUser(request);
			Response response = new Response(true, "");
			return ResponseEntity.ok(response);
		} else {
			Response response = new Response(false, "token NO existe");
			return ResponseEntity.ok(response);
		}

	}
	@GetMapping("/reiniciarToken")
	public String reiniciarToken(@ModelAttribute LdapToken infoToken, Model model,HttpSession session){
		LdapToken token = null;
		try{
			String[] usuario = infoToken.getUsuarioAsignado().split(",");
			String[] uid = usuario[0].split("=");
			String msj = otpService.reiniciarTokenQa(uid[1]);

			try{
				token = repository.findLdapToken(infoToken.getVascoTokenSerialNumber());
			}catch (Exception e){
				log.info("Error al buscar token");
				log.error(e.getMessage());
			}

			Map<String,Object> tokenMap = new HashMap<>();

			if (token != null) {
				log.info("token was found");
				if (token.getUsuarioAsignado().isEmpty()){
					session.setAttribute("userFlag","false");
					model.addAttribute("msgError","El token no tiene usuario asignado");
				}else{
					session.setAttribute("userFlag","true");
				}
				tokenMap.put(TIPO_TOKEN, token.getTipoToken());
				tokenMap.put(ESTADO_TOKEN, token.getEstadoToken());
				tokenMap.put(VASCO_TOKEN_SERIAL_NUMBER, token.getVascoTokenSerialNumber());
				tokenMap.put(USUARIO_ASIGNADO, token.getUsuarioAsignado());
				tokenMap.put(BLOB_RO, token.getBlobRO());
				tokenMap.put(VASCO_APP, token.getVascoApp());
				tokenMap.put(VASCO_MODEL, token.getVascoModel());
				session.setAttribute("userFlag",session.getAttribute("userFlag"));

				model.addAttribute(INFO_TOKEN,token);
				model.addAttribute(NEW_INFO,new LdapToken());
				model.addAttribute(TOKEN,tokenMap);
			} else {
				log.info("token wasn't found");
				model.addAttribute("user",new LdapToken());
				model.addAttribute("msgError","Error: Token Invalido");
				return "indexToken";
			}

			if (msj.contains("Error")) {
				model.addAttribute("error","ERROR AL REINICIAR TOKEN");
			}else{
				model.addAttribute("success","EL TOKEN SE REINICIO CORRECTAMENTE");
			}
		}catch (Exception e){
			log.info("Error al reiniciar token: "+e.getMessage());
			log.info(Arrays.toString(e.getStackTrace()));
		}
		return VISTA_BUSQUEDA_TOKENS;
	}
}
