package mx.m3security.multiva.gestionldap.repository;

import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.Cuenta;
import mx.m3security.multiva.gestionldap.model.LdapToken;
import mx.m3security.multiva.gestionldap.service.IsamService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.*;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Service;

import mx.m3security.multiva.gestionldap.model.LdapUser;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Slf4j
@Service
public class LdapUserRepository {

	public static final String TIPO_TOKEN = "tipoToken";
	public static final String ID_TOKEN = "vascoTokenSerialNumber";

	@Value("${ldap.users.ou}")
	private String usersOU;

	@Value("${spring.ldap.base}")
	private String base;

	@Value("${ldap.users.id}")
	private String uid;
	
	@Autowired
	private ContextSource contextSource;
	@Autowired
	private LdapTemplate ldapTemplate;
	@Autowired
	private IsamService isamService;
	@Autowired
	private LdapTokenRepository tokenRepository;

	public void searUser(){
		// BAD: User input used in DN (Distinguished Name) without encoding
		String dn = "OU=People,O=" + "MULTIVA,C=MX";

		// BAD: User input used in search filter without encoding
		String filter = "username=" + "1000144269";
		ldapTemplate.search(dn,filter, (NameClassPairCallbackHandler) new SearchControls());

	}

	public void authenticate(final String username, final String password) {
		
		String dn = uid + "=" + username + ",ou=" + usersOU + "," + base;
        contextSource.getContext(dn, password);
        
    }
	public LdapUser findLdapUser(final String cn) {
		
		String dn = uid + "=" + cn + ",ou=" + usersOU;
		log.info("findLdapUser DN: "+dn);
        return ldapTemplate.lookup(dn, new LdapUserAttributesMapper());
    }

	public void modifyLdapUser(final LdapUser ldapUser) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", ldapUser.getUid())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(TIPO_TOKEN, ldapUser.getTipoToken());
		context.setAttributeValue(ID_TOKEN, ldapUser.getVascoTokenSerialNumber());
		ldapTemplate.modifyAttributes(context);
	}
	public void modifyLdapUserToken(final LdapUser ldapUser) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", ldapUser.getUid())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(ID_TOKEN, ldapUser.getVascoTokenSerialNumber());
		context.setAttributeValue(TIPO_TOKEN, ldapUser.getTipoToken() != null? ldapUser.getTipoToken() : "");
		ldapTemplate.modifyAttributes(context);
	}
	public void removeLdapUserToken(final LdapUser ldapUser) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", ldapUser.getUid())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(ID_TOKEN, "");
		context.setAttributeValue(TIPO_TOKEN, "");
		ldapTemplate.modifyAttributes(context);
	}
	public void reinicarToken(String token,final String uid) {
		LdapUser user = findLdapUser(uid);
		if (user.getVascoTokenSerialNumber().equals(token)){
			log.info(user.getUid());
			Name dn = LdapNameBuilder
					.newInstance()
					.add("ou", usersOU)
					.add("uid", uid)
					.build();
			DirContextOperations context = ldapTemplate.lookupContext(dn);
			context.setAttributeValue(ID_TOKEN, "");
			context.setAttributeValue(TIPO_TOKEN, "");
		}
	}
	public void modifyLdapUserMail(final LdapUser ldapUser) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", ldapUser.getUid())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue("mail", ldapUser.getMail());
		ldapTemplate.modifyAttributes(context);
	}

	public void modifyLdapUserTipoToken(String uid, String tipotoken) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", uid)
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(TIPO_TOKEN, tipotoken);
		ldapTemplate.modifyAttributes(context);
	}

	/**
     * Custom person attributes mapper, maps the attributes to the person POJO
     */
    private class LdapUserAttributesMapper implements AttributesMapper<LdapUser> {
        public LdapUser mapFromAttributes(Attributes attrs) throws NamingException {
			LdapUser ldapUser = new LdapUser();
			ldapUser.setUid(attrs.get("uid")!=null?(String)attrs.get("uid").get():"");
			ldapUser.setCountIVR(attrs.get("countIVR")!=null?(String)attrs.get("countIVR").get():"");
			ldapUser.setMail(attrs.get("mail")!=null?(String)attrs.get("mail").get():"");
			ldapUser.setNumCliente(attrs.get("NumCliente")!=null?(String)attrs.get("NumCliente").get():"");
			ldapUser.setNumeroCliente(attrs.get("numeroCliente")!=null?(String)attrs.get("numeroCliente").get():"");
			ldapUser.setCountSLD(attrs.get("countSLD")!=null?(String)attrs.get("countSLD").get():"");
			ldapUser.setSn(attrs.get("sn")!=null?(String)attrs.get("sn").get():"");
			ldapUser.setStatusGRAL(attrs.get("statusGRAL")!=null?(String)attrs.get("statusGRAL").get():"");
			ldapUser.setCountPIV(attrs.get("countPIV")!=null?(String)attrs.get("countPIV").get():"");
			ldapUser.setCountGRAL(attrs.get("countGRAL")!=null?(String)attrs.get("countGRAL").get():"");
			ldapUser.setTipoToken(attrs.get(TIPO_TOKEN)!=null?(String)attrs.get(TIPO_TOKEN).get():"");
			ldapUser.setCn(attrs.get("cn")!=null?(String)attrs.get("cn").get():"");
			ldapUser.setVascoTokenSerialNumber(attrs.get(ID_TOKEN)!=null?(String)attrs.get(ID_TOKEN).get():"");
			ldapUser.setNsUserNIPValid(attrs.get("ns_userNIPValid")!=null?(String)attrs.get("ns_userNIPValid").get():"");
			ldapUser.setNsUserID(attrs.get("ns_userID")!=null?(String)attrs.get("ns_userID").get():"");
			ldapUser.setCanalAsignado(attrs.get("canalAsignado")!=null?(String)attrs.get("canalAsignado").get():"");
			ldapUser.setContratoAceptado(attrs.get("contratoAceptado")!=null?(String)attrs.get("contratoAceptado").get():"");
			ldapUser.setDateFirstFail(attrs.get("dateFirstFail")!=null?(String)attrs.get("dateFirstFail").get():"");
			ldapUser.setPersonalidadFiscal(attrs.get("PersonalidadFiscal")!=null?(String)attrs.get("PersonalidadFiscal").get():"");
			ldapUser.setNsLastupdate(attrs.get("ns_lastUpdate")!=null?(String)attrs.get("ns_lastUpdate").get():"");
			ldapUser.setBanBancamovil(attrs.get("ban_bancamovil")!=null?(String)attrs.get("ban_bancamovil").get():"");
			ldapUser.setTarjeta(attrs.get("tarjeta")!=null?(String)attrs.get("tarjeta").get():"");
			ldapUser.setBanMigrado(attrs.get("banMigrado")!=null?(String)attrs.get("banMigrado").get():"");
			ldapUser.setTelefono(attrs.get("telefono")!=null?(String)attrs.get("telefono").get():"");
			ldapUser.setRfc(attrs.get("RFC")!=null?(String)attrs.get("RFC").get():"");
			ldapUser.setBanBancamovil(attrs.get("banBancamovil")!=null?(String)attrs.get("banBancamovil").get():"");
			ldapUser.setTipoPersona(attrs.get("tipoPersona")!=null?(String)attrs.get("tipoPersona").get():"");
			ldapUser.setBanNotificaciones(attrs.get("ban_notificaciones")!=null?(String)attrs.get("ban_notificaciones").get():"");
			ldapUser.setFechaUltimoLogin(attrs.get("fechaUltimoLogin")!=null?(String)attrs.get("fechaUltimoLogin").get():"");
			ldapUser.setRazonSocial(attrs.get("razonSocial")!=null?(String)attrs.get("razonSocial").get():"");
			ldapUser.setAliasMva(attrs.get("aliasMva")!=null?(String)attrs.get("aliasMva").get():"");
			ldapUser.setAliasAlfa(attrs.get("aliasAlfa")!=null?(String)attrs.get("aliasAlfa").get():"");
			ldapUser.setFechaNotificaciones(attrs.get("fechaNotificaciones")!=null?(String)attrs.get("fechaNotificaciones").get():"");
			ldapUser.setUid2(attrs.get("uid2")!=null?(String)attrs.get("uid2").get():"");
			ldapUser.setBanCodi(attrs.get("ban_codi")!=null?(String)attrs.get("ban_codi").get():"");
			ldapUser.setIdDispositivo(attrs.get("id_dispositivo")!=null?(String)attrs.get("id_dispositivo").get():"");
			ldapUser.setSldLastbind(attrs.get("SLD_lastBind")!=null?(String)attrs.get("SLD_lastBind").get():"");
			ldapUser.setNsLastbind(attrs.get("ns_lastBind")!=null?(String)attrs.get("ns_lastBind").get():"");
			ldapUser.setFechaLastAccessBE(attrs.get("fechaLastAccessBE")!=null?(String)attrs.get("fechaLastAccessBE").get():"");
			ldapUser.setNsUserNIP(attrs.get("nsUserNIP")!=null?(String)attrs.get("nsUserNIP").get():"");
			ldapUser.setRequestType(attrs.get("requestType")!=null?(String)attrs.get("requestType").get():"");
			ldapUser.setFechaUltimoAcceso(attrs.get("fechaUltimoAcceso")!=null?(String)attrs.get("fechaUltimoAcceso").get():"");
			ldapUser.setCuenta(attrs.get("cuenta")!=null?(String)attrs.get("cuenta").get():"");
			ldapUser.setNsUserNIP(attrs.get("ns_userNIP")!=null?(String)attrs.get("ns_userNIP").get():"");
			ldapUser.setBlobRO(attrs.get("blobRO")!=null?(String)attrs.get("blobRO").get():"");
			ldapUser.setFechaAltaUsuario(attrs.get("fechaAltaUsuario")!=null?(String)attrs.get("fechaAltaUsuario").get():"");
			ldapUser.setFechaAsignacion(attrs.get("fechaAsignacion")!=null?(String)attrs.get("fechaAsignacion").get():"");
			ldapUser.setNsModby(attrs.get("ns_modby")!=null?(String)attrs.get("ns_modby").get():"");

			byte[] password = (byte[]) attrs.get("userPassword").get();
			log.info("decode passwprd: "+ new String(password));
			String encodedString = Base64.getEncoder().encodeToString(new String(password).getBytes());
			log.info("encode passwprd: "+ encodedString);
			ldapUser.setUserPassword(encodedString);
			ldapUser.setObjClass(attrs.get("objectClass")!=null?(String)attrs.get("objectClass").get():"");
            return ldapUser;
        }
    }

	public List<Cuenta> getList(String numeroCliente){
		List<Cuenta> cuentasAsociadas = new ArrayList<>();
		List<String> cuentasSecundarias = getCuentasSecundarias(ldapTemplate.list("ou=people"));
		for (String cuenta : cuentasSecundarias){
			LdapUser user = findLdapUser(cuenta);
			LdapToken token = tokenRepository.findLdapToken(user.getVascoTokenSerialNumber());
			if (user.getNumeroCliente().equals(numeroCliente)){
				Cuenta cuentaUser = new Cuenta();

				cuentaUser.setId(user.getUid());
				cuentaUser.setToken(user.getVascoTokenSerialNumber());
				cuentaUser.setStatusToken(token != null? token.getEstadoToken() : "");
				cuentasAsociadas.add(cuentaUser);
			}
		}
		return cuentasAsociadas;
	}
	private List<String> getCuentasSecundarias(List<String> list){
		List<String> cuentasSecundarias = new ArrayList<>();
		for (String cuenta : list){
			String[] uid = cuenta.split("=");
			if (uid[1].startsWith("200")){
				cuentasSecundarias.add(uid[1]);

			}
		}
		return cuentasSecundarias;
	}

	public String remove(LdapUser user){
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", usersOU)
				.add("uid", user.getUid())
				.build();

		ldapTemplate.unbind(dn);
		return "removed successfully";
	}

}
