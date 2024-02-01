package mx.m3security.multiva.gestionldap.repository;

import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Service;

import mx.m3security.multiva.gestionldap.model.LdapToken;

import java.util.ArrayList;
import java.util.List;

import static mx.m3security.multiva.gestionldap.util.Constants.*;

@Service
@Slf4j
public class LdapTokenRepository {

	@Value("${ldap.tokens.ou}")
	private String tokensOU;

	@Autowired
	private LdapTemplate ldapTemplate;
	
	public LdapToken findLdapToken(final String vascoTokenSerialNumber) {
		LdapToken token = null;
		String dn = "vascoTokenSerialNumber=" + vascoTokenSerialNumber + ",ou=" + tokensOU;
		try {
			 token = ldapTemplate.lookup(dn, new LdapTokenAttributesMapper());
		}catch (Exception e){
			log.info(e.getMessage());
			log.error(e.getLocalizedMessage());
		}
        return token;
    }
	public void modifyUserAsignado(final LdapToken ldapToken) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", tokensOU)
				.add(ID_TOKEN, ldapToken.getVascoTokenSerialNumber())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(USUARIO_ASIGNADO, ldapToken.getUsuarioAsignado());
		context.setAttributeValue(TIPO_TOKEN,ldapToken.getTipoToken());
		ldapTemplate.modifyAttributes(context);
	}
	public void removeUserAsignado(final LdapToken ldapToken) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", tokensOU)
				.add("vascoTokenSerialNumber", ldapToken.getVascoTokenSerialNumber())
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(USUARIO_ASIGNADO, "");
		ldapTemplate.modifyAttributes(context);
	}
	public void modifyLdapUser(final LdapToken ldapToken) {
        Name dn = LdapNameBuilder
          .newInstance()
          .add("ou", "tokensOU")
          .add(ID_TOKEN, ldapToken.getVascoTokenSerialNumber())
          .build();
        DirContextOperations context = ldapTemplate.lookupContext(dn);
        context.setAttributeValue(ESTADO_TOKEN, ldapToken.getEstadoToken());
        context.setAttributeValue(USUARIO_ASIGNADO, ldapToken.getUsuarioAsignado());
        ldapTemplate.modifyAttributes(context);
    }
	public List<String> getTokensAsociados(String vascoToken){
		List<String> listToken = new ArrayList<>();
		List<String> listTokensSerial = ldapTemplate.list("ou=tokens");

		if (!vascoToken.equals("")){
			for (String token : listTokensSerial){
				String[] cadena = token.split("=");
				LdapToken ldapToken = findLdapToken(cadena[1]);
				if (ldapToken.getVascoTokenSerialNumber().contains(vascoToken))
					listToken.add(ldapToken.getVascoTokenSerialNumber());
			}
		}

		return listToken;
	}
	public boolean validateWithListTokens(String vascoToken){
		List<String> list = ldapTemplate.list("ou=tokens");
		for (String token : list){
			String[] cadena = token.split("=");
			if (vascoToken.equals(cadena[1])){
				return true;
			}
		}
		return false;
	}

	public void modifyLdapTipoToken(String idToken, String tipotoken) {
		Name dn = LdapNameBuilder
				.newInstance()
				.add("ou", tokensOU)
				.add(ID_TOKEN, idToken)
				.build();
		DirContextOperations context = ldapTemplate.lookupContext(dn);
		context.setAttributeValue(TIPO_TOKEN, tipotoken);
		ldapTemplate.modifyAttributes(context);
	}

	/**
     * Custom person attributes mapper, maps the attributes to the person POJO
     */
    private class LdapTokenAttributesMapper implements AttributesMapper<LdapToken> {
        public LdapToken mapFromAttributes(Attributes attrs) throws NamingException {
        	LdapToken ldapToken = new LdapToken();

        	ldapToken.setVascoTokenSerialNumber(attrs.get(ID_TOKEN)!=null?(String)attrs.get(ID_TOKEN).get():"");
        	ldapToken.setTipoToken(attrs.get(TIPO_TOKEN)!=null?(String)attrs.get(TIPO_TOKEN).get():"");
        	ldapToken.setBlobRO(attrs.get(BLOB_RO)!=null?(String)attrs.get(BLOB_RO).get():"");
        	ldapToken.setEstadoToken(attrs.get(ESTADO_TOKEN)!=null?(String)attrs.get(ESTADO_TOKEN).get():"");
        	ldapToken.setUsuarioAsignado(attrs.get(USUARIO_ASIGNADO)!=null?(String)attrs.get(USUARIO_ASIGNADO).get():"");
        	ldapToken.setVascoApp(attrs.get(VASCO_APP)!=null?(String)attrs.get(VASCO_APP).get():"");
        	ldapToken.setVascoModel(attrs.get(VASCO_MODEL)!=null?(String)attrs.get(VASCO_MODEL).get():"");
            return ldapToken;
        }
    }
	
}
