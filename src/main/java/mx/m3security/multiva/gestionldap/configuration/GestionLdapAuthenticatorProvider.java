package mx.m3security.multiva.gestionldap.configuration;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.repository.LdapGroupRepository;
import mx.m3security.multiva.gestionldap.repository.LdapUserRepository;

@Slf4j
@Component
public class GestionLdapAuthenticatorProvider implements AuthenticationProvider {

	@Value("${ldap.group.admin}")
	private String groupAdmin;
	
	@Autowired
	private LdapUserRepository ldapUserRepository;

	@Autowired
	private LdapGroupRepository ldapGroupRepository;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		log.info("auhtenticating user with credentials:" + authentication.getName());
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		try{
			ldapUserRepository.authenticate(username, password);
		}catch (Exception e){
			log.info("Error: "+ e.getMessage());
			return null;
		}
		
		if (!ldapGroupRepository.isUserMemberOfGroup(username, groupAdmin)) {
			return null;
		}

		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return new UsernamePasswordAuthenticationToken(username, password, authorities);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

}