package mx.m3security.multiva.gestionldap.repository;

import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.LdapGroup;

@Slf4j
@Service
public class LdapGroupRepository {

	@Value("${ldap.groups.ou}")
	private String groupsOU;
	
	@Value("${spring.ldap.base}")
	private String base;

	@Value("${ldap.users.ou}")
	private String usersOU;
	
	@Autowired
	private LdapTemplate ldapTemplate;

	public LdapGroup findLdapGroup(final String cn) {

		String dn = "cn=" + cn + ",ou=" + groupsOU;
		return ldapTemplate.lookup(dn, new LdapGroupAttributesMapper());
	}
	
	public boolean isUserMemberOfGroup(final String username, final String group) {

		String dnGroup = "cn=" + group + ",ou=" + groupsOU;
		
		log.info(dnGroup);
		LdapGroup ldapGroup = ldapTemplate.lookup(dnGroup, new LdapGroupAttributesMapper());
		if (ldapGroup !=null) {
			log.info("ldapGroup cn:" + ldapGroup.getCn());
		}
		String dnUser = "uid=" + username + ",ou=" + usersOU + "," + base;
		return ldapGroup != null && ldapGroup.getMember().contains(dnUser);
		
	}

	/**
	 * Custom person attributes mapper, maps the attributes to the person POJO
	 */
	private class LdapGroupAttributesMapper implements AttributesMapper<LdapGroup> {
		public LdapGroup mapFromAttributes(Attributes attrs) throws NamingException {

			LdapGroup ldapGroup = new LdapGroup();
			List<String> listOfMembers = new ArrayList<>();

			ldapGroup.setCn(attrs.get("cn") != null ? (String) attrs.get("cn").get() : "");

			if (attrs.get("member") != null) {
				NamingEnumeration<?> members = attrs.get("member").getAll();
				while (members.hasMore()) {
					String value = members.next().toString();
					log.info("member found:" + value);
					listOfMembers.add(value);
				}
			}

			ldapGroup.setMember(listOfMembers);
			return ldapGroup;
		}
	}

}
