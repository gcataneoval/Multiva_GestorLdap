package mx.m3security.multiva.gestionldap.model;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LdapGroup {

	private String cn;
	private List<String> member;
	
	
}
