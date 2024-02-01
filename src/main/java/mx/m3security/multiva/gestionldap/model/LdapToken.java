package mx.m3security.multiva.gestionldap.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LdapToken {

	private String tipoToken;
	private String vascoTokenSerialNumber;
	private String blobRO;
	private String estadoToken;
	private String usuarioAsignado;
	private String vascoApp;
	private String vascoModel;
	
}
