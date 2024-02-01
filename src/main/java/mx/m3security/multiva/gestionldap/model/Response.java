package mx.m3security.multiva.gestionldap.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Response{
	
	private boolean result;
	private String error;      
}
