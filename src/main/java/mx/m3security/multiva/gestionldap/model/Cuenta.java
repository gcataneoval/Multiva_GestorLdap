package mx.m3security.multiva.gestionldap.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Cuenta {
    private String id;
    private String token;
    private String statusToken;
}
