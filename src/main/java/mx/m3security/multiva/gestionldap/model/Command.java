package mx.m3security.multiva.gestionldap.model;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Command {

    @JsonAlias("admin_id")
    private String admin_id;
    @JsonAlias("admin_pwd")
    private String admin_pwd;
    private Object commands;

    public Command(String admin_id, String admin_pwd, Object commands) {
        this.admin_id = admin_id;
        this.admin_pwd = admin_pwd;
        this.commands = commands;
    }
}
