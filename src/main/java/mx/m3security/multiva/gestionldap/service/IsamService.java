package mx.m3security.multiva.gestionldap.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import lombok.extern.slf4j.Slf4j;
import mx.m3security.multiva.gestionldap.model.Command;
import mx.m3security.multiva.gestionldap.model.IsamResponse;
import mx.m3security.multiva.gestionldap.model.LdapUser;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Component;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

@Slf4j
@Component
public class IsamService {
    public static String INITCTX = "com.sun.jndi.ldap.LdapCtxFactory";
    public static String MGR_DN = "cn=root";
    public static final String MGR_PW = "Mult1v4n3t";

    // parametros para conectarse
    public static final String ISAM_USER = "admin";
    public static final String ISAM_PW = "multiva2017";
    public static final String ADMIN_ID = "sec_master";
    public static final String ADMIN_PW = "multiva2017";

    @Value("${url.host}")
    private String host;
    @Value("${url.endpoint}")
    private String endPoint;
    @Value("${url.ldap}")
    private String urlLdap;

    public List<String> validateUser(String uid) {
        List<String> result = new ArrayList<>();

        try {

            String comm = "user show-dn "+uid+",ou=people,O=MULTIVA,C=MX";
            String[] commands = new String[] {comm};

            SSLContext sslcontext = SSLContexts.custom()
                    .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                    .build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext,
                    new String[] {"TLSv1.2"},
                    null,
                    SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            CloseableHttpClient httpclient = HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .build();
            Unirest.setHttpClient(httpclient);

            Gson linejson = new Gson();
            Command command = new Command(ADMIN_ID, ADMIN_PW, commands);
            String jsonString = linejson.toJson(command);
            log.info("json :"+jsonString);
            HttpResponse<JsonNode> apiResponse = Unirest.post(endPoint)
                    .header("Accept", "application/json")
                    .basicAuth(ISAM_USER, ISAM_PW)
                    .body(jsonString).asJson();

            if (apiResponse.getStatus() == 200) {
                log.info(apiResponse.getBody().toString());
                String response = apiResponse.getBody().toString();
                ObjectMapper mapper = new ObjectMapper();

                IsamResponse isamResponse = mapper.readValue( response,IsamResponse.class);

                String[] cadenas = isamResponse.getResult().split("\n");
                for (int i = 0; i<cadenas.length; i++){
                    if (cadenas[i].contains("Account valid") || cadenas[i].contains("Password valid") ||cadenas[i].contains("Is SecUser") ){
                        result.add(cadenas[i]);
                    }
                }
            } else {
                log.info("Error: "+apiResponse.getBody().toString());
            }
        } catch (Exception ex) {
            log.info("Error: "+ex.getMessage());
            log.error("Trace: "+ex);
        }
        return result;
    }
    public void deleteUser(String uid){

        log.info("Iniciando metodo para eliminar usuario");
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, INITCTX);
        env.put(Context.PROVIDER_URL, host);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, MGR_DN);
        env.put(Context.SECURITY_CREDENTIALS, MGR_PW);
        try{
            DirContext ctx = new InitialDirContext(env);
            ctx.destroySubcontext("uid="+uid+",ou=people,O=MULTIVA,C=MX");
            log.info("Usuario eliminado");
        }catch (Exception e){
            log.info("Error al intentar eliminar el usuario");
            log.error(e.getMessage());
        }
    }
    public String getDataUser(LdapUser user){
        Hashtable<String, Object> env = new Hashtable<String, Object>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, INITCTX);
        env.put(Context.PROVIDER_URL, urlLdap);
        SearchControls controls  = null;
        NamingEnumeration<?> results = null;
        String result = "version 1 \n\n";
        Name dn = LdapNameBuilder
                .newInstance()
                .add("ou", "people")
                .add("uid", user.getUid())
                .build();
        try{
            DirContext dirContext  = new InitialDirContext(env);
            controls  = new SearchControls();
            controls .setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls .setCountLimit(1000);
            String filter = "(objectClass=*)";
            results = dirContext.search(dn, filter, controls);

            while (results.hasMore()) {
                SearchResult searchResult = (SearchResult) results.next();
                Attributes attributes = searchResult.getAttributes();

                Attribute objClassAttr = attributes.get("objectClass");
                Attribute uid = attributes.get("uid");
                result += "dn: "+uid.toString().replace(": ","=")+",ou=people,O=MULTIVA,C=MX \n";
                String[] objClass = objClassAttr.toString().split(",");

                for (int i=0;i<objClass.length;i++){
                    result += "objectClass: "+objClassAttr.get(i)+"\n";
                }
                attributes.remove("objectClass");

                NamingEnumeration<? extends Attribute> attrs = attributes.getAll();
                while (attrs.hasMore()) {

                    result += attrs.next().toString()+"\n";

                }
                result += "userPassword:: "+user.getUserPassword();
            }
            log.info(result);
            return result;
        } catch (NameNotFoundException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }
    public List<String> getUsers() {
        List<String> listUsers = new ArrayList<>();
        Hashtable<String, Object> env = new Hashtable<String, Object>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, urlLdap);

        try {
            DirContext ctx = new InitialDirContext(env);

            NamingEnumeration<SearchResult> answer = ctx.search("ou=People", null);
            while (answer.hasMore()) {
                SearchResult sr = answer.next();
                String name = sr.getNameInNamespace();
                log.info(name);
                LdapName dn = new LdapName(name);
                listUsers.add(dn.toString());
            }
            ctx.close();
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return listUsers;
    }

}
