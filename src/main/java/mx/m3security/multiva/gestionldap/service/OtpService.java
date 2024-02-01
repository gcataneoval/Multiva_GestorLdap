package mx.m3security.multiva.gestionldap.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Scanner;
@Slf4j
@Service
public class OtpService {

    public void reiniciarToken(String uid) throws IOException {
        URL url = new URL("http://security-services.multivaloresgf.local/OtpService/rest/reiniciarToken2");
        HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
        String response = "";
        try{
            httpConn.setRequestMethod("POST");

            httpConn.setRequestProperty("Content-Type", "application/json");

            httpConn.setDoOutput(true);
            OutputStreamWriter writer = new OutputStreamWriter(httpConn.getOutputStream());
            writer.write(uid);
            writer.flush();
            writer.close();
            httpConn.getOutputStream().close();

            InputStream responseStream = httpConn.getResponseCode() / 100 == 2
                    ? httpConn.getInputStream()
                    : httpConn.getErrorStream();
            Scanner s = new Scanner(responseStream).useDelimiter("\\A");
            response = s.hasNext() ? s.next() : "";
            log.info(response);
        } catch (UnknownHostException e){
            response = "Error al reiniciar Token: servicio OTP no disponible";
            log.error("Error: "+e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
            log.info(response);
        }
    }
    public String reiniciarTokenQa(String uid) throws IOException {
        boolean error = false;
        URL url = new URL("http://10.160.229.189:8080/OtpService/rest/reiniciarToken2");
        HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
        String response = "Success";
        try{
            httpConn.setRequestMethod("POST");

            httpConn.setRequestProperty("Content-Type", "application/json");

            httpConn.setDoOutput(true);
            OutputStreamWriter writer = new OutputStreamWriter(httpConn.getOutputStream());
            writer.write(uid);
            writer.flush();
            writer.close();
            httpConn.getOutputStream().close();

            InputStream responseStream = httpConn.getResponseCode() / 100 == 2
                    ? httpConn.getInputStream()
                    : httpConn.getErrorStream();
            Scanner s = new Scanner(responseStream).useDelimiter("\\A");
            response = s.hasNext() ? s.next() : "";
            log.info(response);
        } catch (IOException e){
            response = "Error";
            log.info("Error al reiniciar Token: servicio OTP no disponible");
            log.error("Error: "+e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return response;
    }
}
