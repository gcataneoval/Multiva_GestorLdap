package mx.m3security.multiva.gestionldap.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LdapUser implements Serializable {

	private String uid;
	private String cn;
	private String sn;
	private String countGRAL;
	private String countIVR;
	private String countPIV;
	private String countSLD;
	private String nsUserID;
	private String nsUserNIPValid;
	private String numCliente;
	private String statusGRAL;
	private String tipoToken;
	private String vascoTokenSerialNumber;
	private String canalAsignado;
	private String contratoAceptado;
	private String dateFirstFail;
	private String mail;
	private String tarjeta;
	private String personalidadFiscal;
	private String nsLastupdate;
	private String banMigrado;
	private String telefono;
	private String rfc;
	private String banBancamovil;
	private String tipoPersona;
	private String banNotificaciones;
	private String fechaUltimoLogin;
	private String razonSocial;
	private String aliasMva;
	private String aliasAlfa;
	private String fechaNotificaciones;
	private String uid2;
	private String banCodi;
	private String sldLastbind;
	private String idDispositivo;
	private String nsLastbind;
	private String fechaLastAccessBE;
	private String nsUserNIP;
	private String requestType;
	private String fechaUltimoAcceso;
	private String cuenta;
	private String numeroCliente;
	private String blobRO;
	private String fechaAltaUsuario;
	private String fechaAsignacion;
	private String nsModby;
	private String objClass;
	private String dn;
	private String userPassword;


	public Map<String,Object> getParams1(){
		Map<String,Object> params = new HashMap<>();
		params.put("uid",uid);
		params.put("cn",cn);
		params.put("sn",sn);
		params.put("countGRAL",countGRAL);
		params.put("countIVR",countIVR);
		params.put("countPIV",countPIV);
		params.put("countSLD",countSLD);
		params.put("ns_userID", nsUserID);
		params.put("ns_userNIPValid", nsUserNIPValid);
		params.put("NumCliente",numCliente);
		params.put("statusGRAL",statusGRAL);
		params.put("tipoToken",tipoToken);
		params.put("vascoTokenSerialNumber",vascoTokenSerialNumber);
		params.put("blobRO",blobRO);

		return params;
	}

	public Map<String,Object> getParams2(){
		Map<String,Object> params = new HashMap<>();
		params.put("canalAsignado",canalAsignado);
		params.put("contratoAceptado",contratoAceptado);
		params.put("dateFirstFail",dateFirstFail);
		params.put("mail",mail);
		params.put("tarjeta",tarjeta);
		params.put("personalidadFiscal",personalidadFiscal);
		params.put("ns_lastUpdate",nsLastupdate);
		params.put("banMigrado",banMigrado);
		params.put("telefono",telefono);
		params.put("RFC",rfc);
		params.put("banBancamovil",banBancamovil);
		params.put("tipoPersona",tipoPersona);
		params.put("banNotificaciones",banNotificaciones);
		params.put("fechaUltimoLogin",fechaUltimoLogin);
		params.put("fechaAltaUsuario",fechaAltaUsuario);

		return params;
	}

	public Map<String,Object> getParams3(){
		Map<String,Object> params = new HashMap<>();
		params.put("razonSocial",razonSocial);
		params.put("aliasMva",aliasMva);
		params.put("aliasAlfa",aliasAlfa);
		params.put("fechaNotificaciones",fechaNotificaciones);
		params.put("uid2",uid2);
		params.put("banCodi",banCodi);
		params.put("SLD_lastBind",sldLastbind);
		params.put("id_dispositivo",idDispositivo);
		params.put("ns_lastBind",nsLastbind);
		params.put("fechaLastAccessBE",fechaLastAccessBE);
		params.put("requestType",requestType);
		params.put("fechaUltimoAcceso",fechaUltimoAcceso);
		params.put("cuenta",cuenta);
		params.put("ns_userNIP",nsUserNIP);
		params.put("numeroCliente",numeroCliente);
		params.put("fechaAsignacion",fechaAsignacion);
		params.put("ns_modby", nsModby);

		return params;
	}

	@Override
	public String toString() {
		return "dn: " + dn  +
				"objClass: " + objClass  +
				"numeroCliente: " + numeroCliente  +
				", uid: " + uid  +
				", cn: " + cn  +
				", sn: " + sn  +
				", countGRAL: " + countGRAL  +
				", countIVR: " + countIVR  +
				", countPIV: " + countPIV  +
				", countSLD: " + countSLD  +
				", ns_userID: " + nsUserID +
				", ns_userNIPValid: " + nsUserNIPValid +
				", NumCliente: " + numCliente  +
				", statusGRAL: " + statusGRAL  +
				", tipoToken: " + tipoToken  +
				", vascoTokenSerialNumber: " + vascoTokenSerialNumber  +
				", canalAsignado: " + canalAsignado  +
				", contratoAceptado: " + contratoAceptado  +
				", dateFirstFail: " + dateFirstFail  +
				", mail: " + mail  +
				", tarjeta: " + tarjeta  +
				", PersonalidadFiscal: " + personalidadFiscal  +
				", ns_lastUpdate: " + nsLastupdate  +
				", banMigrado: " + banMigrado  +
				", telefono: " + telefono  +
				", RFC: " + rfc  +
				", ban_bancamovil: " + banBancamovil  +
				", tipoPersona: " + tipoPersona  +
				", ban_notificaciones: " + banNotificaciones  +
				", fechaUltimoLogin: " + fechaUltimoLogin  +
				", RazonSocial: " + razonSocial  +
				", aliasMva: " + aliasMva  +
				", aliasAlfa: " + aliasAlfa  +
				", fechaNotificaciones: " + fechaNotificaciones  +
				", uid2: " + uid2  +
				", ban_codi: " + banCodi  +
				", SLD_lastBind: " + sldLastbind  +
				", id_dispositivo: " + idDispositivo  +
				", ns_lastBind: " + nsLastbind  +
				", fechaLastAccessBE: " + fechaLastAccessBE  +
				", nsUserNIP: " + nsUserNIP  +
				", requestType: " + requestType  +
				", fechaUltimoAcceso: " + fechaUltimoAcceso  +
				", cuenta: " + cuenta+
				", userPassword: " + userPassword;
	}
}
