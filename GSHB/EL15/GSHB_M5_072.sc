if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95068" );
	script_version( "$Revision: 14124 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M5.072: Deaktivieren nicht benötigter Netzdienste" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_WMI_Netstat_natcp.sc", "GSHB/GSHB_SSH_netstat.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05072.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.072: Deaktivieren nicht benötigter Netzdienste.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis: Lediglich Anzeige der in Frage kommenden Dienste." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("itg.inc.sc");
require("smb_nt.inc.sc");
name = "IT-Grundschutz M5.072: Deaktivieren nicht benötigter Netzdienste\n";
gshbm = "GSHB Maßnahme 5.072: ";
WMINetstat = get_kb_item( "GSHB/WMI/NETSTAT" );
SSHNetstat = get_kb_item( "GSHB/SSH/NETSTAT" );
SAMBA = kb_smb_is_samba();
if( SAMBA && ContainsString( "nosock", SSHNetstat ) ){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass keine SSH Verbindung aufgebaut werden konnte." );
}
else {
	if( SAMBA && !ContainsString( "nosock", SSHNetstat ) ){
		if( !ContainsString( "none", SSHNetstat ) ){
			result = NASLString( "unvollständig" );
			desc = NASLString( "Bitte prüfen Sie das Ergebnis und deaktivieren ggf. nicht benötigter Netzdienste:\n\n" + SSHNetstat );
		}
		else {
			if(ContainsString( "none", SSHNetstat )){
				result = NASLString( "Fehler" );
				desc = NASLString( "Es konnte über \"netstat\" kein Ergebnis ermittelt werden." );
			}
		}
	}
	else {
		if(!SAMBA){
			if( ContainsString( "nocred", WMINetstat ) ){
				result = NASLString( "Fehler" );
				desc = NASLString( "Beim Testen des Systems wurde festgestellt, dass keine Logindaten angegeben wurden." );
			}
			else {
				if( ContainsString( "toold", WMINetstat ) ){
					result = NASLString( "Fehler" );
					desc = NASLString( "Ihre GVM/GSM Installation ist zu alt." );
				}
				else {
					if(!ContainsString( "", WMINetstat )){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Bitte prüfen Sie das Ergebnis, und deaktivieren ggf. nicht benötigter Netzdienste:\n\n" + WMINetstat );
					}
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M5_072/result", value: result );
set_kb_item( name: "GSHB/M5_072/desc", value: desc );
set_kb_item( name: "GSHB/M5_072/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_072" );
}
exit( 0 );

