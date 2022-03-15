if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95060" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05034.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_Opie.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.034: Einsatz von Einmalpasswörtern\n";
gshbm = "IT-Grundschutz M5.034: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
OPISERVICES = get_kb_item( "GSHB/OPIE/SERVICES" );
OPIPAM = get_kb_item( "GSHB/OPIE/PAM" );
OPISSH = get_kb_item( "GSHB/OPIE/SSH" );
OPISERVER = get_kb_item( "GSHB/OPIE/SERVER" );
OPICLIENT = get_kb_item( "GSHB/OPIE/CLIENT" );
log = get_kb_item( "GSHB/OPIE/log" );
if( !ContainsString( "none", OSNAME ) ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n" + OSNAME );
}
else {
	if( ContainsString( "windows", OPISERVER ) ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Dieser Test bezieht sich auf UNIX/LINUX Systeme. Das System ist ein Windows-System." );
	}
	else {
		if( ContainsString( "error", OPISERVER ) ){
			result = NASLString( "Fehler" );
			if(!log){
				desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf." );
			}
			if(log){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\n" + log );
			}
		}
		else {
			if( OPISERVER == "yes" && ( OPIPAM == "norights" || OPISERVICES == "norights" ) ){
				result = NASLString( "Fehler" );
				if(OPIPAM == "norights"){
					desc = NASLString( "Der Testbenutzer hat kein Recht auf die Datei /etc/pam.d/opie zu lesen." );
				}
				if(OPISERVICES == "norights"){
					desc += NASLString( "\nDer Testbenutzer hat kein Recht die Dateien unter /etc/pam.d/ zu lesen" );
				}
			}
			else {
				if( OPISERVER == "yes" && ( OPIPAM == "nocat" || OPISSH == "nogrep" || OPISERVICES == "nogrep" ) ){
					result = NASLString( "Fehler" );
					if(OPIPAM == "nocat"){
						desc = NASLString( "Der Befehl -cat- wurde nicht gefunden." );
					}
					if(OPISSH == "nogrep" || OPISERVICES == "nogrep"){
						desc += NASLString( "\nDer Befehl -grep- wurde nicht gefunden." );
					}
				}
				else {
					if( OPISERVER == "no" ){
						result = NASLString( "unvollständig" );
						desc = NASLString( "Wir testen im Moment nur auf Opie, welches auf diesem System nicht installiert ist. Bitte überprüfen Sie manuell, ob eine andere One-Time-Password Software installiert ist. Ansonsten ist ein Einsatz von Einmalpasswörtern nicht möglich." );
					}
					else {
						if( ContainsString( OPIPAM, "auth sufficient pam_opie.so" ) && ContainsString( OPIPAM, "auth required pam_deny.so" ) ){
							result = NASLString( "erfüllt" );
							if( OPISSH == "norights" ) {
								desc = NASLString( "\nDer Testbenutzer hat kein Recht auf die Datei /etc/ssh/sshd_config zu lesen. In dieser Datei sollte der Eintrag -ChallengeResponseAuthentication yes- stehen, damit auch SSH mit Einmalpasswörtern arbeiten kann." );
							}
							else {
								if(!ContainsString( OPISSH, "ChallengeResponseAuthentication yes" )){
									desc = NASLString( "In der Datei /etc/ssh/sshd_config, sollte der Eintrag -ChallengeResponseAuthentication yes- stehen, damit auch SSH mit Einmalpasswörtern arbeiten kann." );
								}
							}
							if( OPISERVICES == "empty" ) {
								desc += NASLString( "\nUm OPIE mit den verschiedenen Authentisierungsdiensten verwenden zu können, muss die Datei /etc/pam.d/opie in die PAM-Konfigurationen der jeweiligen Dienste eingebunden werden. Dazu muss in der Datei /etc/pam.d/<Dienstname> der Eintrag -@include common-auth- durch -@include opie- ersetzt werden." );
							}
							else {
								desc += NASLString( "\nFolgende Dienste arbeiten schon mit Opie zusammen:\n" + OPISERVICES + "\nUm weitere hinzuzufügen, muss in der Datei /etc/pam.d/<Dienstname> der Eintrag -@include common-auth- durch -@include opie- ersetzt werden." );
							}
						}
						else {
							result = NASLString( "nicht erfüllt" );
							desc = NASLString( "Die Datei /etc/pam.d/opie muss angelegt werden und es sollten mindestens die Einträge -auth sufficient pam_opie.so- und -auth required pam_deny.so- in ihr stehen." );
						}
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
set_kb_item( name: "GSHB/M5_034/result", value: result );
set_kb_item( name: "GSHB/M5_034/desc", value: desc );
set_kb_item( name: "GSHB/M5_034/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_034" );
}
exit( 0 );

