if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94176" );
	script_version( "$Revision: 10623 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "IT-Grundschutz M4.005: Protokollierung bei TK-Anlagen" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_WMI_list_Services.sc", "GSHB/GSHB_WMI_OSInfo.sc", "GSHB/GSHB_SSH_syslog.sc" );
	script_require_keys( "WMI/EventLogService" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.005: Protokollierung bei TK-Anlagen

Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.005: Protokollierung der TK-Administrationsarbeiten\n";
gshbm = "IT-Grundschutz M4.005: ";
OSVER = get_kb_item( "WMI/WMI_OSVER" );
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
eventlog = get_kb_item( "WMI/EventLogService" );
log = get_kb_item( "WMI/EventLogService/log" );
syslog = get_kb_item( "GSHB/syslog" );
rsyslog = get_kb_item( "GSHB/rsyslog" );
log_rsyslog = get_kb_item( "GSHB/rsyslog/log" );
if( !ContainsString( "none", OSVER ) ){
	if(!ContainsString( "None", eventlog ) || !ContainsString( "error", eventlog )){
		eventlog = split( buffer: eventlog, sep: "|", keep: 0 );
	}
	if( ContainsString( eventlog, "error" ) ){
		result = NASLString( "Fehler" );
		if(!log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
		}
		if(log){
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
		}
	}
	else {
		if( ContainsString( eventlog, "None" ) ){
			result = NASLString( "nicht erfüllt" );
			desc = NASLString( "Auf dem System wurde kein Eventlog gefunden." );
		}
		else {
			if( ContainsString( eventlog[2], "Running" ) ){
				result = NASLString( "unvollständig" );
				desc = NASLString( "Eventlog läuft auf dem System. Bitte prüfen Sie ob\\nIhre TK-Anlage das Eventlog zum Abspeichern der Events\\nbenutzt." );
			}
			else {
				if(ContainsString( eventlog[2], "Stopped" )){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Eventlog läuft auf dem System nicht. Starten Sie\\nEventlog und prüfen Sie ob Ihre TK-Anlage das Eventlog\\nzum Abspeichern der Events benutzt." );
				}
			}
		}
	}
}
else {
	if( syslog == "windows" ){
		result = NASLString( "Fehler" );
		if( !ContainsString( "none", OSNAME ) && !ContainsString( "error", OSNAME ) ) {
			desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME + "\nAllerdings konnte auf das System nicht korrekt zuge-\ngriffen werden. Folgende Fehler sind aufgetreten:\n" + log );
		}
		else {
			desc = NASLString( "Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n" + log );
		}
	}
	else {
		if( ContainsString( syslog, "error" ) ){
			result = NASLString( "Fehler" );
			if(!log_rsyslog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
			}
			if(log_rsyslog){
				desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
			}
		}
		else {
			if( ContainsString( syslog, "off" ) && ContainsString( rsyslog, "off" ) ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Auf dem System läuft weder syslog noch rsyslog, um\\nggf. Events aus der TK-Anlage zu speichern." );
			}
			else {
				result = NASLString( "unvollständig" );
				desc = NASLString( "Syslog/Rsyslog läuft auf dem System. Bitte prüfen Sie\\nob Ihre TK-Anlage Syslog/Rsyslog zum Abspeichern der\\nEvents benutzt." );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_005/result", value: result );
set_kb_item( name: "GSHB/M4_005/desc", value: desc );
set_kb_item( name: "GSHB/M4_005/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_005" );
}
exit( 0 );

