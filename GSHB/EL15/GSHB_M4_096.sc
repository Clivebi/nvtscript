if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94211" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "IT-Grundschutz M4.096: Abschaltung von DNS" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04096.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_dependencies( "GSHB/GSHB_SSH_dns.sc", "GSHB/GSHB_WMI_OSInfo.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.096: Abschaltung von DNS.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
name = "IT-Grundschutz M4.096: Abschaltung von DNS\n";
gshbm = "IT-Grundschutz M4.096: ";
OSNAME = get_kb_item( "WMI/WMI_OSNAME" );
VAL1 = get_kb_item( "GSHB/DNSTEST/VAL1" );
VAL2 = get_kb_item( "GSHB/DNSTEST/VAL2" );
VAL3 = get_kb_item( "GSHB/DNSTEST/VAL3" );
VAL4 = get_kb_item( "GSHB/DNSTEST/VAL4" );
VAL5 = get_kb_item( "GSHB/DNSTEST/VAL5" );
log = get_kb_item( "GSHB/DNSTEST/log" );
www_ports = http_get_ports( default_port_list: make_list( 80,
	 443,
	 8080,
	 8008,
	 8088 ) );
if(www_ports){
	for www_port in www_ports {
		if(www_port == "80" || www_port == "443" || www_port == "8080" || www_port == "8008" || www_port == "8088"){
			ports += www_port + ", ";
		}
	}
	if(ports){
		ports = ports - "[";
		ports = ports - "]";
	}
}
if( VAL1 == "error" && OSNAME == "none" ){
	result = NASLString( "Fehler" );
	if(!log){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
	}
	if(log){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
	}
}
else {
	if( !ports ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Das System scheint kein Internetserver zu sein. Es\nwurden bei der Überprüfung nur die Ports 80, 443,\n8008, 8080 und 8088 beachtet." );
	}
	else {
		if( OSNAME != "none" ){
			result = NASLString( "nicht zutreffend" );
			desc = NASLString( "Folgendes System wurde erkannt:\n" + OSNAME );
		}
		else {
			if( VAL1 == "TRUE" || VAL2 == "TRUE" || VAL3 == "TRUE" || VAL4 == "TRUE" || VAL5 == "TRUE" ){
				result = NASLString( "nicht erfüllt" );
				desc = NASLString( "Das System scheint ein Internetserver zu sein.\nEntgegen der Empfehlung aus Maßnahme 4.096, läuft es\nmit aktiviertem DNS." );
			}
			else {
				result = NASLString( "erfüllt" );
				desc = NASLString( "Das System scheint ein Internetserver zu sein. Wie in\nder Maßnahme 4.096 Empfohlen, läuft es ohne\naktiviertem DNS." );
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
set_kb_item( name: "GSHB/M4_096/result", value: result );
set_kb_item( name: "GSHB/M4_096/desc", value: desc );
set_kb_item( name: "GSHB/M4_096/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_096" );
}
exit( 0 );

