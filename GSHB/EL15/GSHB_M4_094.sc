if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94210" );
	script_version( "2021-06-11T09:28:25+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 09:28:25 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.094: Schutz der Webserver-Dateien" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04094.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.094: Schutz der Webserver-Dateien.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("itg.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
name = "IT-Grundschutz M4.094: Schutz der Webserver-Dateien\n";
gshbm = "IT-Grundschutz M4.094: ";
port = http_get_port( default: 80, ignore_broken: TRUE, ignore_unscanned: TRUE );
host = http_host_name( dont_add_port: TRUE );
brokenwww = http_get_is_marked_broken( port: port, host: host );
nikto = get_kb_item( "GSHB/NIKTO" );
if( brokenwww ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Es wurde kein Webserver gefunden." );
}
else {
	if( nikto == "error" ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
	}
	else {
		if( !nikto ){
			result = NASLString( "Fehler" );
			desc = NASLString( "Beim Testen des Systems trat ein Fehler auf, es konnte\\nvon Nikto kein Ergebniss ermittelt werden." );
		}
		else {
			if( nikto == "none" && !brokenwww ){
				result = NASLString( "erfüllt" );
				desc = NASLString( "Nikto konnte keinen in der -Open Source Vulnerability Database- aufgeführten oder durch eine CVE Nummer addressierten Fehler finden." );
			}
			else {
				if(nikto != "none" && !brokenwww){
					result = NASLString( "nicht erfüllt" );
					desc = NASLString( "Nikto hat folgende in der -Open Source Vulnerability Database- aufgeführten oder durch eine CVE Nummer addressierten Fehler gefunden:\n" + nikto );
				}
			}
		}
	}
}
set_kb_item( name: "GSHB/M4_094/result", value: result );
set_kb_item( name: "GSHB/M4_094/desc", value: desc );
set_kb_item( name: "GSHB/M4_094/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_094" );
}
exit( 0 );

