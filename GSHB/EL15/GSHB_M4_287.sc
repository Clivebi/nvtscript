if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94226" );
	script_version( "2021-04-14T08:50:25+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 08:50:25 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "sip_detection.sc", "sip_detection_tcp.sc", "ssh_proto_version.sc" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04287.html" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.287: Sichere Administration der VoIP-Middleware\n";
gshbm = "IT-Grundschutz M4.287: ";
sip = get_kb_item( "sip/detected" );
sshvers = get_kb_list( "SSH/supportedversions/22" );
http = http_open_socket( 80 );
if(sshvers){
	for sshver in sshvers {
		if(sshver == "1.33" || sshver == "1.5"){
			val += sshver + ",";
		}
	}
}
if( !sip ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem Zielsystem wurde kein SIP-Dienst gefunden.\nDavon ausgehend, wird es nicht als VoIP-Middleware\nbehandelt." );
}
else {
	if( !http && !val ){
		result = NASLString( "erfüllt" );
		if( !http && !val ) {
			desc = NASLString( "Auf dem Zielsystem wurde weder ein HTTP-Server-Port\n80 noch die SSH-Protokollversion 1 gefunden." );
		}
		else {
			if( !http ) {
				desc = NASLString( "Auf dem Zielsystem wurde kein HTTP-Server-\nPort 80 gefunden." );
			}
			else {
				if(!val){
					desc = NASLString( "Auf dem Zielsystem wurde die SSH-Protokollversion 1\nnicht gefunden." );
				}
			}
		}
	}
	else {
		result = NASLString( "nicht erfüllt" );
		if( http && val ) {
			desc = NASLString( "Auf dem Zielsystem wurde ein HTTP-Server-Port 80 und\ndie SSH-Protokollversion 1 gefunden. Eine Web-basierte\nKonfiguration sollte immer gesichert erfolgen,\nbeispielsweise durch den Einsatz von SSL oder TLS.\nIhre SSH Einstellungen lassen Verbindungen mit der\nProtokollversion 1 zu. Diese Version enthält Schwach-\nstellen. Sie sollten nur die Protokollversion 2\neinsetzten." );
		}
		else {
			if( !http ) {
				desc = NASLString( "Auf dem Zielsystem wurde ein HTTP-Server-Port 80\ngefunden. Eine Web-basierte Konfiguration sollte immer\ngesichert erfolgen, beispielsweise durch den Einsatz\nvon SSL oder TLS." );
			}
			else {
				if(!val){
					desc = NASLString( "Auf dem Zielsystem wurde die SSH-Protokollversion 1\ngefunden. Ihre SSH Einstellungen lassen Verbindungen\nmit der Protokollversion 1 zu. Diese Version enthält\nSchwachstellen. Sie sollten nur die Protokollversion 2\neinsetzten." );
				}
			}
		}
	}
}
if(!result){
	result = NASLString( "Fehler" );
	desc = NASLString( "Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden." );
}
if(http){
	http_close_socket( http );
}
set_kb_item( name: "GSHB/M4_287/result", value: result );
set_kb_item( name: "GSHB/M4_287/desc", value: desc );
set_kb_item( name: "GSHB/M4_287/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_287" );
}
exit( 0 );

