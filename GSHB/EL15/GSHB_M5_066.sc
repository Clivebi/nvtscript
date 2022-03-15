if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95067" );
	script_version( "$Revision: 10646 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05066.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_test_WebServer_Cert.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.066: Clientseitige Verwendung von SSL/TLS\n";
cert = get_kb_item( "GSHB/SSL-Cert" );
RootCert = get_kb_item( "GSHB/SSL-Cert/RootPEMstate" );
sslport = get_kb_item( "Ports/tcp/443" );
gshbm = "GSHB Maßnahme 5.066: ";
if( !sslport ){
	result = NASLString( "nicht zutreffend" );
	desc = NASLString( "Auf dem System wurde kein SSL-Port gefunden." );
}
else {
	if( ContainsString( "unknown", cert ) ){
		result = NASLString( "Fehler" );
		desc = NASLString( "Beim Auslesen des SSL-Zertifikates\\nwurde ein Fehler festgestellt." );
	}
	else {
		if( ContainsString( cert, "Verify return code: 0 (ok)" ) ){
			result = NASLString( "unvollständig" );
			certpart = split( buffer: cert, sep: "\n", keep: 0 );
			desc = NASLString( "Folgendes Zertifikat auf dem Zielsystem wurde erfolgreiche\nverifiziert:\n" + certpart[0] + "\nWeitere Tests sind zurzeit nicht möglich." );
		}
		else {
			result = NASLString( "nicht erfüllt" );
			certpart = split( buffer: cert, sep: "\n", keep: 0 );
			desc = NASLString( "Beim Verifizieren dieses SSL-Zertifikates:\n" + certpart[0] + "\nist folgendes Problem aufgetreten:\n" + certpart[1] );
			if(RootCert == "FAIL"){
				desc += NASLString( "\nSpeichern Sie ggf. für den Test \"Test Webserver SSL\nCertificate\" unter \"Network Vulnerability Test Preferences\"\nein Root Zertifikat." );
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_066/result", value: result );
set_kb_item( name: "GSHB/M5_066/desc", value: desc );
set_kb_item( name: "GSHB/M5_066/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_066" );
}
exit( 0 );

