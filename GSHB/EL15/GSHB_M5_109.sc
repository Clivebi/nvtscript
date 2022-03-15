if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95071" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IT-Grundschutz M5.109: Einsatz eines E-Mail-Scanners auf dem Mailserver" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05109.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_dependencies( "GSHB/GSHB_smtp_eicar_test.sc" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.109: Einsatz eines E-Mail-Scanners auf dem Mailserver.

  Stand: 14. Ergänzungslieferung (14. EL)." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("itg.inc.sc");
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
name = "IT-Grundschutz M5.109: Einsatz eines E-Mail-Scanners auf dem Mailserver\n";
gshbm = "IT-Grundschutz M5.109: ";
port = smtp_get_port( default: 25, ignore_broken: TRUE, ignore_unscanned: TRUE );
Eicar = get_kb_item( "GSHB/Eicar/" + port );
log = get_kb_item( "GSHB/Eicar/" + port + "/log" );
if( ContainsString( Eicar, "error" ) ){
	result = NASLString( "Fehler" );
	if(!log){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf." );
	}
	if(log){
		desc = NASLString( "Beim Testen des Systems trat ein Fehler auf:\\n" + log );
	}
}
else {
	if( !port ){
		result = NASLString( "nicht zutreffend" );
		desc = NASLString( "Das System wurde nicht als Mailserver erkannt." );
	}
	else {
		if( Eicar == "true" ){
			result = NASLString( "unvollständig" );
			desc = NASLString( "Es wurde erfolgreich eine Mail mit Eicar-Testfiles verschickt.\nBitte prüfen Sie das in der Scan Konfiguration konfigurierte\nEmpfängerpostfach sowie den konfigurierten MTA." );
		}
		else {
			if(Eicar == "fail"){
				result = NASLString( "unvollständig" );
				desc = NASLString( "Es konnte anscheinend keine Mail mit Eicar-Testfiles verschickt\nwerden. Bitte prüfen Sie trotzdem das in der Scan Konfiguration\nkonfigurierte Empfängerpostfach sowie den konfigurierten MTA." );
			}
		}
	}
}
set_kb_item( name: "GSHB/M5_109/result", value: result );
set_kb_item( name: "GSHB/M5_109/desc", value: desc );
set_kb_item( name: "GSHB/M5_109/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_109" );
}
exit( 0 );

