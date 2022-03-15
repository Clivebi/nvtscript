if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.95050" );
	script_version( "$Revision: 14124 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "general_note" );
	script_name( "IT-Grundschutz M5.008: Regelmäßiger Sicherheitscheck des Netzes" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05008.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15", "Tools/Present/wmi" );
	script_tag( name: "summary", value: "IT-Grundschutz M5.008: Regelmäßiger Sicherheitscheck des Netzes.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Es wird lediglich ein Meldung ausgegeben, dass mit aktuelleten Plugins getestet werden soll." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M5.008: Regelmäßiger Sicherheitscheck des Netzes\n";
gshbm = "GSHB Maßnahme 5.008: ";
result = NASLString( "unvollständig" );
desc = NASLString( "Führen Sie bitte eine Prüfung Ihres Netzwerkes mit dem aktuellen NVT-Set aus." );
set_kb_item( name: "GSHB/M5_008/result", value: result );
set_kb_item( name: "GSHB/M5_008/desc", value: desc );
set_kb_item( name: "GSHB/M5_008/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M5_008" );
}
exit( 0 );

