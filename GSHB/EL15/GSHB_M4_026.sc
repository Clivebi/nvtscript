if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.94198" );
	script_version( "$Revision: 10611 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 13:49:26 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "general_note" );
	script_name( "IT-Grundschutz M4.026: Regelm‰ﬂiger Sicherheitscheck des Unix-Systems" );
	script_xref( name: "URL", value: "http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04026.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz-15" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-15" );
	script_tag( name: "summary", value: "IT-Grundschutz M4.026: Regelm‰ﬂiger Sicherheitscheck des Unix-Systems.

Stand: 14. Erg‰nzungslieferung (14. EL)." );
	exit( 0 );
}
require("itg.inc.sc");
name = "IT-Grundschutz M4.026: Regelm‰ﬂiger Sicherheitscheck des Unix-Systems\n";
gshbm = "IT-Grundschutz M4.026: ";
result = "Pr¸fung dieser Maﬂnahme ist nicht implementierbar.";
desc = "Pr¸fung dieser Maﬂnahme ist nicht implementierbar.";
set_kb_item( name: "GSHB/M4_026/result", value: result );
set_kb_item( name: "GSHB/M4_026/desc", value: desc );
set_kb_item( name: "GSHB/M4_026/name", value: name );
silence = get_kb_item( "GSHB/silence" );
if(!silence){
	itg_send_details( itg_id: "GSHB/M4_026" );
}
exit( 0 );

