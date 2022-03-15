if(description){
	script_version( "2021-04-16T06:57:08+0000" );
	script_oid( "1.3.6.1.4.1.25623.1.0.150589" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-10 09:31:46 +0000 (Wed, 10 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_name( "SYS.1.3.A14" );
	script_category( ACT_GATHER_INFO );
	script_family( "IT-Grundschutz" );
	script_dependencies( "os_detection.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_1_3_Server_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=3" );
	script_tag( name: "summary", value: "Die Ausgabe von Informationen ueber das Betriebssystem und der
Zugriff auf Protokoll- und Konfigurationsdateien SOLLTE fuer Benutzer auf das notwendige Mass
beschraenkt werden. Ausserdem SOLLTEN bei Befehlsaufrufen keine vertraulichen Informationen als
Parameter uebergeben werden." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Kern" )){
	exit( 0 );
}
title = "Verhinderung des Ausspaehens von System- und Benutzerinformationen";
if(os_host_runs( "linux" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A14" );
	exit( 0 );
}
desc = itg_no_automatic_test();
result = itg_no_automatic_test();
report = policy_build_report( result: result, default: "None", compliant: "yes", fixtext: "None", type: "None", test: "None", info: desc );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.3.A14" );
itg_report( report: report );
exit( 0 );

