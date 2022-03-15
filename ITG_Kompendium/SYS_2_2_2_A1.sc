if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109987" );
	script_version( "2021-04-16T10:39:13+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-09 09:12:10 +0100 (Mon, 09 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.2.2.2.A1" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.2.2.2 ist der Schutz von Informationen,
die durch und auf Windows 8.1-Clients verarbeiten werden.

Die Basis-Anforderung 'A1: Geeignete Auswahl einer Windows 8.1-Version' beschreibt,
dass eine geeignete Windows 8.1 Version, vorzugsweise eine 64-Bit Variante, eingesetzt werden muss." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Basis" )){
	exit( 0 );
}
title = "Geeignete Auswahl einer Windows 8.1-Version";
if(os_host_runs( "windows_8.1" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A1" );
	exit( 0 );
}
desc = "Die Windows Architektur wird getestet.";
if( IsMatchRegexp( os_get_best_cpe(), "x64" ) ){
	compliant = "yes";
	result = "64-Bit";
}
else {
	compliant = "no";
	result = "No 64-Bit";
}
solution = "Installieren Sie Microsoft Windows 8.1 in der 64-Bit Variante.";
report = policy_build_report( result: result, default: "64-Bit", compliant: compliant, fixtext: solution, type: "OS_Test", test: "OS Detection", info: "" );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A1" );
itg_report( report: report );
exit( 0 );

