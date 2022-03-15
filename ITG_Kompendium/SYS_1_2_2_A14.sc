if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150022" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-13 10:19:13 +0100 (Fri, 13 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.1.2.2.A14" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.1.2.2 ist die Absicherung von Microsoft
Windows Server 2012 und Microsoft Windows Server 2012 R2.

Die Kern-Anforderung 'A14: Herunterfahren verschluesselter Server und virtueller Maschinen' beschreibt,
dass nicht genutzte Server heruntergefahren werden sollten. Die Entschluesselung beim herauffahren
sollte in einem interaktiven Schritt erfolgen." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Kern" )){
	exit( 0 );
}
title = "Herunterfahren verschluesselter Server und virtueller Maschinen";
if(os_host_runs( "windows_server_2012" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A14" );
	exit( 0 );
}
desc = itg_no_automatic_test();
result = itg_no_automatic_test();
report = policy_build_report( result: result, default: "None", compliant: "yes", fixtext: "None", type: "None", test: "None", info: desc );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A14" );
itg_report( report: report );
exit( 0 );

