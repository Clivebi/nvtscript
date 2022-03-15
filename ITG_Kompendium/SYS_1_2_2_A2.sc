if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150011" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-13 10:19:13 +0100 (Fri, 13 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.1.2.2.A2" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/WindowsGeneral/win_server_core_installation.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.1.2.2 ist die Absicherung von Microsoft
Windows Server 2012 und Microsoft Windows Server 2012 R2.

Die Basis-Anforderung 'A2: Sichere Installation von Windows Server 2012' beschreibt, dass das
Installationsmedium aus einer sicheren Quelle bezogen sein muss. Falls ausreichend, muss die
Server-Core-Variante installiert sein. Ein gepatchtes System muss vorliegen." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Basis" )){
	exit( 0 );
}
title = "Sichere Installation von Windows Server 2012";
desc = "Folgende Einstellungen werden getestet:
HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion!InstallationType";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.150009" );
if(os_host_runs( "windows_server_2012" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A2" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.1.2.2.A2" );
itg_report( report: report );
exit( 0 );

