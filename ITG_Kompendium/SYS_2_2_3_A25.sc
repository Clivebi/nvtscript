if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109985" );
	script_version( "2021-04-16T10:39:13+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 10:39:13 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.2.2.3.A25" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/Windows10/WindowsComponents/win_telemetry_proxy_server.sc", "Policy/Windows10/WindowsComponents/win_enterprise_auth_proxy.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A25: Umgang mit Fernzugriffsfunktionen der Connected User Experience and
Telemetry' beschreibt, dass CUET geblockt werden sollte." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Kern" )){
	exit( 0 );
}
title = "Umgang mit Fernzugriffsfunktionen der Connected User Experience and Telemetry";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Data Collection and Preview Builds\\Configure Connected User Experiences and Telemetry,
Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Data Collection and Preview Builds\\Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.109610",
	 "1.3.6.1.4.1.25623.1.0.109434" );
if(!policy_host_runs_windows_10()){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.3.A25" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_report( report: report );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.3.A25" );
exit( 0 );

