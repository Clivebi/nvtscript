if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150003" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-12-09 09:12:10 +0100 (Mon, 09 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "SYS.2.2.2.A17" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_2_Clients_unter_Windows_8_1.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB-ITG" );
	script_dependencies( "smb_reg_service_pack.sc", "os_detection.sc", "Policy/WindowsGeneral/SystemServices/win_error_reporting_service.sc", "Policy/WindowsGeneral/System/win_error_reporting.sc", "Policy/Windows8/win8_auto_approve_os_dumps.sc", "Policy/WindowsGeneral/System/turn_off_windows_error_reporting.sc", "Policy/WindowsGeneral/WindowsComponents/win_default_consent.sc" );
	script_tag( name: "summary", value: "Ziel des Bausteins SYS.2.2.2 ist der Schutz von Informationen,
die durch und auf Windows 8.1-Clients verarbeiten werden.

Die Kern-Anforderung 'A17: Sicherer Einsatz des Wartungscenters' beschreibt, wie der Einsatz des
Wartungscenters konfiguriert sein sollte." );
	exit( 0 );
}
require("itg.inc.sc");
require("policy_functions.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!itg_start_requirement( level: "Kern" )){
	exit( 0 );
}
title = "Sicherer Einsatz des Wartungscenters";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration/Policies/Windows Settings/Security Settings/System Services/Windows Error Reporting Service,
Computer Configuration/Administrative Templates/System/Internet Communication Management/Internet Communication settings/Turn off Windows Error Reporting,
Windows Components/Windows Error Reporting/Automatically send memory dumps for OS-generated error reports,
System/Internet Communication Management/Internet Communication settings/ Turn off Windows Error Reporting,
Computer Configuration/Administrative Templates/Windows Components/Windows Error Reporting/Consent/Configure Default consent";
oid_list = make_list( "1.3.6.1.4.1.25623.1.0.109282",
	 "1.3.6.1.4.1.25623.1.0.109366",
	 "1.3.6.1.4.1.25623.1.0.109689",
	 "1.3.6.1.4.1.25623.1.0.109887",
	 "1.3.6.1.4.1.25623.1.0.109688" );
if(os_host_runs( "windows_8.1" ) != "yes"){
	result = itg_result_wrong_target();
	desc = itg_desc_wrong_target();
	itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A17" );
	exit( 0 );
}
results_list = itg_get_policy_control_result( oid_list: oid_list );
result = itg_translate_result( compliant: results_list["compliant"] );
report = policy_build_report( result: "MULTIPLE", default: "MULTIPLE", compliant: results_list["compliant"], fixtext: results_list["solutions"], type: "MULTIPLE", test: results_list["tests"], info: results_list["notes"] );
itg_set_kb_entries( result: result, desc: desc, title: title, id: "SYS.2.2.2.A17" );
itg_report( report: report );
exit( 0 );

